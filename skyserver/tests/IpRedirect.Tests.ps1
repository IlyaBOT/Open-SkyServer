Import-Module (Join-Path $PSScriptRoot '..\SkypeIpRedirect.psm1') -Force

InModuleScope SkypeIpRedirect {
    Describe 'Skype IPv4 redirect ownership and rollback (mocked OS commands)' {
        BeforeEach {
            $script:statePath = Join-Path (Get-PSDrive TestDrive).Root ([Guid]::NewGuid().ToString('N') + '.json')
            $script:mockAddresses = @{
                '127.0.0.1' = [pscustomobject]@{IPAddress='127.0.0.1';InterfaceIndex=1;PrefixLength=8;SkipAsSource=$false}
            }
            $script:receive = 'Enabled'
            $script:send = 'Disabled'
            $script:boot = 'boot-a'
            $script:failAddress = ''
            Mock Assert-SkypeRedirectAdmin {}
            Mock Get-SkypeRedirectBootId { $script:boot }
            Mock Get-NetIPAddress { $script:mockAddresses.Values }
            Mock Get-NetIPInterface {
                [pscustomobject]@{InterfaceIndex=1;WeakHostReceive=$script:receive;WeakHostSend=$script:send}
            }
            Mock Set-NetIPInterface {
                param($InterfaceIndex,$WeakHostReceive,$WeakHostSend,$PolicyStore)
                $PolicyStore | Should Be 'ActiveStore'
                if ($null -ne $WeakHostReceive -and "$WeakHostReceive" -ne '') { $script:receive = [string]$WeakHostReceive }
                if ($null -ne $WeakHostSend -and "$WeakHostSend" -ne '') { $script:send = [string]$WeakHostSend }
            }
            Mock New-NetIPAddress {
                param($InterfaceIndex,$IPAddress,$PrefixLength,$SkipAsSource,$PolicyStore)
                $PolicyStore | Should Be 'ActiveStore'
                $PrefixLength | Should Be 32
                $SkipAsSource | Should Be $true
                if ($IPAddress -eq $script:failAddress) { throw 'Simulated OS add failure' }
                $script:mockAddresses[$IPAddress] = [pscustomobject]@{
                    IPAddress=$IPAddress;InterfaceIndex=$InterfaceIndex;PrefixLength=$PrefixLength;SkipAsSource=$SkipAsSource
                }
            }
            Mock Remove-NetIPAddress {
                param($InterfaceIndex,$IPAddress,$PolicyStore)
                $PolicyStore | Should Be 'ActiveStore'
                $IPAddress | Should Not Be '127.0.0.1'
                foreach ($address in $IPAddress) { $script:mockAddresses.Remove([string]$address) }
            }
        }

        It 'adds temporary /32 aliases and restores original weak-host settings' {
            Enable-SkypeIpRedirect -IPAddress '203.0.113.1','203.0.113.2' -StatePath $script:statePath | Out-Null
            $script:mockAddresses.Count | Should Be 3
            $script:send | Should Be 'Enabled'
            Disable-SkypeIpRedirect -StatePath $script:statePath
            $script:mockAddresses.Count | Should Be 1
            $script:receive | Should Be 'Enabled'
            $script:send | Should Be 'Disabled'
            (Test-Path -LiteralPath $script:statePath) | Should Be $false
        }

        It 'keeps ownership and original settings across repeated enable calls' {
            Enable-SkypeIpRedirect -IPAddress '203.0.113.1' -StatePath $script:statePath | Out-Null
            Enable-SkypeIpRedirect -IPAddress '203.0.113.1' -StatePath $script:statePath | Out-Null
            Assert-MockCalled New-NetIPAddress -Times 1 -Exactly -Scope It
            @( (Read-SkypeRedirectState $script:statePath).AddedAddresses ).Count | Should Be 1
            Disable-SkypeIpRedirect -StatePath $script:statePath
            $script:send | Should Be 'Disabled'
        }

        It 'never removes a target address that existed before enable' {
            $script:mockAddresses['203.0.113.1'] = [pscustomobject]@{IPAddress='203.0.113.1';InterfaceIndex=1;PrefixLength=32;SkipAsSource=$true}
            Enable-SkypeIpRedirect -IPAddress '203.0.113.1','203.0.113.2' -StatePath $script:statePath | Out-Null
            Disable-SkypeIpRedirect -StatePath $script:statePath
            $script:mockAddresses.ContainsKey('203.0.113.1') | Should Be $true
            $script:mockAddresses.ContainsKey('203.0.113.2') | Should Be $false
            Assert-MockCalled Remove-NetIPAddress -Times 1 -Exactly -Scope It
        }

        It 'rolls back an OS failure after partially adding the requested addresses' {
            $script:failAddress = '203.0.113.2'
            { Enable-SkypeIpRedirect -IPAddress '203.0.113.1','203.0.113.2' -StatePath $script:statePath } | Should Throw
            $script:mockAddresses.Count | Should Be 1
            $script:send | Should Be 'Disabled'
            (Test-Path -LiteralPath $script:statePath) | Should Be $false
            Assert-MockCalled New-NetIPAddress -Times 2 -Exactly -Scope It
            Assert-MockCalled Remove-NetIPAddress -Times 1 -Exactly -Scope It
        }

        It 'recovers an interrupted add from the pending ownership record' {
            Enable-SkypeIpRedirect -IPAddress '203.0.113.1' -StatePath $script:statePath | Out-Null
            $state = Read-SkypeRedirectState $script:statePath
            $state.AddedAddresses = @()
            $state.PendingAddress = '203.0.113.1'
            Save-SkypeRedirectState $state $script:statePath
            Disable-SkypeIpRedirect -StatePath $script:statePath
            $script:mockAddresses.Count | Should Be 1
        }

        It 'preserves an alias changed by another tool and keeps its journal' {
            Enable-SkypeIpRedirect -IPAddress '203.0.113.1' -StatePath $script:statePath | Out-Null
            $script:mockAddresses['203.0.113.1'].PrefixLength = 24
            { Disable-SkypeIpRedirect -StatePath $script:statePath } | Should Throw
            (Test-Path -LiteralPath $script:statePath) | Should Be $true
            $script:mockAddresses['203.0.113.1'].PrefixLength | Should Be 24
            Assert-MockCalled Remove-NetIPAddress -Times 0 -Exactly -Scope It
        }

        It 'refuses to overwrite ownership of an interrupted address operation' {
            Enable-SkypeIpRedirect -IPAddress '203.0.113.1' -StatePath $script:statePath | Out-Null
            $state = Read-SkypeRedirectState $script:statePath
            $state.AddedAddresses = @()
            $state.PendingAddress = '203.0.113.1'
            Save-SkypeRedirectState $state $script:statePath
            { Enable-SkypeIpRedirect -IPAddress '203.0.113.2' -StatePath $script:statePath } | Should Throw
            (Read-SkypeRedirectState $script:statePath).PendingAddress | Should Be '203.0.113.1'
            Assert-MockCalled New-NetIPAddress -Times 1 -Exactly -Scope It
        }

        It 'does not apply a previous boot ownership journal to the current network' {
            Enable-SkypeIpRedirect -IPAddress '203.0.113.1' -StatePath $script:statePath | Out-Null
            $script:boot = 'boot-b'
            Disable-SkypeIpRedirect -StatePath $script:statePath
            Assert-MockCalled Remove-NetIPAddress -Times 0 -Exactly -Scope It
            (Test-Path -LiteralPath $script:statePath) | Should Be $false
            @(Get-ChildItem -LiteralPath (Split-Path $script:statePath) -Filter ((Split-Path $script:statePath -Leaf) + '.expired-*')).Count | Should Be 1
        }

        It 'refuses a corrupt journal before deleting any addresses' {
            [IO.File]::WriteAllText($script:statePath, '{"SchemaVersion":999}')
            { Disable-SkypeIpRedirect -StatePath $script:statePath } | Should Throw
            Assert-MockCalled Remove-NetIPAddress -Times 0 -Exactly -Scope It
            Assert-MockCalled Set-NetIPInterface -Times 0 -Exactly -Scope It
        }

        It 'rejects private destinations and conflicts without network changes' {
            { Enable-SkypeIpRedirect -IPAddress '127.0.0.2' -StatePath $script:statePath } | Should Throw
            $script:mockAddresses['203.0.113.1'] = [pscustomobject]@{IPAddress='203.0.113.1';InterfaceIndex=8;PrefixLength=24;SkipAsSource=$false}
            { Enable-SkypeIpRedirect -IPAddress '203.0.113.1' -StatePath $script:statePath } | Should Throw
            Assert-MockCalled New-NetIPAddress -Times 0 -Exactly -Scope It
            Assert-MockCalled Set-NetIPInterface -Times 0 -Exactly -Scope It
        }
    }
}
