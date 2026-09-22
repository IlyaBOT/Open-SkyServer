Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-SkypeRedirectAdmin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open PowerShell as Administrator to enable or disable IP aliases. Plan and Status do not require elevation.'
    }
}

function Get-SkypeRedirectBootId {
    (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o')
}

function ConvertTo-SkypeRedirectAddress([string]$Address) {
    $ip = $null
    if ($Address -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or -not [Net.IPAddress]::TryParse($Address, [ref]$ip)) {
        throw "Not an IPv4 literal: $Address"
    }
    $b = $ip.GetAddressBytes()
    if ($b[0] -in 0,10,127 -or $b[0] -ge 224 -or
        ($b[0] -eq 169 -and $b[1] -eq 254) -or
        ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
        ($b[0] -eq 192 -and $b[1] -eq 168) -or
        ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127)) {
        throw "Refusing a local/private/multicast destination: $Address"
    }
    $ip.ToString()
}

function Get-SkypeRedirectTargets {
    param([string]$AddressListPath, [string]$SkypeSharedXml, [switch]$IncludeHostCache, [string[]]$AdditionalIPAddress = @())
    $addresses = @()
    foreach ($line in [IO.File]::ReadAllLines($AddressListPath)) {
        $value = ($line -split '#', 2)[0].Trim()
        if ($value) { $addresses += ConvertTo-SkypeRedirectAddress $value }
    }
    foreach ($address in $AdditionalIPAddress) { $addresses += ConvertTo-SkypeRedirectAddress $address }
    if ($IncludeHostCache -and (Test-Path -LiteralPath $SkypeSharedXml)) {
        # Use the server's existing HostCache parser without changing the profile.
        $type = [AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType('SkyServer.SkypeHostCache', $false) } | Select-Object -First 1
        if (-not $type) {
            Add-Type -Path (Join-Path $PSScriptRoot 'SkypeHostCache.cs') -ReferencedAssemblies System.dll,System.Xml.dll -WarningAction SilentlyContinue
            $type = [AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType('SkyServer.SkypeHostCache', $false) } | Select-Object -First 1
        }
        $endpoints = $type.GetMethod('ReadEndpoints').Invoke($null, @($SkypeSharedXml))
        foreach ($endpoint in $endpoints) {
            try { $addresses += ConvertTo-SkypeRedirectAddress $endpoint.Address.ToString() }
            catch { Write-Warning "Skipped HostCache entry: $($_.Exception.Message)" }
        }
    }
    @($addresses | Sort-Object -Unique)
}

function Get-SkypeRedirectPlan {
    param([string[]]$IPAddress, [int]$InterfaceIndex = 1)
    $current = @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
    if (-not @($current | Where-Object { $_.IPAddress -eq '127.0.0.1' -and $_.InterfaceIndex -eq $InterfaceIndex }).Count) {
        throw "Interface $InterfaceIndex is not the IPv4 loopback interface."
    }
    foreach ($address in @($IPAddress | Sort-Object -Unique)) {
        $address = ConvertTo-SkypeRedirectAddress $address
        $existing = @($current | Where-Object IPAddress -eq $address)
        $action = 'Add'
        if ($existing.Count) {
            $action = 'KeepExisting'
            if (@($existing | Where-Object InterfaceIndex -ne $InterfaceIndex).Count) { $action = 'Conflict' }
        }
        [pscustomobject]@{ IPAddress = $address; Action = $action; InterfaceIndex = $InterfaceIndex; PrefixLength = 32; PolicyStore = 'ActiveStore' }
    }
}

function Save-SkypeRedirectState($State, [string]$Path) {
    $Path = [IO.Path]::GetFullPath($Path)
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)) | Out-Null
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($temporary, ($State | ConvertTo-Json -Depth 6), [Text.Encoding]::UTF8)
    if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $Path) }
}

function Read-SkypeRedirectState([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $state = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    if ($state.SchemaVersion -ne 1 -or $state.InterfaceIndex -lt 1 -or -not $state.BootId -or
        $state.OriginalWeakHostReceive -notin 'Enabled','Disabled' -or $state.OriginalWeakHostSend -notin 'Enabled','Disabled') {
        throw 'Invalid redirect state; no network changes were made.'
    }
    foreach ($address in @($state.AddedAddresses) + @($state.PendingAddress)) {
        if (-not $address) { continue }
        [void](ConvertTo-SkypeRedirectAddress $address)
        if ($address -notin $state.TargetAddresses -or $address -in $state.OriginalAddresses) {
            throw 'Redirect state attempts to remove an unowned address.'
        }
    }
    $state
}

function Disable-SkypeIpRedirect {
    param([string]$StatePath)
    Assert-SkypeRedirectAdmin
    $state = Read-SkypeRedirectState $StatePath
    if (-not $state) { Write-Host 'No owned IP aliases to remove.'; return }
    if ($state.BootId -ne (Get-SkypeRedirectBootId)) {
        # ActiveStore changes expired at reboot. Never act on a different boot's addresses.
        $archive = $StatePath + '.expired-' + [Guid]::NewGuid().ToString('N')
        [IO.File]::Move([IO.Path]::GetFullPath($StatePath), [IO.Path]::GetFullPath($archive))
        Write-Host "Archived expired state without changing the network: $archive"
        return
    }
    [void](Get-SkypeRedirectPlan -IPAddress @() -InterfaceIndex $state.InterfaceIndex)
    $owned = @(@($state.AddedAddresses) + @($state.PendingAddress) | Where-Object { $_ } | Sort-Object -Unique)
    foreach ($address in $owned) {
        $existing = @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Where-Object IPAddress -eq $address)
        foreach ($item in $existing) {
            if ($item.InterfaceIndex -ne $state.InterfaceIndex -or $item.PrefixLength -ne 32 -or -not $item.SkipAsSource) {
                throw "Address $address has changed outside this script; preserving it and the journal."
            }
            Remove-NetIPAddress -InterfaceIndex $state.InterfaceIndex -IPAddress $address -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop
        }
        $state.AddedAddresses = @($state.AddedAddresses | Where-Object { $_ -ne $address })
        if ($state.PendingAddress -eq $address) { $state.PendingAddress = '' }
        Save-SkypeRedirectState $state $StatePath
    }
    $interface = Get-NetIPInterface -InterfaceIndex $state.InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    $restore = @{ InterfaceIndex = $state.InterfaceIndex; AddressFamily = 'IPv4'; PolicyStore = 'ActiveStore'; ErrorAction = 'Stop' }
    if ([string]$interface.WeakHostReceive -eq 'Enabled') { $restore.WeakHostReceive = $state.OriginalWeakHostReceive }
    if ([string]$interface.WeakHostSend -eq 'Enabled') { $restore.WeakHostSend = $state.OriginalWeakHostSend }
    if ($restore.ContainsKey('WeakHostReceive') -or $restore.ContainsKey('WeakHostSend')) { Set-NetIPInterface @restore }
    Remove-Item -LiteralPath $StatePath -ErrorAction Stop
    Write-Host 'Removed owned IP aliases and restored interface settings where unchanged by others.'
}

function Enable-SkypeIpRedirect {
    param([string[]]$IPAddress, [int]$InterfaceIndex = 1, [string]$StatePath)
    Assert-SkypeRedirectAdmin
    $plan = @(Get-SkypeRedirectPlan -IPAddress $IPAddress -InterfaceIndex $InterfaceIndex)
    if (-not $plan.Count) { throw 'No redirect targets.' }
    if (@($plan | Where-Object Action -eq 'Conflict').Count) { throw 'An IP already belongs to another interface; no changes made.' }
    $state = Read-SkypeRedirectState $StatePath
    $boot = Get-SkypeRedirectBootId
    if ($state -and ($state.BootId -ne $boot -or $state.InterfaceIndex -ne $InterfaceIndex)) {
        throw 'Journal belongs to a different boot/interface. Run Disable before enabling again.'
    }
    if ($state -and $state.PendingAddress) {
        throw 'An interrupted address operation is pending. Run Disable to recover before enabling again.'
    }
    if (-not $state) {
        $interface = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        $state = [pscustomobject]@{
            SchemaVersion = 1; BootId = $boot; InterfaceIndex = $InterfaceIndex
            OriginalWeakHostReceive = [string]$interface.WeakHostReceive
            OriginalWeakHostSend = [string]$interface.WeakHostSend
            OriginalAddresses = @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Select-Object -ExpandProperty IPAddress)
            TargetAddresses = @(); AddedAddresses = @(); PendingAddress = ''
        }
    }
    $state.TargetAddresses = @(@($state.TargetAddresses) + @($plan.IPAddress) | Sort-Object -Unique)
    Save-SkypeRedirectState $state $StatePath
    try {
        Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -WeakHostReceive Enabled -WeakHostSend Enabled -ErrorAction Stop
        foreach ($item in $plan) {
            if ($item.Action -ne 'Add') { continue }
            $state.PendingAddress = $item.IPAddress
            Save-SkypeRedirectState $state $StatePath
            New-NetIPAddress -InterfaceIndex $InterfaceIndex -IPAddress $item.IPAddress -PrefixLength 32 -SkipAsSource $true -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
            $state.AddedAddresses = @(@($state.AddedAddresses) + $item.IPAddress | Sort-Object -Unique)
            $state.PendingAddress = ''
            Save-SkypeRedirectState $state $StatePath
        }
    }
    catch {
        $failure = $_
        try { Disable-SkypeIpRedirect -StatePath $StatePath }
        catch { Write-Warning "Rollback incomplete. Keep $StatePath and retry Disable: $($_.Exception.Message)" }
        throw $failure
    }
    $plan
}

Export-ModuleMember -Function Get-SkypeRedirectTargets,Get-SkypeRedirectPlan,Read-SkypeRedirectState,Enable-SkypeIpRedirect,Disable-SkypeIpRedirect
