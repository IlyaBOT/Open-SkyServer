[CmdletBinding()]
param(
    # Optional real, offline pipeline. Never launches Skype or reads private keys.
    [string]$CanonicalImage,
    [string]$BuildDirectory,
    [string]$Original,
    [string]$PythonPath = 'python.exe'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$patcher = Split-Path $PSScriptRoot -Parent
. (Join-Path $patcher 'Launch-Skype.ps1')
$root = Join-Path ([IO.Path]::GetTempPath()) ('OpenSky-PublicTests-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
$script:passed = 0

function Assert-Test($Condition, [string]$Name) {
    if (-not $Condition) { throw "FAIL $Name" }
    $script:passed++
    Write-Host "PASS $Name"
}
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    $caught = $false
    try { & $Action } catch {
        $caught = $true
        if ($_.Exception.Message -notmatch $Pattern) { throw }
    }
    Assert-Test $caught "rejected: $Pattern"
}
function Read-TestXml([string]$Path) {
    $document = [Xml.XmlDocument]::new()
    $document.Load($Path)
    return ,$document
}
function Invoke-TestFile([string]$Script, [string[]]$Arguments) {
    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $result = & $powershell -NoProfile -ExecutionPolicy Bypass -File $Script @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    return [pscustomobject]@{ ExitCode=$code; Output=($result | Out-String) }
}

try {
    $profile = Join-Path $root 'profile'
    $account = Join-Path $profile 'account-one'
    [void][IO.Directory]::CreateDirectory($account)
    $shared = Join-Path $profile 'shared.xml'
    $accountXml = Join-Path $account 'config.xml'
    $sharedBefore = '<config><Unrelated keep="yes">text</Unrelated><Lib><Connection><HostCache>OLD</HostCache><LastProbingFailed>1</LastProbingFailed></Connection><ContactSearch><ForceServer>1</ForceServer><UseServer>1</UseServer></ContactSearch></Lib></config>'
    [IO.File]::WriteAllText($shared, $sharedBefore)
    [IO.File]::WriteAllText($accountXml, '<config><Unrelated>keep</Unrelated><Lib><ContactSearch><ForceServer>0</ForceServer></ContactSearch></Lib></config>')
    Set-SkypeProfile -ProfilePath $profile -ServerIp '176.101.124.66' -ResetBootstrap
    $xml = Read-TestXml $shared
    Assert-Test ($xml.SelectSingleNode('/config/Lib/Connection/SearchServers').InnerText -eq '176.101.124.66:12350') 'shared search server'
    Assert-Test ($xml.SelectSingleNode('/config/Lib/Connection/DisableSupernode').InnerText -eq '1') 'disable supernode'
    Assert-Test ($xml.SelectSingleNode('/config/Lib/Connection/ForceSupernode').InnerText -eq '0') 'do not force supernode'
    Assert-Test (-not $xml.SelectSingleNode('/config/Lib/ContactSearch/ForceServer') -and
                 -not $xml.SelectSingleNode('/config/Lib/Connection/HostCache') -and
                 -not $xml.SelectSingleNode('/config/Lib/Connection/LastProbingFailed')) 'remove obsolete shared flags and stale bootstrap'
    Assert-Test ($xml.SelectSingleNode('/config/Unrelated').GetAttribute('keep') -eq 'yes') 'preserve unrelated shared XML'
    $xml = Read-TestXml $accountXml
    Assert-Test ($xml.SelectSingleNode('/config/Lib/ContactSearch/ForceServer').InnerText -eq '1' -and
                 $xml.SelectSingleNode('/config/Lib/ContactSearch/UseServer').InnerText -eq '1' -and
                 $xml.SelectSingleNode('/config/Unrelated').InnerText -eq 'keep') 'account flags and unrelated XML'
    Assert-Test ([IO.File]::ReadAllText($shared + '.opensky.bak') -eq $sharedBefore) 'exact pre-change XML backup'
    $beforeTime = (Get-Item -LiteralPath $shared).LastWriteTimeUtc
    $backupHash = (Get-FileHash -LiteralPath ($shared + '.opensky.bak')).Hash
    Set-SkypeProfile -ProfilePath $profile -ServerIp '176.101.124.66' -ResetBootstrap
    Assert-Test ((Get-Item -LiteralPath $shared).LastWriteTimeUtc -eq $beforeTime) 'idempotence: no unnecessary writes'
    Assert-Test ((Get-FileHash -LiteralPath ($shared + '.opensky.bak')).Hash -eq $backupHash -and
                 @(Get-ChildItem -LiteralPath $profile -Filter '*.bak' -File).Count -eq 1) 'idempotence: no backup churn'

    $xml = Read-TestXml $shared
    $cache = $xml.CreateElement('HostCache')
    $cache.InnerText = 'CURRENT'
    [void]$xml.SelectSingleNode('/config/Lib/Connection').AppendChild($cache)
    $xml.Save($shared)
    Set-SkypeProfile -ProfilePath $profile -ServerIp '176.101.124.66'
    $xml = Read-TestXml $shared
    Assert-Test ($xml.SelectSingleNode('/config/Lib/Connection/HostCache').InnerText -eq 'CURRENT') 'watcher preserves current-session bootstrap cache'

    $locked = [IO.File]::Open($accountXml, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $length = $locked.Length
        Assert-Throws { Set-SkypeXml -Path $accountXml -Values @{'Lib/ContactSearch/ForceServer'='1'} } 'used by another process|being used|Open'
        Set-SkypeProfile -ProfilePath $profile -ServerIp '176.101.124.66' -RetryBusy -WarningAction SilentlyContinue
        Assert-Test ($locked.Length -eq $length) 'busy XML is not truncated'
    } finally { $locked.Dispose() }

    $partialDir = Join-Path $profile 'initializing'
    [void][IO.Directory]::CreateDirectory($partialDir)
    $partial = Join-Path $partialDir 'config.xml'
    [IO.File]::WriteAllText($partial, '<config><')
    Set-SkypeProfile -ProfilePath $profile -ServerIp '176.101.124.66' -RetryBusy -WarningAction SilentlyContinue
    Assert-Test ([IO.File]::ReadAllText($partial) -eq '<config><' -and -not (Test-Path -LiteralPath ($partial + '.opensky.bak'))) 'incomplete first-login XML deferred unchanged'
    [IO.File]::WriteAllText($partial, '<config><Unrelated>first login</Unrelated></config>')
    Set-SkypeProfile -ProfilePath $profile -ServerIp '176.101.124.66' -RetryBusy
    $xml = Read-TestXml $partial
    Assert-Test ($xml.SelectSingleNode('/config/Lib/ContactSearch/UseServer').InnerText -eq '1') 'completed first-login XML retried'

    $other = Join-Path $root 'other-profile'
    [void][IO.Directory]::CreateDirectory($other)
    [IO.File]::WriteAllText((Join-Path $other 'shared.xml'), '<config><Untouched /></config>')
    $otherHash = (Get-FileHash -LiteralPath (Join-Path $other 'shared.xml')).Hash
    $script:watchContext = @{ Count=0; Profile=$profile }
    $fakeProcess = [pscustomobject]@{ Id = -1 }
    $fakeProcess | Add-Member -MemberType ScriptProperty -Name HasExited -Value {
        $script:watchContext.Count++
        if ($script:watchContext.Count -eq 2) {
            $late = Join-Path $script:watchContext.Profile 'created-after-launch'
            [void][IO.Directory]::CreateDirectory($late)
            [IO.File]::WriteAllText((Join-Path $late 'config.xml'), '<config><Login>new</Login></config>')
        }
        return $script:watchContext.Count -ge 4
    }
    Watch-SkypeProfile -Process $fakeProcess -ProfilePath $profile -ServerIp '176.101.124.66'
    $xml = Read-TestXml (Join-Path $profile 'created-after-launch\config.xml')
    Assert-Test ($xml.SelectSingleNode('/config/Lib/ContactSearch/ForceServer').InnerText -eq '1' -and
                 $xml.SelectSingleNode('/config/Lib/ContactSearch/UseServer').InnerText -eq '1') 'watcher discovers account created after launch'
    Assert-Test ((Get-FileHash -LiteralPath (Join-Path $other 'shared.xml')).Hash -eq $otherHash) 'watcher only touches launched profile'

    $unsafe = Join-Path $root 'unsafe.xml'
    foreach ($contents in @('<!DOCTYPE config [<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">]><config>&x;</config>',
                             '<wrong />', '<config><Lib /><Lib /></config>', ('<config>' + ('a' * 1048576) + '</config>'))) {
        [IO.File]::WriteAllText($unsafe, $contents)
        $beforeHash = (Get-FileHash -LiteralPath $unsafe).Hash
        Assert-Throws { Set-SkypeXml -Path $unsafe -Values @{'Lib/Connection/SearchServers'='176.101.124.66:12350'} } 'DTD|config XML root|duplicate XML|size|MiB'
        Assert-Test ((Get-FileHash -LiteralPath $unsafe).Hash -eq $beforeHash) 'invalid XML remains byte-identical'
    }
    Assert-Throws { Start-PatchedSkype -Directory (Join-Path $root 'missing') -ConfigureOnly } 'Missing isolated profile'

    # A minimal copied public package, deliberately with no server tree or keys.
    $package = Join-Path $root 'package with spaces'
    [void][IO.Directory]::CreateDirectory((Join-Path $package 'tools'))
    [void][IO.Directory]::CreateDirectory((Join-Path $package 'dist'))
    foreach ($file in @('Patch-Skype.ps1','Launch-Skype.ps1','skypatch.ps1')) {
        [IO.File]::Copy((Join-Path $patcher $file), (Join-Path $package $file))
    }
    foreach ($file in @('ClientPatch.py','Inspect-PackedSkype.py')) {
        [IO.File]::Copy((Join-Path $patcher ('tools\' + $file)), (Join-Path $package ('tools\' + $file)))
    }
    $patchCommand = Join-Path $package 'Patch-Skype.ps1'
    $wrong = Join-Path $root 'original.exe'
    [IO.File]::WriteAllText($wrong, 'not the supported original')
    Assert-Throws { & $patchCommand -ClientPath $wrong -NoShortcut } 'Public patch profile is missing'
    $fileResult = Invoke-TestFile $patchCommand @('-ClientPath', $wrong, '-NoShortcut')
    Assert-Test ($fileResult.ExitCode -ne 0 -and $fileResult.Output -match 'Public patch profile is missing') 'PS5.1 -File resolves default recipe from its own package'
    $fileResult = Invoke-TestFile (Join-Path $package 'Launch-Skype.ps1') @('-ConfigureOnly')
    Assert-Test ($fileResult.ExitCode -ne 0 -and $fileResult.Output -match 'Missing isolated profile') 'PS5.1 -File resolves launcher default directory'
    $recipe = Join-Path $package 'dist\community.patch.json'
    [IO.File]::WriteAllText($recipe, '{}')
    $wrongHash = (Get-FileHash -LiteralPath $wrong).Hash
    Assert-Throws { & $patchCommand -ClientPath $wrong -OutputDirectory (Join-Path $root 'should-not-exist') -NoShortcut } 'Unsupported original SHA256'
    Assert-Test ((Get-FileHash -LiteralPath $wrong).Hash -eq $wrongHash -and
                 -not (Test-Path -LiteralPath (Join-Path $root 'should-not-exist')) -and
                 -not (Test-Path -LiteralPath (Join-Path $package '.packages')) -and
                 -not (Test-Path -LiteralPath (Join-Path $package 'diagnostics'))) 'unsupported original rejected before writes, bootstrap, or emulation'
    $fileResult = Invoke-TestFile $patchCommand @('-ClientPath', $wrong, '-NoShortcut')
    Assert-Test ($fileResult.ExitCode -ne 0 -and $fileResult.Output -match 'Unsupported original SHA256') 'PS5.1 -File rejects unsupported original before emulation'

    if ($CanonicalImage -or $BuildDirectory -or $Original) {
        if (-not $CanonicalImage -or -not $BuildDirectory -or -not $Original) { throw 'Supply all three integration inputs.' }
        $fileResult = Invoke-TestFile $patchCommand @('-ClientPath', $Original, '-NoShortcut')
        Assert-Test ($fileResult.ExitCode -ne 0 -and $fileResult.Output -match 'Public patch profile validation failed') 'PS5.1 default Python discovery selects one executable'
        # Remove only the known dummy recipe in our own temporary package.
        Remove-Item -LiteralPath $recipe
        & $PythonPath -B (Join-Path $package 'tools\ClientPatch.py') create --image $CanonicalImage --build-dir $BuildDirectory --output $recipe
        if ($LASTEXITCODE -ne 0) { throw 'Real recipe creation failed.' }
        $originalHash = (Get-FileHash -LiteralPath $Original).Hash
        $portable = Join-Path $root 'portable with spaces'
        $fileResult = Invoke-TestFile $patchCommand @('-ClientPath', $Original, '-OutputDirectory', $portable, '-PythonPath', $PythonPath, '-NoShortcut')
        Write-Host $fileResult.Output
        Assert-Test ($fileResult.ExitCode -eq 0) 'PS5.1 -File full offline pipeline'
        Assert-Test ((Get-FileHash -LiteralPath (Join-Path $portable 'Skype.exe')).Hash -eq
                     (Get-FileHash -LiteralPath (Join-Path $BuildDirectory 'Skype.exe')).Hash) 'real exact rebuilt EXE'
        Assert-Test ((Get-FileHash -LiteralPath (Join-Path $portable 'Skype.exe.bak')).Hash -eq $originalHash -and
                     (Get-FileHash -LiteralPath $Original).Hash -eq $originalHash) 'real exact backup and unchanged input'
        $manifest = Get-Content -LiteralPath (Join-Path $portable 'client.json') -Raw | ConvertFrom-Json
        $sharedXml = Read-TestXml (Join-Path $portable 'profile\shared.xml')
        Assert-Test ($sharedXml.SelectSingleNode('/config/Lib/Connection/SearchServers').InnerText -eq ($manifest.server_ip + ':12350')) 'real portable retains recipe server configuration'
        Assert-Test (@(Get-ChildItem -LiteralPath $portable -File).Count -eq 4 -and
                     -not (Test-Path -LiteralPath (Join-Path $portable 'keys'))) 'public output allowlist and no private keys'
        $fileResult = Invoke-TestFile (Join-Path $portable 'Launch-Skype.ps1') @('-ConfigureOnly')
        Assert-Test ($fileResult.ExitCode -eq 0) 'PS5.1 -File copied launcher configures without launching'
        Assert-Throws { & $patchCommand -ClientPath $Original -OutputDirectory $portable -PythonPath $PythonPath -NoShortcut } 'NEW directory'
        Write-Host "Offline integration artifacts: $root"
    } else { Write-Host 'SKIP real unpacker pipeline: no integration inputs supplied.' }
    Write-Host "PASS $script:passed assertions; no Skype process was started."
} finally {
    # Keep generated artifacts for inspection. No repository or user data cleanup.
    Write-Host "Test artifacts: $root"
}
