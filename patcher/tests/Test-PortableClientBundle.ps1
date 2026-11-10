[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ClientDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
Add-Type -AssemblyName System.IO.Compression.FileSystem
$patcher = Split-Path -Parent $PSScriptRoot
$builder = Join-Path $patcher 'tools\New-PortableClientBundle.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ('OpenSky-PortableTests-' + [Guid]::NewGuid().ToString('N'))
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
try {
    $source = Join-Path $root 'source with spaces'
    [void][IO.Directory]::CreateDirectory($source)
    foreach ($name in @('Skype.exe', 'Skype.exe.bak', 'client.json')) {
        [IO.File]::Copy((Join-Path $ClientDirectory $name), (Join-Path $source $name))
    }
    # Synthetic secrets must not escape even if the operator selects a used client.
    [void][IO.Directory]::CreateDirectory((Join-Path $source 'profile\existing-account'))
    [void][IO.Directory]::CreateDirectory((Join-Path $source 'private-keys'))
    [IO.File]::WriteAllText((Join-Path $source 'profile\existing-account\main.db'), 'SYNTHETIC-PRIVATE-HISTORY')
    [IO.File]::WriteAllText((Join-Path $source 'profile\shared.xml'), '<config><Private>SYNTHETIC-PASSWORD</Private></config>')
    [IO.File]::WriteAllText((Join-Path $source 'private-keys\login.private.xml'), 'SYNTHETIC-PRIVATE-KEY')
    [IO.File]::WriteAllText((Join-Path $source 'Launch-Skype.ps1'), 'throw "Do not execute source launch scripts"')
    $before = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $source -File -Recurse)) {
        $before[$file.FullName] = (Get-FileHash -LiteralPath $file.FullName).Hash
    }

    $output = Join-Path $root 'portable with spaces'
    $result = & $builder -ClientDirectory $source -OutputDirectory $output
    Assert-Test (Test-Path -LiteralPath $result.Archive -PathType Leaf) 'archive generated without Python or keys'
    Assert-Test ($result.ProfileCopied -eq $false) 'source profile is never copied'
    Assert-Test ((Get-FileHash -LiteralPath $result.Archive).Hash -eq $result.SHA256 -and
        [IO.File]::ReadAllText($result.Archive + '.sha256').StartsWith($result.SHA256 + '  ')) 'outer archive checksum'

    $expected = @('Launch-Skype.ps1', 'README.txt', 'SHA256SUMS.txt', 'Skype.exe', 'Skype.exe.bak',
        'Start-PortableSkype.ps1', 'Start-Skype.cmd', 'client.json', 'profile/shared.xml')
    $zip = [IO.Compression.ZipFile]::OpenRead($result.Archive)
    try {
        $names = @($zip.Entries | Select-Object -ExpandProperty FullName)
        Assert-Test ($names.Count -eq $expected.Count -and -not @(Compare-Object $names $expected).Count) 'exact nine-file ZIP allowlist'
        Assert-Test (@($names | Where-Object { $_ -match '(?i)private|\.db|\.log|\.pcap|existing-account' }).Count -eq 0) 'no secrets, databases, accounts or captures'
    } finally { $zip.Dispose() }
    $unpacked = Join-Path $root 'unpacked with spaces'
    [IO.Compression.ZipFile]::ExtractToDirectory($result.Archive, $unpacked)
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $unpacked 'SHA256SUMS.txt'))) {
        Assert-Test ($line -match '^([0-9a-f]{64})  ([A-Za-z0-9./-]+)$') 'checksum manifest syntax'
        Assert-Test ((Get-FileHash -LiteralPath (Join-Path $unpacked $Matches[2])).Hash -eq $Matches[1]) ('extracted hash: ' + $Matches[2])
    }
    $xml = [Xml.XmlDocument]::new()
    $xml.Load((Join-Path $unpacked 'profile\shared.xml'))
    Assert-Test ($xml.SelectSingleNode('/config/Lib/Connection/SearchServers').InnerText -eq ($result.ServerIp + ':12350')) 'clean profile uses the validated server address'
    Assert-Test ($xml.SelectSingleNode('/config/Lib/Connection/DisableSupernode').InnerText -eq '1' -and
        -not $xml.SelectSingleNode('/config/Private') -and
        @(Get-ChildItem -LiteralPath (Join-Path $unpacked 'profile')).Count -eq 1) 'no account state and supernode mode disabled'
    Assert-Test ((Get-FileHash -LiteralPath (Join-Path $unpacked 'Launch-Skype.ps1')).Hash -eq
        (Get-FileHash -LiteralPath (Join-Path $patcher 'Launch-Skype.ps1')).Hash) 'launcher comes from the repository, not the source client'

    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    & $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $unpacked 'Start-PortableSkype.ps1') -ConfigureOnly -NoShortcut
    Assert-Test ($LASTEXITCODE -eq 0) 'extracted PS5.1 entrypoint configures without Python or launching Skype'
    $unexpected = @(Get-CimInstance Win32_Process -Filter "Name = 'Skype.exe'" | Where-Object {
        $_.ExecutablePath -eq (Join-Path $unpacked 'Skype.exe')
    })
    Assert-Test ($unexpected.Count -eq 0) 'ConfigureOnly does not spawn a client process'
    foreach ($name in @('Start-PortableSkype.ps1', 'Launch-Skype.ps1')) {
        $errors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $unpacked $name), [ref]$null, [ref]$errors)
        Assert-Test (-not $errors.Count) ('PS5.1 syntax: ' + $name)
    }
    Assert-Throws { & $builder -ClientDirectory $source -OutputDirectory $output } 'refusing to overwrite'
    Assert-Test ((Get-FileHash -LiteralPath $result.Archive).Hash -eq $result.SHA256) 'existing archive not overwritten'
    $broken = Join-Path $root 'broken'
    [void][IO.Directory]::CreateDirectory($broken)
    foreach ($name in @('Skype.exe', 'Skype.exe.bak', 'client.json')) {
        [IO.File]::Copy((Join-Path $source $name), (Join-Path $broken $name))
    }
    [IO.File]::AppendAllText((Join-Path $broken 'Skype.exe'), 'SYNTHETIC-CORRUPTION')
    $badOutput = Join-Path $root 'rejected-output'
    Assert-Throws { & $builder -ClientDirectory $broken -OutputDirectory $badOutput } 'SHA256 mismatch'
    Assert-Test (-not (Test-Path -LiteralPath ($badOutput + '.zip'))) 'corrupt executable never reaches a release ZIP'
    foreach ($file in $before.Keys) {
        Assert-Test ((Get-FileHash -LiteralPath $file).Hash -eq $before[$file]) ('source unchanged: ' + [IO.Path]::GetFileName($file))
    }
    Write-Host "PASS $script:passed assertions; no Skype process or desktop shortcut was created."
} finally { Write-Host "Test artifacts retained: $root" }
