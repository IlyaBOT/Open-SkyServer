[CmdletBinding()]
param(
    [ValidateSet('Patch','Restore','Inspect')][string]$Action = 'Patch',
    [string]$ClientPath,
    [string]$ProfilePath = (Join-Path $env:APPDATA 'Skype')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'client.json') -Raw | ConvertFrom-Json
$payload = Join-Path $PSScriptRoot 'Skype.exe'
if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash -ne $manifest.patched_sha256) { throw 'Client package hash mismatch.' }
if (-not $ClientPath) {
    foreach ($path in @((Join-Path ${env:ProgramFiles(x86)} 'Skype\Phone\Skype.exe'), (Join-Path $env:ProgramFiles 'Skype\Phone\Skype.exe'))) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { $ClientPath = $path; break }
    }
}
if (-not $ClientPath) { throw 'Skype installation not found. Supply -ClientPath.' }
$ClientPath = [IO.Path]::GetFullPath($ClientPath)
if ($ClientPath -eq [IO.Path]::GetFullPath($payload)) { throw 'Select an installed clean client, not the package payload.' }
$hash = (Get-FileHash -LiteralPath $ClientPath -Algorithm SHA256).Hash
if ($Action -eq 'Inspect') {
    [pscustomobject]@{Client=$ClientPath; SHA256=$hash; ServerIp=$manifest.server_ip; Supported=($hash -in @($manifest.original_sha256,$manifest.patched_sha256))}
    return
}
if (@(Get-Process Skype -ErrorAction SilentlyContinue).Count) { throw 'Exit all Skype instances before patching or restoring.' }
$backup = $ClientPath + '.bak'
if ($Action -eq 'Restore') {
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $manifest.original_sha256) { throw 'Original backup hash mismatch.' }
    if ($hash -notin @($manifest.original_sha256,$manifest.patched_sha256)) { throw 'Unknown current executable; refusing to overwrite.' }
    [IO.File]::Copy($backup,$ClientPath,$true)
    Write-Host 'Original EXE restored. Profile settings and account data were preserved.'
    return
}
if ($hash -notin @($manifest.original_sha256,$manifest.patched_sha256)) { throw 'Unsupported client hash. This package supports one exact Skype 4.2 build.' }
if (Test-Path -LiteralPath $backup) {
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $manifest.original_sha256) { throw 'Existing .bak is not the expected original. It will not be overwritten.' }
} elseif ($hash -eq $manifest.original_sha256) { [IO.File]::Copy($ClientPath,$backup,$false) }
else { throw 'Patched EXE has no original backup; refusing to invent one.' }
if ($hash -ne $manifest.patched_sha256) {
    $stage = $ClientPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::Copy($payload,$stage,$false)
        if ((Get-FileHash -LiteralPath $stage).Hash -ne $manifest.patched_sha256) { throw 'Staged payload hash mismatch.' }
        [IO.File]::Replace($stage,$ClientPath,[NullString]::Value)
    } finally { if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage } }
}
# Search routing is account-scoped. Run again after the first login and exit.
$ProfilePath = [IO.Path]::GetFullPath($ProfilePath)
[IO.Directory]::CreateDirectory($ProfilePath) | Out-Null
$shared = Join-Path $ProfilePath 'shared.xml'
$paths = @($shared)
foreach ($account in @(Get-ChildItem -LiteralPath $ProfilePath -Directory)) {
    if ($account.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
    $config = Join-Path $account.FullName 'config.xml'
    if (Test-Path -LiteralPath $config) { $paths += $config }
}
foreach ($path in $paths) {
    $document = New-Object Xml.XmlDocument
    $document.XmlResolver = $null
    if (Test-Path -LiteralPath $path) {
        $settings = New-Object Xml.XmlReaderSettings
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersInDocument = 1048576
        $reader = [Xml.XmlReader]::Create($path,$settings)
        try { $document.Load($reader) } finally { $reader.Dispose() }
        [IO.File]::Copy($path,($path + '.skypatch-' + [Guid]::NewGuid().ToString('N') + '.bak'),$false)
    } else { $document.LoadXml('<config version="1.0" />') }
    if ($document.DocumentElement.Name -ne 'config') { throw 'Unexpected profile XML root.' }
    $values = if ($path -eq $shared) { @{
        'Lib/Connection/SearchServers'=($manifest.server_ip + ':12350')
        'Lib/Connection/DisableSupernode'='1'
        'Lib/Connection/ForceSupernode'='0'
    } } else { @{'Lib/ContactSearch/ForceServer'='1'; 'Lib/ContactSearch/UseServer'='1'} }
    foreach ($entry in $values.GetEnumerator()) {
        $node = $document.DocumentElement
        foreach ($name in $entry.Key.Split('/')) {
            $child = $node.SelectSingleNode($name)
            if (-not $child) { $child = $document.CreateElement($name); $null = $node.AppendChild($child) }
            $node = $child
        }
        $node.InnerText = $entry.Value
    }
    $document.Save($path)
}
Write-Host "Patched for $($manifest.server_ip). Backup: $backup"
if ($paths.Count -eq 1) { Write-Warning 'After first login, exit Skype and run this patcher again to configure account-scoped search.' }
