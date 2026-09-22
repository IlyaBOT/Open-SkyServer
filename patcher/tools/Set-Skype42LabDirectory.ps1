[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ProfilePath,
    [string]$ServerIp = '192.168.1.101',
    [ValidateRange(1,65535)][int]$Port = 12350
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$root = [IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot -Parent) 'diagnostics')).TrimEnd('\') + '\'
$ProfilePath = [IO.Path]::GetFullPath($ProfilePath).TrimEnd('\')
if (-not $ProfilePath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw 'Only isolated diagnostics profiles may be configured.' }
$ip = [Net.IPAddress]::Parse($ServerIp)
if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.Equals([Net.IPAddress]::Any) -or $ip.GetAddressBytes()[0] -ge 224) { throw 'Expected a unicast IPv4 address.' }
foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='Skype.exe'")) {
    if ($process.CommandLine -and $process.CommandLine.IndexOf($ProfilePath, [StringComparison]::OrdinalIgnoreCase) -ge 0) { throw 'Stop this lab client before editing its profile.' }
}
$paths = @(Join-Path $ProfilePath 'shared.xml')
foreach ($account in @(Get-ChildItem -LiteralPath $ProfilePath -Directory)) {
    $accountConfig = Join-Path $account.FullName 'config.xml'
    if (Test-Path -LiteralPath $accountConfig) {
        if ($account.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked account directories are not supported.' }
        $paths += $accountConfig
    }
}
if ($paths.Count -eq 1) { throw 'Initialize a lab account first; ForceServer is an account-scoped setting.' }
foreach ($path in $paths) {
$settings = New-Object Xml.XmlReaderSettings
$settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
$settings.XmlResolver = $null
$settings.MaxCharactersInDocument = 1048576
$reader = [Xml.XmlReader]::Create($path, $settings)
$document = New-Object Xml.XmlDocument
$document.XmlResolver = $null
try { $document.Load($reader) } finally { $reader.Dispose() }
if ($document.DocumentElement.Name -ne 'config') { throw 'Expected Skype config root.' }
$backup = $path + '.directory-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8) + '.bak'
[IO.File]::Copy($path, $backup, $false)
# The '*' prefix in the native key selects shared.xml. ContactSearch keys
# lack it and must be written to each initialized account's config.xml.
$isShared = $path -eq (Join-Path $ProfilePath 'shared.xml')
$values = if ($isShared) { @{
    'Lib/Connection/SearchServers' = ($ip.ToString() + ':' + $Port)
    'Lib/Connection/DisableSupernode' = '1'
    'Lib/Connection/ForceSupernode' = '0'
} } else { @{
    'Lib/ContactSearch/ForceServer' = '1'
    'Lib/ContactSearch/UseServer' = '1'
} }
if ($isShared) {
    foreach ($key in @('ForceServer','UseServer')) {
        $obsolete = $document.SelectSingleNode('/config/Lib/ContactSearch/' + $key)
        if ($obsolete) { $null = $obsolete.ParentNode.RemoveChild($obsolete) }
    }
}
foreach ($entry in $values.GetEnumerator()) {
    $node = $document.DocumentElement
    foreach ($name in $entry.Key.Split('/')) {
        $child = $node.SelectSingleNode($name)
        if (-not $child) { $child = $document.CreateElement($name); $null = $node.AppendChild($child) }
        $node = $child
    }
    $node.InnerText = $entry.Value
}
$temporary = $path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
try {
    $document.Save($temporary)
    [IO.File]::Replace($temporary, $path, [NullString]::Value)
} finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
[pscustomobject]@{ ConfigPath=$path; Scope=$(if ($isShared) { 'shared' } else { 'account' }); Backup=$backup }
}
