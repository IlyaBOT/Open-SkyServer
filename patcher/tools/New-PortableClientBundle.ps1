<#
Packages an existing verified portable client. Uses an explicit file allowlist,
never its profile or launch scripts. No keys, unpacker or Python are required.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ClientDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$patcher = Split-Path -Parent $PSScriptRoot
. (Join-Path $patcher 'Launch-Skype.ps1')
Add-Type -AssemblyName System.IO.Compression

$ClientDirectory = [IO.Path]::GetFullPath($ClientDirectory)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$archivePath = $OutputDirectory + '.zip'
$hashPath = $archivePath + '.sha256'
foreach ($path in @($ClientDirectory, $OutputDirectory, $archivePath, $hashPath)) { Assert-SkypeLocalPath $path }
foreach ($path in @($OutputDirectory, $archivePath, $hashPath)) {
    if (Test-Path -LiteralPath $path) { throw "Choose new output paths; refusing to overwrite: $path" }
}
if (-not (Test-Path -LiteralPath (Split-Path -Parent $OutputDirectory) -PathType Container)) {
    throw 'OutputDirectory must have an existing parent directory.'
}
$inputs = @('Skype.exe', 'Skype.exe.bak', 'client.json')
foreach ($name in $inputs) {
    $path = Join-Path $ClientDirectory $name
    Assert-SkypeLocalPath $path
    $file = Get-Item -LiteralPath $path -ErrorAction Stop
    $limit = if ($name -eq 'client.json') { 16384 } else { 67108864 }
    if ($file.PSIsContainer -or $file.Length -gt $limit) { throw "Invalid or oversized portable input: $name" }
}
foreach ($name in @('Launch-Skype.ps1', 'Start-Skype.cmd', 'Start-PortableSkype.ps1', 'PORTABLE_README.txt')) {
    $path = Join-Path $patcher $name
    Assert-SkypeLocalPath $path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing package tool: $name" }
}
[void][IO.Directory]::CreateDirectory($OutputDirectory)
foreach ($name in $inputs) { [IO.File]::Copy((Join-Path $ClientDirectory $name), (Join-Path $OutputDirectory $name), $false) }
[void][IO.Directory]::CreateDirectory((Join-Path $OutputDirectory 'profile'))

# Validate the copies with the trusted launcher before emitting a usable ZIP.
# ConfigureOnly creates a clean bootstrap XML; it never logs in or starts Skype.
Start-PatchedSkype -Directory $OutputDirectory -ConfigureOnly
foreach ($name in @('Launch-Skype.ps1', 'Start-Skype.cmd', 'Start-PortableSkype.ps1')) {
    [IO.File]::Copy((Join-Path $patcher $name), (Join-Path $OutputDirectory $name), $false)
}
$metadata = Get-Content -LiteralPath (Join-Path $OutputDirectory 'client.json') -Raw | ConvertFrom-Json
$readme = [IO.File]::ReadAllText((Join-Path $patcher 'PORTABLE_README.txt')).
    Replace('{SERVER_IP}', $metadata.server_ip).Replace('{SERVER_PORT}', [string]$metadata.server_port)
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'README.txt'), $readme, [Text.Encoding]::ASCII)

$files = @('Launch-Skype.ps1', 'README.txt', 'Skype.exe', 'Skype.exe.bak',
    'Start-PortableSkype.ps1', 'Start-Skype.cmd', 'client.json', 'profile/shared.xml')
$lines = foreach ($name in $files) {
    $hash = (Get-FileHash -LiteralPath (Join-Path $OutputDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    $hash + '  ' + $name
}
[IO.File]::WriteAllLines((Join-Path $OutputDirectory 'SHA256SUMS.txt'), [string[]]$lines, [Text.Encoding]::ASCII)
$files += 'SHA256SUMS.txt'

# Build the archive from named files, not a recursive folder wildcard.
$stream = [IO.File]::Open($archivePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        foreach ($name in $files) {
            $input = [IO.File]::OpenRead((Join-Path $OutputDirectory $name))
            try {
                $entry = $zip.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
                $target = $entry.Open()
                try { $input.CopyTo($target) } finally { $target.Dispose() }
            } finally { $input.Dispose() }
        }
    } finally { $zip.Dispose() }
} finally { $stream.Dispose() }
$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$hashStream = [IO.File]::Open($hashPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $bytes = [Text.Encoding]::ASCII.GetBytes($archiveHash + '  ' + [IO.Path]::GetFileName($archivePath) + "`r`n")
    $hashStream.Write($bytes, 0, $bytes.Length)
} finally { $hashStream.Dispose() }
[pscustomobject]@{
    Archive = $archivePath; SHA256 = $archiveHash; Bytes = (Get-Item -LiteralPath $archivePath).Length
    ClientVersion = $metadata.client_version; ServerIp = $metadata.server_ip; ProfileCopied = $false
}
