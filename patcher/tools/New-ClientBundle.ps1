[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BuildDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$build = Get-Content -LiteralPath (Join-Path $BuildDirectory 'build.json') -Raw | ConvertFrom-Json
$client = Join-Path $BuildDirectory 'Skype.exe'
if ((Get-FileHash -LiteralPath $client).Hash -ne $build.patched_sha256) { throw 'Build manifest does not match EXE.' }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a new output directory.' }
[IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($OutputDirectory)) | Out-Null
# Explicit allowlist: never include profiles, database, logs, or private keys.
Copy-Item -LiteralPath $client -Destination (Join-Path $OutputDirectory 'Skype.exe')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'skypatch-package.ps1') -Destination (Join-Path $OutputDirectory 'skypatch.ps1')
$manifest = [ordered]@{format=1; original_sha256=$build.original_sha256; patched_sha256=$build.patched_sha256; server_ip=$build.server_ip}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'client.json'),($manifest | ConvertTo-Json),[Text.Encoding]::ASCII)
$archive = [IO.Path]::GetFullPath($OutputDirectory) + '.zip'
if (Test-Path -LiteralPath $archive) { throw 'Archive already exists.' }
Compress-Archive -LiteralPath @((Join-Path $OutputDirectory 'Skype.exe'),(Join-Path $OutputDirectory 'skypatch.ps1'),(Join-Path $OutputDirectory 'client.json')) -DestinationPath $archive
Get-FileHash -LiteralPath $archive -Algorithm SHA256
