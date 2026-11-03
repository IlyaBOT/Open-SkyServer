[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ClientPath,
    [Parameter(Mandatory=$true)][string]$KeysDirectory,
    [string]$ServerIp = '176.101.124.66',
    [string]$OutputDirectory,
    [string]$ImagePath,
    [string]$PythonPath = 'python',
    [string]$OpenSslPath = 'C:\Program Files\Git\usr\bin\openssl.exe',
    [switch]$GenerateKeys
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$patcher = Split-Path -Parent $PSScriptRoot
$root = Split-Path -Parent $patcher
$ClientPath = (Resolve-Path -LiteralPath $ClientPath).Path
$KeysDirectory = [IO.Path]::GetFullPath($KeysDirectory)
$address = [Net.IPAddress]::Parse($ServerIp)
if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $address.GetAddressBytes()[0] -eq 0 -or $address.GetAddressBytes()[0] -ge 224) {
    throw 'ServerIp must be a unicast IPv4 address.'
}
if ((Get-FileHash -LiteralPath $ClientPath -Algorithm SHA256).Hash -ne
    'A2E175CE7C9888C125E2B3D4C2343229832BA0D0CD8A8A1CE120CE92624E856C') {
    throw 'This builder requires the original Skype 4.2.0.187 executable.'
}
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $patcher ('dist\community-' + $ServerIp) }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a new OutputDirectory.' }
if (-not (Test-Path -LiteralPath $KeysDirectory) -and -not $GenerateKeys) {
    throw 'Existing server keys are required. Use -GenerateKeys only for a new authority.'
}
& $PythonPath --version
if ($LASTEXITCODE -ne 0) { throw 'Python 3 is required.' }
$previousPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = Join-Path $patcher '.packages\analysis'
try {
    & $PythonPath -c 'import pefile, unicorn'
    if ($LASTEXITCODE -ne 0) {
        & $PythonPath -m pip install --only-binary=:all: --target $env:PYTHONPATH 'pefile==2024.8.26' 'unicorn==2.1.4'
        if ($LASTEXITCODE -ne 0) { throw 'Could not install local analysis dependencies.' }
    }
} finally { $env:PYTHONPATH = $previousPythonPath }
$diagnostics = Join-Path $patcher 'diagnostics'
$work = Join-Path $diagnostics ('community-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work) | Out-Null
& (Join-Path $root 'server\csharp\skyserver-keygen.ps1') -OutputDirectory $KeysDirectory `
    -PatcherOutput (Join-Path $work 'legacy-template.ps1') -ServerIp $ServerIp -ClientIntegrity -OpenSslPath $OpenSslPath
if (-not $ImagePath) {
    $ImagePath = Join-Path $work 'original.image.bin'
    & $PythonPath (Join-Path $PSScriptRoot 'Inspect-PackedSkype.py') --client $ClientPath --seconds 120 --output $ImagePath
    if ($LASTEXITCODE -ne 0) { throw 'Original image reconstruction failed.' }
} else { $ImagePath = (Resolve-Path -LiteralPath $ImagePath).Path }
$build = Join-Path $work 'build'
& $PythonPath (Join-Path $PSScriptRoot 'Build-Skype42Lab.py') --client $ClientPath --image $ImagePath `
    --keys-dir $KeysDirectory --server-ip $ServerIp --openssl $OpenSslPath --output-dir $build
if ($LASTEXITCODE -ne 0) { throw 'Client build failed.' }
# The user package contains patch instructions and tools, never a client or keys.
$recipe = Join-Path $work 'community.patch.json'
& $PythonPath (Join-Path $PSScriptRoot 'ClientPatch.py') create --image $ImagePath --build-dir $build `
    --output $recipe
if ($LASTEXITCODE -ne 0) { throw 'Public patch recipe generation failed.' }
& (Join-Path $PSScriptRoot 'New-PublicPatchBundle.ps1') -PatchFile $recipe -OutputDirectory $OutputDirectory -PythonPath $PythonPath
Write-Host "Public patch package: $OutputDirectory"
Write-Host "Server authority: $KeysDirectory"
Write-Host "Private developer build: $build"
