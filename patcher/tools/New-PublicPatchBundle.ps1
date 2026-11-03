[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PatchFile,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$PythonPath = 'python'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$patcher = Split-Path -Parent $PSScriptRoot
$PatchFile = (Resolve-Path -LiteralPath $PatchFile).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$archive = $OutputDirectory + '.zip'
if ((Test-Path -LiteralPath $OutputDirectory) -or (Test-Path -LiteralPath $archive)) {
    throw 'Choose new package and archive output paths.'
}
$validate = @'
import sys
sys.path.insert(0, sys.argv[1])
from ClientPatch import load_recipe
load_recipe(sys.argv[2])
'@
& $PythonPath -I -c $validate $PSScriptRoot $PatchFile
if ($LASTEXITCODE -ne 0) { throw 'Invalid public patch recipe.' }
$files = @('Patch-Skype.ps1','Patch-Skype.cmd','Launch-Skype.ps1','skypatch.ps1',
           'tools\ClientPatch.py','tools\Inspect-PackedSkype.py')
foreach ($name in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $patcher $name) -PathType Leaf)) {
        throw "Missing public package tool: $name"
    }
}
[IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $OutputDirectory 'tools')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $OutputDirectory 'dist')) | Out-Null
foreach ($name in $files) {
    Copy-Item -LiteralPath (Join-Path $patcher $name) -Destination (Join-Path $OutputDirectory $name)
}
Copy-Item -LiteralPath $PatchFile -Destination (Join-Path $OutputDirectory 'dist\community.patch.json')
Compress-Archive -LiteralPath @(
    (Join-Path $OutputDirectory 'Patch-Skype.ps1'),
    (Join-Path $OutputDirectory 'Patch-Skype.cmd'),
    (Join-Path $OutputDirectory 'Launch-Skype.ps1'),
    (Join-Path $OutputDirectory 'skypatch.ps1'),
    (Join-Path $OutputDirectory 'tools'),
    (Join-Path $OutputDirectory 'dist')
) -DestinationPath $archive
Get-FileHash -LiteralPath $archive -Algorithm SHA256
