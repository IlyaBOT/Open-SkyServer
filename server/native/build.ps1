$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio Installer/vswhere.exe was not found.' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'Visual Studio C++ x86 tools are required.' }
$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars32.bat'

$outDir = Join-Path $PSScriptRoot 'bin\x86\Release'
[IO.Directory]::CreateDirectory($outDir) | Out-Null

$source = Join-Path $PSScriptRoot 'skype_rc4_helper.c'
$dll = Join-Path $outDir 'skype_rc4_helper.dll'
$obj = Join-Path $outDir 'skype_rc4_helper.obj'
& cmd /c "`"$vcvars`" && cl /nologo /LD /O2 /MT /TC /Fe:`"$dll`" /Fo:`"$obj`" `"$source`" /link ws2_32.lib"
if ($LASTEXITCODE -ne 0) { throw 'RC4 helper build failed.' }
Write-Host "Built $dll"
