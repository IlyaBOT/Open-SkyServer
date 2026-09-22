$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'Visual Studio C++ x86 tools are required.' }
$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars32.bat'
$output = Join-Path $PSScriptRoot 'bin\x86\Release'
[IO.Directory]::CreateDirectory($output) | Out-Null
$source = Join-Path $PSScriptRoot 'skype_blob_worker.c'
$exe = Join-Path $output 'skype_blob_worker.exe'
$obj = Join-Path $output 'skype_blob_worker.obj'
& cmd /c "`"$vcvars`" && cl /nologo /O2 /MT /TC /Fe:`"$exe`" /Fo:`"$obj`" `"$source`" /link ws2_32.lib"
if ($LASTEXITCODE -ne 0) { throw 'Blob worker build failed.' }
Write-Host "Built $exe"
