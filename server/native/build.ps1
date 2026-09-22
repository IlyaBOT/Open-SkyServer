$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$vcvars = "D:\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
$outDir = Join-Path $PSScriptRoot "bin\x86\Release"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$source = Join-Path $PSScriptRoot "skype_rc4_helper.c"
$dll = Join-Path $outDir "skype_rc4_helper.dll"
$obj = Join-Path $outDir "skype_rc4_helper.obj"
$cmd = "`"$vcvars`" && cl /nologo /LD /O2 /MT /TC /Fe:`"$dll`" /Fo:`"$obj`" `"$source`""
cmd /c $cmd
if ($LASTEXITCODE -ne 0) {
    throw "native helper build failed with exit code $LASTEXITCODE"
}

Copy-Item -Force $dll (Join-Path $root "skyserver\bin\Release\skype_rc4_helper.dll")
