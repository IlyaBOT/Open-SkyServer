param([switch]$Test)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio Installer/vswhere.exe was not found.' }
$msbuild = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) { throw 'Install the Visual Studio MSBuild component.' }

$referenceRoot = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework'
if (-not (Test-Path -LiteralPath (Join-Path $referenceRoot '.NETFramework\v4.0\mscorlib.dll'))) {
    $packageRoot = Join-Path $PSScriptRoot '.packages\net40.1.0.3'
    $referenceRoot = Join-Path $packageRoot 'build'
    if (-not (Test-Path -LiteralPath (Join-Path $referenceRoot '.NETFramework\v4.0\mscorlib.dll'))) {
        New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
        $archive = Join-Path $packageRoot 'references.nupkg'
        $url = 'https://api.nuget.org/v3-flatcontainer/microsoft.netframework.referenceassemblies.net40/1.0.3/microsoft.netframework.referenceassemblies.net40.1.0.3.nupkg'
        $oldProtocol = [Net.ServicePointManager]::SecurityProtocol
        try {
            [Net.ServicePointManager]::SecurityProtocol = $oldProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $archive -TimeoutSec 60
        } finally {
            [Net.ServicePointManager]::SecurityProtocol = $oldProtocol
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $package = [IO.Compression.ZipFile]::OpenRead($archive)
        try {
            $root = [IO.Path]::GetFullPath($packageRoot).TrimEnd('\') + '\'
            foreach ($entry in $package.Entries) {
                $destination = [IO.Path]::GetFullPath((Join-Path $packageRoot $entry.FullName))
                if (-not $destination.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Archive entry is outside the package directory.'
                }
                if ($entry.Name.Length -eq 0) { continue }
                [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destination, $true)
            }
        } finally {
            $package.Dispose()
        }
    }
}

function Build-Project([string]$Project) {
    $frameworkPath = Join-Path $referenceRoot '.NETFramework\v4.0'
    & $msbuild $Project /nologo /verbosity:minimal /m /p:Configuration=Release /p:Platform=AnyCPU "/p:TargetFrameworkRootPath=$referenceRoot" "/p:FrameworkPathOverride=$frameworkPath"
    if ($LASTEXITCODE -ne 0) { throw "MSBuild failed: $Project" }
}

& (Join-Path (Split-Path -Parent $PSScriptRoot) 'skyserver_native\build.ps1')
& (Join-Path (Split-Path -Parent $PSScriptRoot) 'skyserver_native\build_blob_worker.ps1')
Build-Project (Join-Path $PSScriptRoot 'SkyServer.csproj')
if ($Test) {
    Build-Project (Join-Path $PSScriptRoot 'tests\ProtocolTests.csproj')
    $sqlite = $env:SKYSERVER_SQLITE
    if (-not $sqlite) { $sqlite = (Get-Command sqlite3.exe -ErrorAction Stop).Source }
    $output = Join-Path $PSScriptRoot ('diagnostics\auth-tests-' + [Guid]::NewGuid().ToString('N'))
    & (Join-Path $PSScriptRoot 'tests\bin\Release\ProtocolTests.exe') $sqlite $output
    if ($LASTEXITCODE -ne 0) { throw 'Protocol tests failed.' }
    Write-Host "Test artifacts: $output"
}
