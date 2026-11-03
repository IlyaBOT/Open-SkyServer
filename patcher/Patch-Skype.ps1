<#
Creates a NEW portable directory without changing or starting the selected EXE.
Requires Python 3; analysis wheels are pinned and installed only in this package.
The operator supplies dist/community.patch.json; no private keys are needed.
#>
[CmdletBinding()]
param(
    [string]$ClientPath,
    [string]$OutputDirectory,
    [string]$PatchFile,
    [string]$PythonPath,
    [switch]$NoShortcut
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$packageRoot = [IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
if (-not $PatchFile) { $PatchFile = Join-Path $packageRoot 'dist\community.patch.json' }

function Assert-PatchLocalPath([string]$Path) {
    $at = [IO.Path]::GetFullPath($Path)
    while ($at) {
        if ((Test-Path -LiteralPath $at) -and
            ((Get-Item -LiteralPath $at -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Linked paths are not supported: $at"
        }
        $at = [IO.Path]::GetDirectoryName($at)
    }
}

if (-not (Test-Path -LiteralPath $PatchFile -PathType Leaf)) {
    throw "Public patch profile is missing: $PatchFile. Obtain community.patch.json from the server operator and place it in patcher/dist, or pass -PatchFile."
}
$PatchFile = [IO.Path]::GetFullPath($PatchFile)
Assert-PatchLocalPath $PatchFile
if (-not $ClientPath) {
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = [Windows.Forms.OpenFileDialog]::new()
    $dialog.Title = 'Select your original Skype.exe (4.2.0.187)'
    $dialog.Filter = 'Skype executable (*.exe;*.bak)|*.exe;*.bak|All files (*.*)|*.*'
    $dialog.CheckFileExists = $true
    try {
        if ($dialog.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { Write-Host 'Cancelled; nothing changed.'; return }
        $ClientPath = $dialog.FileName
    } finally { $dialog.Dispose() }
}
$ClientPath = [IO.Path]::GetFullPath($ClientPath)
Assert-PatchLocalPath $ClientPath
$tool = Join-Path $packageRoot 'tools\ClientPatch.py'
$inspector = Join-Path $packageRoot 'tools\Inspect-PackedSkype.py'
$launcher = Join-Path $packageRoot 'Launch-Skype.ps1'
foreach ($required in @($tool, $inspector, $launcher, (Join-Path $packageRoot 'skypatch.ps1'))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Incomplete public patch package: $required" }
    Assert-PatchLocalPath $required
}
$pythonArguments = @()
if ($PythonPath) {
    $PythonPath = (Get-Command $PythonPath -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
} else {
    $python = Get-Command py.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($python) { $PythonPath = $python.Source; $pythonArguments = @('-3') }
    else {
        $python = Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $python) { throw 'Python 3 is required. Install Python or pass -PythonPath to its executable.' }
        $PythonPath = $python.Source
    }
}
$original = $null
$recipeLock = $null
$work = $null
$image = $null
try {
    # Deny writes/deletion until unpacking and the exact backup have finished.
    $original = [IO.File]::Open($ClientPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    if ($original.Length -gt 67108864) { throw 'Original executable exceeds the 64 MiB size limit.' }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $originalHash = [BitConverter]::ToString($hasher.ComputeHash($original)).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
    $original.Position = 0
    if ($originalHash -cne 'a2e175ce7c9888c125e2b3d4c2343229832ba0d0cd8a8a1ce120ce92624e856c') {
        throw "Unsupported original SHA256: $originalHash. Select the exact original Skype 4.2.0.187; no emulator or installer was run."
    }
    $recipeLock = [IO.File]::Open($PatchFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    if ($recipeLock.Length -gt 8388608) { throw 'Public patch profile exceeds the 8 MiB size limit.' }
    $validate = @'
import json, sys
sys.path.insert(0, sys.argv[1])
import ClientPatch as cp
raw = cp.read_bounded(sys.argv[2], cp.MAX_RECIPE_SIZE)
recipe = cp.validate_recipe(cp._json(raw))
print(json.dumps(cp.public_metadata(recipe, cp.sha256(raw))))
'@
    $metadataJson = & $PythonPath @pythonArguments -I -c $validate (Split-Path $tool -Parent) $PatchFile
    if ($LASTEXITCODE -ne 0) { throw 'Public patch profile validation failed; nothing was patched.' }
    $metadata = ($metadataJson -join "`n") | ConvertFrom-Json
    # Never put arbitrary manifest strings into paths or shortcut names.
    if ($metadata.client_version -cne '4.2.0.187') { throw 'Unsupported client version in public patch profile.' }
    if (-not $OutputDirectory) {
        $parent = Join-Path $packageRoot 'client'
        Assert-PatchLocalPath $parent
        [void][IO.Directory]::CreateDirectory($parent)
        $OutputDirectory = Join-Path $parent ('Skype-4.2.0.187-Patched-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
    }
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    Assert-PatchLocalPath $OutputDirectory
    if (Test-Path -LiteralPath $OutputDirectory) { throw 'OutputDirectory must be a NEW directory; existing files will not be overwritten.' }
    if (-not (Test-Path -LiteralPath (Split-Path $OutputDirectory -Parent) -PathType Container)) {
        throw 'OutputDirectory must have an existing parent directory.'
    }
    $shortcutPath = $null
    if (-not $NoShortcut) {
        $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
        if (-not $desktop) { throw 'Desktop folder is unavailable. Use -NoShortcut for a headless installation.' }
        $shortcutPath = Join-Path $desktop 'Skype 4.2.0.187 Patched.lnk'
        if (Test-Path -LiteralPath $shortcutPath) { throw "Desktop shortcut already exists and will not be overwritten: $shortcutPath. Use -NoShortcut or move it first." }
    }
    $packages = Join-Path $packageRoot '.packages\analysis'
    Assert-PatchLocalPath $packages
    $checkPackages = @'
import importlib.metadata, os, sys
try:
    root = os.path.realpath(sys.argv[1])
    versions = {d.metadata['Name'].lower(): d.version for d in importlib.metadata.distributions(path=[root])}
    assert versions.get('pefile') == '2024.8.26' and versions.get('unicorn') == '2.1.4'
    sys.path.insert(0, root)
    import pefile, unicorn
    for module in (pefile, unicorn):
        assert os.path.normcase(os.path.commonpath([root, os.path.realpath(module.__file__)])) == os.path.normcase(root)
except Exception:
    sys.exit(1)
'@
    & $PythonPath @pythonArguments -I -c $checkPackages $packages
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'Installing pinned analysis dependencies into this package only...'
        & $PythonPath @pythonArguments -I -m pip --isolated install --disable-pip-version-check --only-binary=:all: --no-deps --upgrade --target $packages pefile==2024.8.26 unicorn==2.1.4
        if ($LASTEXITCODE -ne 0) { throw 'Local dependency bootstrap failed. Python pip and network access to binary wheels are required; no global packages were installed.' }
        & $PythonPath @pythonArguments -I -c $checkPackages $packages
        if ($LASTEXITCODE -ne 0) { throw 'Pinned package-local analysis dependencies did not validate.' }
    }
    $diagnostics = [IO.Path]::GetFullPath((Join-Path $packageRoot 'diagnostics'))
    Assert-PatchLocalPath $diagnostics
    [void][IO.Directory]::CreateDirectory($diagnostics)
    $work = Join-Path $diagnostics ('public-patch-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $work -ErrorAction Stop
    $image = Join-Path $work 'canonical.image.bin'
    Write-Host 'Unpacking the verified original offline; Skype will not be started...'
    & $PythonPath @pythonArguments -I $inspector --client $ClientPath --output $image
    if ($LASTEXITCODE -ne 0) { throw 'Offline unpacking failed; no client was launched or modified.' }
    if ((Get-Item -LiteralPath $image).Length -ne 25460736 -or
        (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash -ne $metadata.static_image_sha256) {
        throw 'Unpacker did not produce the canonical image SHA256.'
    }
    $null = New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop
    $backup = [IO.File]::Open((Join-Path $OutputDirectory 'Skype.exe.bak'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $original.CopyTo($backup); $backup.Flush($true) } finally { $backup.Dispose() }
    if ((Get-FileHash -LiteralPath (Join-Path $OutputDirectory 'Skype.exe.bak')).Hash -ne $originalHash) { throw 'Exact original backup verification failed.' }
    $outputExe = Join-Path $OutputDirectory 'Skype.exe'
    & $PythonPath @pythonArguments -I $tool apply --image $image --patch $PatchFile --output $outputExe
    if ($LASTEXITCODE -ne 0) { throw "Recipe application failed. Partial new output was retained at $OutputDirectory; the input was not changed." }
    if ((Get-FileHash -LiteralPath $outputExe).Hash -ne $metadata.patched_sha256) { throw 'Patched EXE SHA256 mismatch.' }
    [void][IO.Directory]::CreateDirectory((Join-Path $OutputDirectory 'profile'))
    [IO.File]::Copy($launcher, (Join-Path $OutputDirectory 'Launch-Skype.ps1'), $false)
    $metadataPath = Join-Path $OutputDirectory 'client.json'
    $metadataStream = [IO.File]::Open($metadataPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $metadataBytes = [Text.Encoding]::ASCII.GetBytes(($metadata | ConvertTo-Json))
        $metadataStream.Write($metadataBytes, 0, $metadataBytes.Length)
    } finally { $metadataStream.Dispose() }
    & (Join-Path $OutputDirectory 'Launch-Skype.ps1') -ConfigureOnly
    if ($shortcutPath) {
        if (Test-Path -LiteralPath $shortcutPath) { throw 'Desktop shortcut appeared during patching; refusing to overwrite it.' }
        $shell = New-Object -ComObject WScript.Shell
        try {
            $shortcut = $shell.CreateShortcut($shortcutPath)
            try {
                $shortcut.TargetPath = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
                $shortcut.Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $OutputDirectory 'Launch-Skype.ps1') + '"'
                $shortcut.WorkingDirectory = $OutputDirectory
                $shortcut.IconLocation = $outputExe + ',0'
                $shortcut.Description = 'Skype 4.2.0.187 Patched'
                $shortcut.Save()
            } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) }
        } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
    }
    [pscustomobject]@{ OutputDirectory=$OutputDirectory; ClientPath=$outputExe; ProfilePath=(Join-Path $OutputDirectory 'profile');
        ServerIp=$metadata.server_ip; SHA256=$metadata.patched_sha256; Shortcut=$shortcutPath; Launched=$false }
} finally {
    if ($original) { $original.Dispose() }
    if ($recipeLock) { $recipeLock.Dispose() }
    if ($work) {
        # Only our GUID-named workspace and known temporary file; never recurse.
        $expectedParent = [IO.Path]::GetFullPath((Join-Path $packageRoot 'diagnostics'))
        if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($work)) -eq $expectedParent) {
            Assert-PatchLocalPath $work
            if ($image -and (Test-Path -LiteralPath $image)) { Remove-Item -LiteralPath $image -ErrorAction Stop }
            if (Test-Path -LiteralPath $work) { [IO.Directory]::Delete($work, $false) }
        }
    }
}
