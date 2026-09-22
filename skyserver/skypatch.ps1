# Legacy constant-patcher template. Packed Skype 4.2 requires the verified
# package workflow in DEPLOYMENT.md and tools/New-ClientBundle.ps1 instead.
[CmdletBinding()]
param(
    [ValidateSet('Patch', 'Inspect', 'Restore')][string]$Action = 'Patch',
    [string]$ClientPath,
    [string]$ProfilePath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

# skyserver-keygen fills these PUBLIC values in the distributable copy.
$ServerIp = '@@SERVER_IP@@'
$LoginModulusHex = '@@LOGIN_MODULUS@@'
$CredentialsModulusHex = '@@CREDENTIALS_MODULUS@@'
$OriginalLoginModulus = 'A8F223612F4F5FC81EF1CA5E310B0B21532A72DF6C1AF0FBEC87304AEC983AAB5D74A14CC72E53EF7752A248C0E5ABE09484B597692015E796350989C88B3CAE140CA82CCD9914E540468CF0EDB35DCBA4C352890E7A9EAFAC550B3978627651AD0A804F385EF5F4093AC6EE66B23E1F8202C61C6C0375EEB713852397CED2E199492AA61A3EAB163D4C2625C873E95CAFD95B80DD2D8732C8E25638A2007ACFA6C8F1FF31CC2BC4CA8F4446F51DA404335A48C955AAA3A4B57250D7BA29700B'
$OriginalCredentialsModulus = 'B8506AEED8ED30FE1C0E6774874B59206A77329042A49BE2403DA47D50052441067F87BCD57E6579B83DF0BADE2BEFF5B5CD8D87E8B3EDAC5F57FABCCD49695974E2B5E5F0287D6C19ECC31B4504A9F8BE25DA78FA4EF345F91D339B73CC2D70B3904E11CA570CE9B5DC4B08B3C44B74DC463587EA637EF4456E61462B72042FC2F4AD5510A9850C06DC9A7374412FCADDA955BD9800F9754CB3B8CC62D0E98D8282180971055B457C06F351E61164FC5A9DE9D83D1D1378964001380B5B99EE4C5C7D50AC2462A4B7EA34FD32D90BD8D4B46410263673F900D1C60470165DF9F3CB48016AB8CA45CE6875A71D977915CA8251B50258748DBC37FE332EDC2855'
$KnownPackedHash = 'A2E175CE7C9888C125E2B3D4C2343229832BA0D0CD8A8A1CE120CE92624E856C'
# Do not infer patch offsets from a version string or coincidental four-byte hits.
# Add only profiles verified against the EXACT original file and a native login test.
$VerifiedProfiles = @()

function Convert-Hex([string]$Value) {
    if ($Value.Length -eq 0 -or $Value.Length % 2 -ne 0 -or $Value -notmatch '\A[0-9a-fA-F]+\z') { throw 'Invalid hexadecimal bytes.' }
    $bytes = New-Object byte[] ($Value.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($Value.Substring(2 * $i, 2), 16) }
    return ,$bytes
}

function Get-BytesHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '') } finally { $sha.Dispose() }
}

function Find-Client {
    $paths = New-Object 'Collections.Generic.List[string]'
    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Skype.exe',
                       'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\Skype.exe',
                       'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Skype.exe')) {
        if (Test-Path -LiteralPath $key) {
            $value = (Get-Item -LiteralPath $key).GetValue('')
            if ($value) { $paths.Add(([string]$value).Trim('"')) }
        }
    }
    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:LOCALAPPDATA)) {
        if ($base) { $paths.Add((Join-Path $base 'Skype\Phone\Skype.exe')) }
    }
    foreach ($path in $paths) { if (Test-Path -LiteralPath $path -PathType Leaf) { return [IO.Path]::GetFullPath($path) } }
    throw 'Skype.exe not found. Supply -ClientPath for a portable installation.'
}

function Get-PeInfo([byte[]]$Bytes) {
    if ($Bytes.Length -lt 64 -or $Bytes[0] -ne 0x4d -or $Bytes[1] -ne 0x5a) { throw 'Not a PE executable.' }
    $pe = [BitConverter]::ToInt32($Bytes, 60)
    if ($pe -lt 64 -or $pe -gt $Bytes.Length - 24 -or [BitConverter]::ToUInt32($Bytes, $pe) -ne 0x4550) { throw 'Invalid PE header.' }
    $size = [BitConverter]::ToUInt16($Bytes, $pe + 20)
    if ($size -lt 96 -or $pe + 24 + $size -gt $Bytes.Length) { throw 'Invalid PE optional header.' }
    return [pscustomobject]@{ Machine = [BitConverter]::ToUInt16($Bytes, $pe + 4); PeOffset = $pe; ChecksumOffset = $pe + 88 }
}

function Find-ByteOffsets([byte[]]$Bytes, [byte[]]$Pattern) {
    if (-not ('SkyPatch.ByteSearch' -as [type])) {
        Add-Type @'
using System.Collections.Generic;
namespace SkyPatch { public static class ByteSearch {
 public static int[] Find(byte[] data, byte[] pattern) {
  var found = new List<int>();
  for (int i=0; i<=data.Length-pattern.Length; i++) {
   if (data[i]!=pattern[0]) continue;
   int j=1; while (j<pattern.Length && data[i+j]==pattern[j]) j++;
   if (j==pattern.Length) found.Add(i);
  }
  return found.ToArray();
 }
} }
'@
    }
    return [SkyPatch.ByteSearch]::Find($Bytes, $Pattern)
}

function Inspect-Client([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $pe = Get-PeInfo $bytes
    $hash = Get-BytesHash $bytes
    $patterns = [ordered]@{}
    foreach ($key in @(@{Name='login'; Hex=$OriginalLoginModulus}, @{Name='credentials'; Hex=$OriginalCredentialsModulus})) {
        $be = Convert-Hex $key.Hex
        $le = $be.Clone()
        [array]::Reverse($le)
        $patterns[$key.Name + '_big_endian'] = @(Find-ByteOffsets $bytes $be)
        $patterns[$key.Name + '_little_endian'] = @(Find-ByteOffsets $bytes $le)
    }
    foreach ($ip in @('193.88.6.13', '194.165.188.79', '195.46.253.219', '91.190.218.40', '91.190.216.17', '65.55.223.25', '64.4.23.141', '111.221.74.33')) {
        $patterns[$ip + '_ascii'] = @(Find-ByteOffsets $bytes ([Text.Encoding]::ASCII.GetBytes($ip)))
        $patterns[$ip + '_network'] = @(Find-ByteOffsets $bytes ([Net.IPAddress]::Parse($ip).GetAddressBytes()))
    }
    return [pscustomobject]@{
        Path=$Path; Version=[Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersion
        Sha256=$hash; Machine=$pe.Machine; Length=$bytes.Length
        KnownPacked=($hash -eq $KnownPackedHash); VerifiedProfileAvailable=(@($VerifiedProfiles | Where-Object { $_.OriginalSha256 -eq $hash }).Count -eq 1)
        PatternOffsets=$patterns
    }
}

function Get-Replacement($Patch) {
    switch ($Patch.Role) {
        'LoginKey' { $bytes = Convert-Hex $LoginModulusHex; $length = 192 }
        'CredentialsKey' { $bytes = Convert-Hex $CredentialsModulusHex; $length = 256 }
        'ServerAddress' {
            $ip = [Net.IPAddress]::Parse($ServerIp)
            if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.Equals([Net.IPAddress]::Any) -or $ip.GetAddressBytes()[0] -ge 224) { throw 'Unicast IPv4 server address required.' }
            if ($Patch.Encoding -eq 'AsciiZ') {
                $length = (Convert-Hex $Patch.OriginalHex).Length
                $text = [Text.Encoding]::ASCII.GetBytes($ip.ToString())
                if ($text.Length -ge $length) { throw 'Server IP does not fit the verified ASCIIZ slot.' }
                $bytes = New-Object byte[] $length
                [Array]::Copy($text, $bytes, $text.Length)
                return ,$bytes
            }
            $bytes = $ip.GetAddressBytes(); $length = 4
        }
        default { throw 'Unknown patch role.' }
    }
    if ($bytes.Length -ne $length) { throw 'Incorrect public modulus size. Run skyserver-keygen.' }
    switch ($Patch.Encoding) {
        'BigEndian' { }
        'LittleEndian' { [array]::Reverse($bytes) }
        default { throw 'Unverified byte encoding.' }
    }
    return ,$bytes
}

function New-PatchedBytes([byte[]]$Original, $Profile) {
    if ((Get-BytesHash $Original) -ne $Profile.OriginalSha256) { throw 'Original file fingerprint does not match patch profile.' }
    $pe = Get-PeInfo $Original
    if ($pe.Machine -ne $Profile.Machine) { throw 'PE architecture mismatch.' }
    $result = $Original.Clone()
    $occupied = New-Object 'Collections.Generic.HashSet[int]'
    $roles = New-Object 'Collections.Generic.HashSet[string]'
    foreach ($patch in $Profile.Patches) {
        $offset = [long]$patch.Offset
        $before = Convert-Hex $patch.OriginalHex
        $after = Get-Replacement $patch
        if ($offset -lt 0 -or $offset -gt $Original.Length - $before.Length -or $before.Length -ne $after.Length) { throw 'Patch is outside the file or changes its length.' }
        for ($i = 0; $i -lt $before.Length; $i++) {
            $at = [int]($offset + $i)
            if (-not $occupied.Add($at)) { throw 'Overlapping patch ranges.' }
            if ($Original[$at] -ne $before[$i]) { throw "Original byte mismatch at $at." }
            $result[$at] = $after[$i]
        }
        $roles.Add([string]$patch.Role) | Out-Null
    }
    foreach ($role in @('LoginKey', 'CredentialsKey', 'ServerAddress')) {
        if (-not $roles.Contains($role)) { throw "Incomplete profile: missing $role." }
    }
    if ((Get-BytesHash $result) -eq (Get-BytesHash $Original)) { throw 'Profile makes no changes.' }
    # Authenticode cannot stay valid after a byte patch. Preserve the original in .bak.
    # PE checksum handling, unpacking and integrity checks must be part of version RE.
    return ,$result
}

function Assert-ClientStopped([string]$Path) {
    foreach ($process in @(Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($Path)) -ErrorAction SilentlyContinue)) {
        if ($process.Path -and [IO.Path]::GetFullPath($process.Path) -eq $Path) {
            # Only terminate the exact binary being patched, not other installations.
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            if (-not $process.WaitForExit(10000)) { throw 'Skype did not exit.' }
        }
    }
}

function Write-Atomic([string]$Path, [byte[]]$Bytes) {
    $temp = $Path + '.new-' + [Guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllBytes($temp, $Bytes)
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temp, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temp, $Path) }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}

function Invoke-SkyPatch([string]$Path, [string]$Mode, $Profile) {
    $Path = [IO.Path]::GetFullPath($Path)
    if ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing a reparse-point executable.' }
    $backup = $Path + '.bak'
    $journal = $Path + '.skypatch.json'
    foreach ($file in @($backup, $journal, ($Path + '.skypatch.lock'))) {
        if ((Test-Path -LiteralPath $file) -and ((Get-Item -LiteralPath $file).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Refusing a reparse-point backup or transaction file.'
        }
    }
    $current = [IO.File]::ReadAllBytes($Path)
    $currentHash = Get-BytesHash $current
    $state = $null
    if (Test-Path -LiteralPath $journal) {
        $state = [IO.File]::ReadAllText($journal) | ConvertFrom-Json
        if ($state.Schema -ne 1 -or $state.Path -ne $Path) { throw 'Invalid patch journal.' }
        if (-not (Test-Path -LiteralPath $backup -PathType Leaf) -or (Get-FileHash -LiteralPath $backup).Hash -ne $state.OriginalSha256) { throw 'Original backup missing or modified.' }
        $acceptedHashes = @($state.OriginalSha256, $state.PatchedSha256)
        if ($state.PSObject.Properties.Name -contains 'PreviousSha256') { $acceptedHashes += $state.PreviousSha256 }
        if ($currentHash -notin $acceptedHashes) { throw 'Client changed outside this patcher; refusing to overwrite it.' }
    }
    if ($Mode -eq 'Restore') {
        if (-not $state) { throw 'No verified backup journal. Nothing restored.' }
        if ($currentHash -eq $state.OriginalSha256) { Write-Host 'Already restored; original backup retained.'; return }
        $replacement = [IO.File]::ReadAllBytes($backup)
    } else {
        if (-not $Profile) {
            if ($currentHash -eq $KnownPackedHash) { throw 'UNSUPPORTED_PACKED_SKYPE_4_2_0_187: keys and endpoints are not plaintext on disk. No verified unpack/integrity patch profile exists. Client unchanged.' }
            throw 'UNSUPPORTED_BINARY: no verified patch profile for this exact SHA256. Client unchanged.'
        }
        $original = $current
        if ($state) { $original = [IO.File]::ReadAllBytes($backup) }
        $replacement = New-PatchedBytes $original $Profile
        $patchedHash = Get-BytesHash $replacement
        if ($currentHash -eq $patchedHash) { Write-Host 'Already patched with these public keys and server address.'; return }
        if (-not $state -and (Test-Path -LiteralPath $backup) -and
            (Get-FileHash -LiteralPath $backup).Hash -ne $Profile.OriginalSha256) {
            throw 'Unmanaged .bak exists; refusing to overwrite the original backup.'
        }
    }
    # Validate everything before stopping Skype or modifying anything. No UAC prompts.
    $lockPath = $Path + '.skypatch.lock'
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        Assert-ClientStopped $Path
        if ((Get-FileHash -LiteralPath $Path).Hash -ne $currentHash) { throw 'Client changed during patch preflight.' }
        if ($Mode -eq 'Patch') {
            if (-not (Test-Path -LiteralPath $backup)) { [IO.File]::Copy($Path, $backup, $false) }
            if ((Get-FileHash -LiteralPath $backup).Hash -ne (Get-BytesHash $original)) { throw 'Backup verification failed.' }
            $state = [ordered]@{Schema=1; Path=$Path; OriginalSha256=(Get-BytesHash $original); PatchedSha256=$patchedHash; PreviousSha256=$currentHash; ServerIp=$ServerIp; Utc=[DateTime]::UtcNow.ToString('o')}
            Write-Atomic $journal ([Text.Encoding]::UTF8.GetBytes(($state | ConvertTo-Json)))
        }
        Write-Atomic $Path $replacement
        if ((Get-FileHash -LiteralPath $Path).Hash -ne (Get-BytesHash $replacement)) { throw 'Post-write verification failed. Original remains in .bak.' }
        Write-Host "$Mode complete: $Path"
        Write-Host "Original backup retained: $backup"
    # Keep the lock file; the exclusive HANDLE, not file existence, owns the lock.
    # A crash releases the handle automatically and a later invocation can recover.
    } finally { $lock.Dispose() }
}

if ($MyInvocation.InvocationName -eq '.') { return }
try {
    if (-not $ClientPath) { $ClientPath = Find-Client }
    $ClientPath = [IO.Path]::GetFullPath($ClientPath)
    if ($Action -eq 'Inspect') { Inspect-Client $ClientPath | ConvertTo-Json -Depth 6; exit 0 }
    $profile = $null
    if ($Action -eq 'Patch') {
        if ($ProfilePath) {
            $profile = [IO.File]::ReadAllText([IO.Path]::GetFullPath($ProfilePath)) | ConvertFrom-Json
            Write-Warning 'Using an explicit developer patch profile; native login compatibility is not implied.'
        } else {
            $originalHash = (Get-FileHash -LiteralPath $ClientPath).Hash
            if (Test-Path -LiteralPath ($ClientPath + '.skypatch.json')) {
                $originalHash = ([IO.File]::ReadAllText($ClientPath + '.skypatch.json') | ConvertFrom-Json).OriginalSha256
            }
            $profile = @($VerifiedProfiles | Where-Object { $_.OriginalSha256 -eq $originalHash }) | Select-Object -First 1
        }
    }
    Invoke-SkyPatch $ClientPath $Action $profile
} catch {
    [Console]::Error.WriteLine('skypatch: ' + $_.Exception.Message)
    exit 1
}
