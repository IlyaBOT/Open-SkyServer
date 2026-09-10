[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'private-keys'),
    [string]$PatcherOutput = (Join-Path $PSScriptRoot 'dist\skypatch.ps1'),
    [string]$ServerIp = '192.168.1.101',
    [switch]$ClientIntegrity,
    [string]$OpenSslPath = 'C:\Program Files\Git\usr\bin\openssl.exe'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Protect-KeyDirectory([string]$Path) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($identity)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($identity, (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'))) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

$ip = [Net.IPAddress]::Parse($ServerIp)
if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.Equals([Net.IPAddress]::Any) -or $ip.GetAddressBytes()[0] -ge 224) {
    throw 'ServerIp must be a unicast IPv4 address.'
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$PatcherOutput = [IO.Path]::GetFullPath($PatcherOutput)
if ($PatcherOutput.StartsWith($OutputDirectory.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The public patcher must be outside the private key directory.'
}
$templatePath = Join-Path $PSScriptRoot 'skypatch.ps1'
if ($PatcherOutput -eq $templatePath) { throw 'Do not overwrite the patcher template.' }
$template = [IO.File]::ReadAllText($templatePath)
foreach ($token in @('@@SERVER_IP@@', '@@LOGIN_MODULUS@@', '@@CREDENTIALS_MODULUS@@')) {
    if ([regex]::Matches($template, [regex]::Escape($token)).Count -ne 1) { throw "Invalid template token: $token" }
}

if (Test-Path -LiteralPath $OutputDirectory) {
    # Never silently rotate an authority or change ACLs on a pre-existing directory.
    foreach ($name in @('login', 'credentials')) {
        foreach ($kind in @('private', 'public')) {
            if (-not (Test-Path -LiteralPath (Join-Path $OutputDirectory "$name.$kind.xml") -PathType Leaf)) {
                throw 'Key directory is incomplete. Choose a new OutputDirectory; existing keys will not be overwritten.'
            }
        }
    }
    Write-Host 'Using existing key pairs; no key rotation.'
} else {
    $parent = Split-Path -Parent $OutputDirectory
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $stage = $OutputDirectory + '.new-' + [Guid]::NewGuid().ToString('N')
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    Protect-KeyDirectory $stage
    foreach ($role in @(@{Name='login'; Bits=1536}, @{Name='credentials'; Bits=2048})) {
        $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider ([int]$role.Bits)
        $rsa.PersistKeyInCsp = $false
        try {
            $public = $rsa.ExportParameters($false)
            if ([Convert]::ToBase64String($public.Exponent) -ne 'AQAB') { throw 'RSA exponent must be 65537.' }
            [IO.File]::WriteAllText((Join-Path $stage ($role.Name + '.private.xml')), $rsa.ToXmlString($true), [Text.Encoding]::ASCII)
            [IO.File]::WriteAllText((Join-Path $stage ($role.Name + '.public.xml')), $rsa.ToXmlString($false), [Text.Encoding]::ASCII)
        } finally { $rsa.Dispose() }
    }
    # A failed generation leaves only a protected staging directory for inspection.
    [IO.Directory]::Move($stage, $OutputDirectory)
    Write-Host "Generated private keys in $OutputDirectory"
}

$moduli = @{}
foreach ($role in @(@{Name='login'; Bits=1536}, @{Name='credentials'; Bits=2048})) {
    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
    $pub = New-Object Security.Cryptography.RSACryptoServiceProvider
    $rsa.PersistKeyInCsp = $false
    $pub.PersistKeyInCsp = $false
    try {
        $rsa.FromXmlString([IO.File]::ReadAllText((Join-Path $OutputDirectory ($role.Name + '.private.xml'))))
        $pub.FromXmlString([IO.File]::ReadAllText((Join-Path $OutputDirectory ($role.Name + '.public.xml'))))
        if ($rsa.PublicOnly -or $rsa.KeySize -ne $role.Bits -or $rsa.ToXmlString($false) -ne $pub.ToXmlString($false) -or
            [Convert]::ToBase64String($pub.ExportParameters($false).Exponent) -ne 'AQAB') { throw 'Invalid or mismatched RSA pair.' }
        $challenge = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($challenge) } finally { $rng.Dispose() }
        $roundtrip = $rsa.Decrypt($pub.Encrypt($challenge, $false), $false)
        if ([Convert]::ToBase64String($challenge) -ne [Convert]::ToBase64String($roundtrip)) { throw 'Key pair self-test failed.' }
        $moduli[$role.Name] = [BitConverter]::ToString($pub.ExportParameters($false).Modulus).Replace('-', '')
    } finally { $rsa.Dispose(); $pub.Dispose() }
}
$generated = $template.Replace('@@SERVER_IP@@', $ip.ToString()).Replace('@@LOGIN_MODULUS@@', $moduli.login).Replace('@@CREDENTIALS_MODULUS@@', $moduli.credentials)
if ($generated -match '<(D|P|Q|DP|DQ|InverseQ)>') { throw 'Unexpected private key material in public patcher.' }
[IO.Directory]::CreateDirectory((Split-Path -Parent $PatcherOutput)) | Out-Null
$temp = $PatcherOutput + '.new-' + [Guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText($temp, $generated, [Text.Encoding]::UTF8)
if (Test-Path -LiteralPath $PatcherOutput) { [IO.File]::Replace($temp, $PatcherOutput, [NullString]::Value) }
else { [IO.File]::Move($temp, $PatcherOutput) }
Write-Host "Public-only patcher: $PatcherOutput"
Write-Host "Server: --keys-dir `"$OutputDirectory`""
Write-Warning 'Legacy RSA-1536 is for compatibility testing only. Keep *.private.xml on the server; distribute only dist\skypatch.ps1. A supported binary patch profile is still required.'

if ($ClientIntegrity) {
    if (-not (Test-Path -LiteralPath $OpenSslPath -PathType Leaf)) { throw 'OpenSSL is required for the optional client-integrity key.' }
    $integrity = Join-Path $OutputDirectory 'client-integrity'
    if (-not (Test-Path -LiteralPath $integrity)) {
        $stage = $integrity + '.new-' + [Guid]::NewGuid().ToString('N')
        [IO.Directory]::CreateDirectory($stage) | Out-Null
        Protect-KeyDirectory $stage
        # This legacy key signs the local EXE checksum table, never accounts or
        # network credentials. Its 768-bit size and exponent 3 are client ABI.
        & $OpenSslPath genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:768 -pkeyopt rsa_keygen_pubexp:3 -out (Join-Path $stage 'integrity.private.pem') -outpubkey (Join-Path $stage 'integrity.public.pem')
        if ($LASTEXITCODE -ne 0) { throw 'Integrity key generation failed; protected staging files retained.' }
        [IO.Directory]::Move($stage, $integrity)
    }
    $privatePath = Join-Path $integrity 'integrity.private.pem'
    $publicPath = Join-Path $integrity 'integrity.public.pem'
    if (-not (Test-Path -LiteralPath $privatePath) -or -not (Test-Path -LiteralPath $publicPath)) {
        throw 'Incomplete integrity key pair; refusing replacement.'
    }
    $derived = (& $OpenSslPath pkey -in $privatePath -pubout) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Could not derive integrity public key.' }
    $existing = [IO.File]::ReadAllText($publicPath).Replace("`r", '').Trim()
    if ($derived.Trim() -ne $existing) { throw 'Integrity public/private key mismatch.' }
    $details = (& $OpenSslPath pkey -pubin -in $publicPath -text_pub -noout) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $details -notmatch 'Public-Key: \(768 bit\)' -or $details -notmatch 'Exponent: 3 \(0x3\)') {
        throw 'Integrity key must be RSA-768 with exponent 3.'
    }
    $modulusLine = (& $OpenSslPath rsa -pubin -in $publicPath -noout -modulus) -join ''
    if ($LASTEXITCODE -ne 0 -or $modulusLine -notmatch '\AModulus=([0-9A-F]{192})\z') { throw 'Invalid integrity modulus.' }
    $hex = $Matches[1]
    $hexPath = Join-Path $integrity 'integrity.modulus.hex'
    if (Test-Path -LiteralPath $hexPath) {
        if ([IO.File]::ReadAllText($hexPath).Trim() -ne $hex) { throw 'Stored integrity modulus mismatch.' }
    } else { [IO.File]::WriteAllText($hexPath, $hex, [Text.Encoding]::ASCII) }
    Write-Host "Client integrity key ready: $integrity (development only, never distribute private PEM)."
}
