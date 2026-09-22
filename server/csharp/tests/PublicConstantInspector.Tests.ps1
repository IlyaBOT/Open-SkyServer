. (Join-Path (Split-Path -Parent $PSScriptRoot) 'skypatch.ps1')
if (-not ('PublicConstantInspector' -as [type])) {
    Add-Type -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\PublicConstantInspector.cs') -ReferencedAssemblies System.Numerics
}

Describe 'Read-only public modulus scanner' {
    It 'finds plaintext and periodic-XOR moduli at their exact offsets' {
        $login = Convert-Hex $OriginalLoginModulus
        $credentials = Convert-Hex $OriginalCredentialsModulus
        $bytes = New-Object byte[] 4096
        [Array]::Copy($credentials, 0, $bytes, 2048, $credentials.Length)
        $mask = [byte[]]@(0x19, 0x82, 0xfe, 0x34)
        for ($i = 0; $i -lt $login.Length; $i++) { $bytes[512 + $i] = $login[$i] -bxor $mask[$i % 4] }
        $fixture = Join-Path $TestDrive 'public-constants.bin'
        [IO.File]::WriteAllBytes($fixture, $bytes)
        $result = [PublicConstantInspector]::Scan(0, $login, $credentials, $fixture)
        @($result | Where-Object { $_ -match '^file offset=0x00000200 login:.*xorPeriod=4 ' }).Count | Should BeGreaterThan 0
        @($result | Where-Object { $_ -match '^file offset=0x00000800 credentials:.*xorPeriod=0 ' }).Count | Should BeGreaterThan 0
        (Get-BytesHash ([IO.File]::ReadAllBytes($fixture))) | Should Be (Get-BytesHash $bytes)
    }

    It 'does not report a truncated modulus as a match' {
        $login = Convert-Hex $OriginalLoginModulus
        $credentials = Convert-Hex $OriginalCredentialsModulus
        $fixture = Join-Path $TestDrive 'truncated.bin'
        [IO.File]::WriteAllBytes($fixture, $login[0..150])
        $result = [PublicConstantInspector]::Scan(0, $login, $credentials, $fixture)
        @($result | Where-Object { $_ -match '^file offset=' }).Count | Should Be 0
    }
}
