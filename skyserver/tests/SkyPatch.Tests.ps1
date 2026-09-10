$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'skypatch.ps1')

Describe 'Transactional patching on a synthetic PE fixture (not Skype compatibility)' {
    BeforeEach {
        $ServerIp = '192.168.1.101'
        $LoginModulusHex = 'A1' * 192
        $CredentialsModulusHex = 'B1' * 256
        $path = Join-Path $TestDrive ('fixture-' + [Guid]::NewGuid().ToString('N') + '.exe')
        $bytes = New-Object byte[] 2048
        $bytes[0] = 0x4d; $bytes[1] = 0x5a; $bytes[60] = 128
        $bytes[128] = 0x50; $bytes[129] = 0x45
        $bytes[132] = 0x4c; $bytes[133] = 1; $bytes[148] = 224
        [Array]::Copy((Convert-Hex $OriginalLoginModulus), 0, $bytes, 512, 192)
        [Array]::Copy((Convert-Hex $OriginalCredentialsModulus), 0, $bytes, 704, 256)
        [Array]::Copy([Text.Encoding]::ASCII.GetBytes('193.88.6.13'), 0, $bytes, 1024, 11)
        [IO.File]::WriteAllBytes($path, $bytes)
        $originalHash = Get-BytesHash $bytes
        $profile = [pscustomobject]@{
            OriginalSha256=$originalHash; Machine=332
            Patches=@(
                [pscustomobject]@{Role='LoginKey'; Encoding='LittleEndian'; Offset=512; OriginalHex=$OriginalLoginModulus},
                [pscustomobject]@{Role='CredentialsKey'; Encoding='BigEndian'; Offset=704; OriginalHex=$OriginalCredentialsModulus},
                [pscustomobject]@{Role='ServerAddress'; Encoding='AsciiZ'; Offset=1024; OriginalHex=[BitConverter]::ToString($bytes[1024..1039]).Replace('-', '')}
            )
        }
    }

    It 'backs up, patches both keys and address, repeats, restores, and repeats restore' {
        Invoke-SkyPatch $path Patch $profile
        (Get-FileHash ($path + '.bak')).Hash | Should Be $originalHash
        $patched = [IO.File]::ReadAllBytes($path)
        [Text.Encoding]::ASCII.GetString($patched,1024,13) | Should Be $ServerIp
        [BitConverter]::ToString($patched[512..703]).Replace('-', '') | Should Be $LoginModulusHex
        [BitConverter]::ToString($patched[704..959]).Replace('-', '') | Should Be $CredentialsModulusHex
        $patchedHash = Get-BytesHash $patched
        Invoke-SkyPatch $path Patch $profile
        (Get-FileHash $path).Hash | Should Be $patchedHash
        Invoke-SkyPatch $path Restore $null
        (Get-FileHash $path).Hash | Should Be $originalHash
        Invoke-SkyPatch $path Restore $null
        Invoke-SkyPatch $path Patch $profile
        (Get-FileHash ($path + '.bak')).Hash | Should Be $originalHash
    }

    It 'refuses unknown builds without creating a backup or journal' {
        { Invoke-SkyPatch $path Patch $null } | Should Throw 'UNSUPPORTED_BINARY'
        (Test-Path ($path + '.bak')) | Should Be $false
        (Get-FileHash $path).Hash | Should Be $originalHash
    }

    It 'rejects a wrong original fingerprint before mutation' {
        $profile.OriginalSha256 = '0' * 64
        { Invoke-SkyPatch $path Patch $profile } | Should Throw 'fingerprint'
        (Test-Path ($path + '.bak')) | Should Be $false
    }

    It 'rejects mismatched bytes and overlapping hunks' {
        $profile.Patches[0].OriginalHex = '01' * 192
        { Invoke-SkyPatch $path Patch $profile } | Should Throw 'mismatch'
        $profile.Patches[0].OriginalHex = $OriginalLoginModulus
        $profile.Patches += $profile.Patches[0]
        { Invoke-SkyPatch $path Patch $profile } | Should Throw 'Overlapping'
    }

    It 'rejects incomplete roles and out-of-bounds offsets' {
        $profile.Patches = $profile.Patches[0..1]
        { Invoke-SkyPatch $path Patch $profile } | Should Throw 'missing ServerAddress'
        $profile.Patches[0].Offset = -1
        { Invoke-SkyPatch $path Patch $profile } | Should Throw 'outside'
    }

    It 'preserves unmanaged backups' {
        [IO.File]::WriteAllText($path + '.bak', 'unrelated backup')
        { Invoke-SkyPatch $path Patch $profile } | Should Throw 'Unmanaged'
        [IO.File]::ReadAllText($path + '.bak') | Should Be 'unrelated backup'
    }

    It 'refuses restore after a backup is damaged' {
        Invoke-SkyPatch $path Patch $profile
        [IO.File]::WriteAllText($path + '.bak', 'damaged')
        { Invoke-SkyPatch $path Restore $null } | Should Throw 'backup missing or modified'
    }

    It 'preserves unrelated client changes during restore' {
        Invoke-SkyPatch $path Patch $profile
        $changed = [IO.File]::ReadAllBytes($path)
        $changed[1500] = 3
        [IO.File]::WriteAllBytes($path, $changed)
        { Invoke-SkyPatch $path Restore $null } | Should Throw 'changed outside'
        (Get-FileHash $path).Hash | Should Be (Get-BytesHash $changed)
    }

    It 'can rotate public configuration without replacing the original backup' {
        Invoke-SkyPatch $path Patch $profile
        $ServerIp = '127.0.0.1'
        Invoke-SkyPatch $path Patch $profile
        $patched = [IO.File]::ReadAllBytes($path)
        [Text.Encoding]::ASCII.GetString($patched,1024,9) | Should Be $ServerIp
        (Get-FileHash ($path + '.bak')).Hash | Should Be $originalHash
        Invoke-SkyPatch $path Restore $null
        (Get-FileHash $path).Hash | Should Be $originalHash
    }

    It 'checks key size and address slot capacity' {
        $LoginModulusHex = 'A1' * 191
        { Invoke-SkyPatch $path Patch $profile } | Should Throw 'modulus size'
        $LoginModulusHex = 'A1' * 192
        $profile.Patches[2].OriginalHex = '31'
        { Invoke-SkyPatch $path Patch $profile } | Should Throw 'does not fit'
    }

    It 'fails while another invocation holds the transaction lock' {
        $lock = [IO.File]::Open($path + '.skypatch.lock', 'CreateNew', 'ReadWrite', 'None')
        try {
            { Invoke-SkyPatch $path Patch $profile } | Should Throw
            (Get-FileHash $path).Hash | Should Be $originalHash
        } finally { $lock.Dispose() }
    }

    It 'resumes after creating the original backup but before writing the journal' {
        [IO.File]::Copy($path, $path + '.bak')
        [IO.File]::WriteAllText($path + '.skypatch.lock', '')
        Invoke-SkyPatch $path Patch $profile
        Invoke-SkyPatch $path Restore $null
        (Get-FileHash $path).Hash | Should Be $originalHash
    }

    It 'restores after a configuration update journal was written but the file was not replaced' {
        Invoke-SkyPatch $path Patch $profile
        $oldPatchedHash = (Get-FileHash $path).Hash
        $ServerIp = '127.0.0.1'
        $nextHash = Get-BytesHash (New-PatchedBytes $bytes $profile)
        $state = [ordered]@{Schema=1;Path=$path;OriginalSha256=$originalHash;PatchedSha256=$nextHash;PreviousSha256=$oldPatchedHash}
        [IO.File]::WriteAllText($path + '.skypatch.json', ($state | ConvertTo-Json))
        Invoke-SkyPatch $path Restore $null
        (Get-FileHash $path).Hash | Should Be $originalHash
    }
}

Describe 'Developer authority generation' {
    It 'generates and reuses a separate protected client-integrity authority without exporting its private key' -Skip:(-not (Test-Path 'C:\Program Files\Git\usr\bin\openssl.exe')) {
        $keys = Join-Path $TestDrive 'integrity-authority'
        $publicScript = Join-Path $TestDrive 'integrity-dist\skypatch.ps1'
        & (Join-Path $root 'skyserver-keygen.ps1') -OutputDirectory $keys -PatcherOutput $publicScript -ClientIntegrity
        $directory = Join-Path $keys 'client-integrity'
        $private = Join-Path $directory 'integrity.private.pem'
        $hash = (Get-FileHash $private).Hash
        $loginHash = (Get-FileHash (Join-Path $keys 'login.private.xml')).Hash
        (Get-Acl $directory).AreAccessRulesProtected | Should Be $true
        @((Get-Acl $directory).Access).Count | Should Be 2
        $hexPath = Join-Path $directory 'integrity.modulus.hex'
        ([IO.File]::ReadAllText($hexPath) -match '\A[0-9A-F]{192}\z') | Should Be $true
        ([IO.File]::ReadAllText($publicScript) -match 'BEGIN.*PRIVATE KEY') | Should Be $false
        & (Join-Path $root 'skyserver-keygen.ps1') -OutputDirectory $keys -PatcherOutput $publicScript -ClientIntegrity
        (Get-FileHash $private).Hash | Should Be $hash
        (Get-FileHash (Join-Path $keys 'login.private.xml')).Hash | Should Be $loginHash
        [IO.File]::WriteAllText($hexPath, ('A1' * 96))
        { & (Join-Path $root 'skyserver-keygen.ps1') -OutputDirectory $keys -PatcherOutput $publicScript -ClientIntegrity } | Should Throw 'modulus mismatch'
        (Get-FileHash $private).Hash | Should Be $hash
    }

    It 'generates matching keys, restricts private ACLs, exports only public data, and does not rotate on rerun' {
        $keys = Join-Path $TestDrive 'authority'
        $publicScript = Join-Path $TestDrive 'dist\skypatch.ps1'
        & (Join-Path $root 'skyserver-keygen.ps1') -OutputDirectory $keys -PatcherOutput $publicScript
        $originalPrivateHash = (Get-FileHash (Join-Path $keys 'login.private.xml')).Hash
        (Get-Acl $keys).AreAccessRulesProtected | Should Be $true
        @((Get-Acl $keys).Access).Count | Should Be 2
        $scriptText = [IO.File]::ReadAllText($publicScript)
        $scriptText.Contains('@@') | Should Be $false
        ($scriptText -match '<(D|P|Q|DP|DQ|InverseQ)>') | Should Be $false
        foreach ($name in @('login','credentials')) {
            [xml]$priv = [IO.File]::ReadAllText((Join-Path $keys ($name + '.private.xml')))
            $scriptText.Contains($priv.RSAKeyValue.D) | Should Be $false
        }
        & (Join-Path $root 'skyserver-keygen.ps1') -OutputDirectory $keys -PatcherOutput $publicScript
        (Get-FileHash (Join-Path $keys 'login.private.xml')).Hash | Should Be $originalPrivateHash
    }

    It 'refuses to overwrite incomplete authority directories or leak the patcher alongside private keys' {
        $keys = Join-Path $TestDrive 'incomplete'
        [IO.Directory]::CreateDirectory($keys) | Out-Null
        { & (Join-Path $root 'skyserver-keygen.ps1') -OutputDirectory $keys -PatcherOutput (Join-Path $TestDrive 'public.ps1') } | Should Throw 'incomplete'
        { & (Join-Path $root 'skyserver-keygen.ps1') -OutputDirectory $keys -PatcherOutput (Join-Path $keys 'public.ps1') } | Should Throw 'outside'
    }
}
