[CmdletBinding()]
param(
    [string]$Directory,
    [switch]$ConfigureOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
if (-not $Directory) { $Directory = [IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path) }

function Assert-SkypeLocalPath([string]$Path) {
    $at = [IO.Path]::GetFullPath($Path)
    while ($at) {
        if (Test-Path -LiteralPath $at) {
            if ((Get-Item -LiteralPath $at -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Linked paths are not supported: $at"
            }
        }
        $at = [IO.Path]::GetDirectoryName($at)
    }
}

function Set-SkypeXml {
    [CmdletBinding()]
    param([string]$Path, [hashtable]$Values, [switch]$Shared, [switch]$ResetBootstrap)
    Assert-SkypeLocalPath $Path
    $existed = Test-Path -LiteralPath $Path -PathType Leaf
    $mode = if ($Shared -and -not $existed) { [IO.FileMode]::CreateNew } else { [IO.FileMode]::Open }
    # Keep one exclusive handle for the entire read/modify/write transaction.
    # A replace-after-read scheme can discard changes from a concurrent writer.
    $stream = [IO.File]::Open($Path, $mode, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        if ($stream.Length -gt 1048576) { throw 'Profile XML exceeds the 1 MiB limit.' }
        $raw = [byte[]]::new([int]$stream.Length)
        $read = 0
        while ($read -lt $raw.Length) {
            $count = $stream.Read($raw, $read, $raw.Length - $read)
            if ($count -eq 0) { throw 'Short profile XML read.' }
            $read += $count
        }
        $document = [Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.PreserveWhitespace = $true
        if ($existed) {
            $settings = [Xml.XmlReaderSettings]::new()
            $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
            $settings.XmlResolver = $null
            $settings.MaxCharactersInDocument = 1048576
            $memory = [IO.MemoryStream]::new($raw, $false)
            $reader = [Xml.XmlReader]::Create($memory, $settings)
            try { $document.Load($reader) } finally { $reader.Dispose(); $memory.Dispose() }
        } else { $document.LoadXml('<config version="1.0" />') }
        if (-not $document.DocumentElement -or $document.DocumentElement.Name -cne 'config' -or
            $document.DocumentElement.NamespaceURI) { throw 'Expected Skype config XML root.' }
        $changed = -not $existed
        if ($Shared) {
            $obsolete = @('/config/Lib/ContactSearch/ForceServer', '/config/Lib/ContactSearch/UseServer')
            if ($ResetBootstrap) {
                $obsolete += @('/config/Lib/Connection/HostCache', '/config/Lib/Connection/LastProbingFailed')
            }
            foreach ($xpath in $obsolete) {
                foreach ($node in @($document.SelectNodes($xpath))) {
                    [void]$node.ParentNode.RemoveChild($node)
                    $changed = $true
                }
            }
        }
        foreach ($entry in $Values.GetEnumerator()) {
            $node = $document.DocumentElement
            foreach ($name in $entry.Key.Split('/')) {
                $children = $node.SelectNodes($name)
                if ($children.Count -gt 1) { throw "Ambiguous duplicate XML setting: $($entry.Key)" }
                if ($children.Count -eq 0) {
                    $child = $document.CreateElement($name)
                    [void]$node.AppendChild($child)
                    $changed = $true
                } else { $child = $children[0] }
                $node = $child
            }
            if ($node.InnerText -cne $entry.Value) { $node.InnerText = $entry.Value; $changed = $true }
        }
        if (-not $changed) { return $false }
        $serialized = [IO.MemoryStream]::new()
        try {
            $writerSettings = [Xml.XmlWriterSettings]::new()
            $writerSettings.Encoding = [Text.UTF8Encoding]::new($false)
            $writerSettings.Indent = $true
            $writer = [Xml.XmlWriter]::Create($serialized, $writerSettings)
            try { $document.Save($writer) } finally { $writer.Dispose() }
            $updated = $serialized.ToArray()
        } finally { $serialized.Dispose() }
        if ($updated.Length -gt 1048576) { throw 'Updated XML exceeds the 1 MiB limit.' }
        # One pre-change snapshot, only on an actual edit. Repeated polls are no-ops.
        $backupPath = $Path + '.opensky.bak'
        Assert-SkypeLocalPath $backupPath
        if ($existed -and -not (Test-Path -LiteralPath $backupPath)) {
            $backup = [IO.File]::Open($backupPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $backup.Write($raw, 0, $raw.Length); $backup.Flush($true) } finally { $backup.Dispose() }
        }
        try {
            $stream.Position = 0
            $stream.Write($updated, 0, $updated.Length)
            $stream.SetLength($updated.Length)
            $stream.Flush($true)
        } catch {
            $stream.Position = 0
            $stream.Write($raw, 0, $raw.Length)
            $stream.SetLength($raw.Length)
            $stream.Flush($true)
            throw
        }
        return $true
    } finally { $stream.Dispose() }
}

function Set-SkypeProfile {
    [CmdletBinding()]
    param([string]$ProfilePath, [string]$ServerIp, [int]$Port = 12350,
          [switch]$ResetBootstrap, [switch]$RetryBusy, [hashtable]$Failures = @{})
    Assert-SkypeLocalPath $ProfilePath
    if (-not (Test-Path -LiteralPath $ProfilePath -PathType Container)) {
        throw "Missing isolated profile: $ProfilePath. Run Patch-Skype.ps1 to create a portable client."
    }
    $sharedPath = Join-Path $ProfilePath 'shared.xml'
    $paths = @($sharedPath)
    foreach ($account in @(Get-ChildItem -LiteralPath $ProfilePath -Directory -Force)) {
        if ($account.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        $config = Join-Path $account.FullName 'config.xml'
        if (Test-Path -LiteralPath $config -PathType Leaf) { $paths += $config }
    }
    foreach ($path in $paths) {
        $shared = $path -eq $sharedPath
        $values = if ($shared) { @{
            'Lib/Connection/SearchServers' = ($ServerIp + ':' + $Port)
            'Lib/Connection/DisableSupernode' = '1'
            'Lib/Connection/ForceSupernode' = '0'
        } } else { @{
            'Lib/ContactSearch/ForceServer' = '1'
            'Lib/ContactSearch/UseServer' = '1'
        } }
        try {
            $null = Set-SkypeXml -Path $path -Values $values -Shared:$shared -ResetBootstrap:$ResetBootstrap
            [void]$Failures.Remove($path)
        } catch {
            if (-not $RetryBusy) { throw }
            # First-login files can be locked or temporarily incomplete. Retry on
            # the next tick, never truncate them or invent a replacement account.
            if (-not $Failures.ContainsKey($path)) {
                Write-Warning "Profile setting deferred; will retry: $path ($($_.Exception.Message))"
                $Failures[$path] = $true
            }
        }
    }
}

function Watch-SkypeProfile {
    [CmdletBinding()]
    param($Process, [string]$ProfilePath, [string]$ServerIp, [int]$Port = 12350)
    $failures = @{}
    while (-not $Process.HasExited) {
        Set-SkypeProfile -ProfilePath $ProfilePath -ServerIp $ServerIp -Port $Port -RetryBusy -Failures $failures
        Start-Sleep -Milliseconds 500
    }
    # Persist settings after the client's final save as well.
    Set-SkypeProfile -ProfilePath $ProfilePath -ServerIp $ServerIp -Port $Port -RetryBusy -Failures $failures
    if ($failures.Count) { Write-Warning 'Some profile XML settings remain unapplied. Close this client and run its launcher again.' }
}

function Start-PatchedSkype {
    param([string]$Directory, [switch]$ConfigureOnly)
    $Directory = [IO.Path]::GetFullPath($Directory)
    Assert-SkypeLocalPath $Directory
    $profile = Join-Path $Directory 'profile'
    if (-not (Test-Path -LiteralPath $profile -PathType Container)) {
        throw "Missing isolated profile: $profile. Run Patch-Skype.ps1 to create a portable client."
    }
    Assert-SkypeLocalPath $profile
    $manifestPath = Join-Path $Directory 'client.json'
    Assert-SkypeLocalPath $manifestPath
    if ((Get-Item -LiteralPath $manifestPath).Length -gt 16384) { throw 'Public metadata exceeds size limit.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $expectedFields = @('format','client_version','original_sha256','static_image_sha256','patched_sha256',
                        'patched_size','server_ip','server_port','recipe_sha256')
    if (@(Compare-Object @($manifest.PSObject.Properties.Name) $expectedFields).Count -or
        $manifest.format -isnot [int] -or $manifest.format -ne 1 -or $manifest.client_version -cne '4.2.0.187' -or
        $manifest.original_sha256 -cne 'a2e175ce7c9888c125e2b3d4c2343229832ba0d0cd8a8a1ce120ce92624e856c' -or
        $manifest.static_image_sha256 -cne '53ecb3032e76afe1db0a01eeb81e81f81c84e72d7cfae79dad3f197ca171d1ac' -or
        $manifest.patched_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $manifest.recipe_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $manifest.server_port -isnot [int] -or $manifest.server_port -ne 12350 -or
        ($manifest.patched_size -isnot [int] -and $manifest.patched_size -isnot [long]) -or
        $manifest.patched_size -lt 25460736 -or $manifest.patched_size -gt 26509312) {
        throw 'Invalid or unsupported public client metadata.'
    }
    if ($manifest.server_ip -isnot [string]) { throw 'Invalid server IPv4 in public metadata.' }
    $ip = [Net.IPAddress]::Parse($manifest.server_ip)
    if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $ip.ToString() -cne $manifest.server_ip -or $ip.Equals([Net.IPAddress]::Any) -or
        $ip.GetAddressBytes()[0] -ge 224) { throw 'Expected a unicast server IPv4.' }
    $client = Join-Path $Directory 'Skype.exe'
    foreach ($file in @($client, ($client + '.bak'))) {
        Assert-SkypeLocalPath $file
        if ((Get-Item -LiteralPath $file).Length -gt 67108864) { throw 'Client file exceeds size limit.' }
    }
    if ((Get-Item -LiteralPath $client).Length -ne $manifest.patched_size -or
        (Get-FileHash -LiteralPath $client -Algorithm SHA256).Hash -ne $manifest.patched_sha256 -or
        (Get-FileHash -LiteralPath ($client + '.bak') -Algorithm SHA256).Hash -ne $manifest.original_sha256) {
        throw 'Patched client or exact original backup SHA256 mismatch.'
    }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $identity = [BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($profile.ToLowerInvariant()))).Replace('-', '') }
    finally { $hasher.Dispose() }
    $mutex = [Threading.Mutex]::new($false, ('Local\OpenSkyProfile-' + $identity))
    $owned = $false
    try {
        try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned = $true }
        if (-not $owned) { throw 'This portable profile already has a launcher running.' }
        Set-SkypeProfile -ProfilePath $profile -ServerIp $manifest.server_ip -Port $manifest.server_port -ResetBootstrap
        if ($ConfigureOnly) { return }
        $process = Start-Process -FilePath $client -WorkingDirectory $Directory -PassThru -ArgumentList @(
            '/secondary', ('/datapath:"{0}"' -f $profile)
        )
        Watch-SkypeProfile -Process $process -ProfilePath $profile -ServerIp $manifest.server_ip -Port $manifest.server_port
    } finally {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

# Dot sourcing exposes the XML helpers for offline tests without starting Skype.
if ($MyInvocation.InvocationName -ne '.') {
    Start-PatchedSkype -Directory $Directory -ConfigureOnly:$ConfigureOnly
}
