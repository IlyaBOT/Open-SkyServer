[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[2-6]\.\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][uri]$Url,
    [Parameter(Mandatory)][uri]$SourcePage,
    [Parameter(Mandatory)][string]$ArchiveRoot,
    [ValidateSet('GET', 'POST')][string]$Method = 'GET',
    [ValidateSet('exe', 'msi')][string]$Format = 'exe',
    [string]$ResumeCandidate,
    [long]$MinimumBytes = 2000000
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $ArchiveRoot).ProviderPath.TrimEnd('\')
$directory = Join-Path (Join-Path $root $Version) 'Windows'
$fileName = if ($Format -eq 'msi') { "SkypeSetup_$Version.msi" } else { "SkypeSetupFull_$Version.exe" }
$target = Join-Path $directory $fileName
$log = Join-Path $root 'Windows_DOWNLOAD_LOG.jsonl'
if (Test-Path -LiteralPath $target) {
    throw "Existing file preserved; refusing overwrite: $target"
}
if ($Url.Scheme -ne 'https') { throw 'Only HTTPS downloads are allowed.' }
foreach ($path in @($root, (Join-Path $root $Version), $directory)) {
    if ((Test-Path -LiteralPath $path) -and
        ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Reparse-point destination refused: $path"
    }
}
[IO.Directory]::CreateDirectory($directory) | Out-Null
$temporary = "$target.$([guid]::NewGuid().ToString('N')).part"
if ($ResumeCandidate) {
    $temporary = (Resolve-Path -LiteralPath $ResumeCandidate).ProviderPath
    if ([IO.Path]::GetDirectoryName($temporary) -ne $directory -or !$temporary.EndsWith('.part')) {
        throw 'Resume candidate must be a .part file in the exact version/Windows directory.'
    }
    if ((Get-Item -LiteralPath $temporary).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Reparse-point candidate refused.'
    }
}
$record = [ordered]@{
    utc = [DateTime]::UtcNow.ToString('o')
    platform = 'Windows desktop'
    expected_version = $Version
    source_page = $SourcePage.AbsoluteUri
    request_url = $Url.AbsoluteUri
    method = $Method
    destination = $target
    status = 'started'
    installer_executed = $false
}
$client = [Net.Http.HttpClient]::new()
$client.Timeout = [TimeSpan]::FromMinutes(5)
$request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $Url)
$response = $null
try {
    if ($ResumeCandidate) {
        $record.resumed_candidate = $temporary
    } else {
    $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    $record.http_status = [int]$response.StatusCode
    $record.resolved_url = $response.RequestMessage.RequestUri.AbsoluteUri
    $record.content_type = [string]$response.Content.Headers.ContentType
    $record.content_length = $response.Content.Headers.ContentLength
    $response.EnsureSuccessStatusCode() | Out-Null
    if ($response.Content.Headers.ContentLength -gt 268435456) { throw 'Unexpected file larger than 256 MiB.' }
    $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    $outputStream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try {
        $buffer = [byte[]]::new(1048576)
        $total = 0L
        while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $count
            if ($total -gt 268435456) { throw 'Download exceeded 256 MiB.' }
            $outputStream.Write($buffer, 0, $count)
        }
    } finally {
        $outputStream.Dispose()
        $inputStream.Dispose()
    }
    }
    $record.size_bytes = (Get-Item -LiteralPath $temporary).Length
    $record.sha256 = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
    $record.sha1 = (Get-FileHash -LiteralPath $temporary -Algorithm SHA1).Hash.ToLowerInvariant()
    if ($record.size_bytes -lt $MinimumBytes) { throw 'Too small for the requested full offline installer.' }
    if ($null -ne $record.content_length -and $record.size_bytes -ne $record.content_length) {
        throw 'Content-Length does not match the completed download.'
    }
    if ($Format -eq 'msi') {
        $stream = [IO.File]::OpenRead($temporary)
        try {
            $header = [byte[]]::new(8)
            if ($stream.Read($header, 0, 8) -ne 8 -or [Convert]::ToHexString($header) -ne 'D0CF11E0A1B11AE1') {
                throw 'Missing MSI compound-file signature.'
            }
        } finally { $stream.Dispose() }
        $record.magic = 'D0CF11E0A1B11AE1 / MSI compound file'
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase($temporary, 0)
        try {
            $summary = $database.SummaryInformation(0)
            $record.msi_template = $summary.Property(7)
            $record.installer_architecture = if ($record.msi_template -match '^Intel;') { 'x86' } else { 'unknown' }
            $view = $database.OpenView('SELECT `Property`, `Value` FROM `Property`')
            $view.Execute()
            $properties = [ordered]@{}
            while ($row = $view.Fetch()) { $properties[$row.StringData(1)] = $row.StringData(2) }
            $view.Close()
            $record.msi_properties = $properties
            $record.company_name = $properties.Manufacturer
            $record.product_version = $properties.ProductVersion
            $view = $database.OpenView('SELECT `FileName`, `FileSize`, `Version` FROM `File`')
            $view.Execute()
            $payloadFiles = @()
            while ($row = $view.Fetch()) {
                $payloadFiles += [ordered]@{ name = $row.StringData(1); size_bytes = $row.IntegerData(2); version = $row.StringData(3) }
            }
            $view.Close()
            $record.msi_files = $payloadFiles
            $skypeFiles = @($payloadFiles | Where-Object { $_.name -match '(^|\|)Skype\.exe$' })
            if ($skypeFiles.Count -ne 1 -or $skypeFiles[0].version -ne $Version) {
                throw 'MSI Skype.exe File table version does not match the requested version.'
            }
            $record.file_version_fixed = $skypeFiles[0].version
            $view = $database.OpenView('SELECT `Cabinet` FROM `Media`')
            $view.Execute()
            $cabinets = @()
            while ($row = $view.Fetch()) { $cabinets += $row.StringData(1) }
            $view.Close()
            $view = $database.OpenView('SELECT `Name` FROM `_Streams`')
            $view.Execute()
            $streams = @()
            while ($row = $view.Fetch()) { $streams += $row.StringData(1) }
            $view.Close()
            $record.msi_cabinets = $cabinets
            $record.msi_stream_names = $streams
            if (!$cabinets.Count) { throw 'MSI has no Media cabinet entries.' }
            foreach ($cabinet in $cabinets) {
                if (!$cabinet.StartsWith('#') -or $streams -notcontains $cabinet.Substring(1)) {
                    throw "MSI requires missing or external cabinet: $cabinet"
                }
            }
            $record.offline_payload_status = 'embedded_cabinets_present'
        } finally {
            foreach ($object in @($row, $view, $summary, $database, $installer)) {
                if ($null -ne $object -and [Runtime.InteropServices.Marshal]::IsComObject($object)) {
                    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($object) | Out-Null
                }
            }
            $row = $view = $summary = $database = $installer = $null
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
        }
    } else {
    $stream = [IO.File]::OpenRead($temporary)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Missing DOS MZ signature.' }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt $stream.Length - 26) { throw 'Invalid PE offset.' }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw 'Missing PE signature.' }
        $machine = $reader.ReadUInt16()
        $stream.Position = $peOffset + 24
        $optionalMagic = $reader.ReadUInt16()
        $record.magic = 'MZ / PE'
        $record.pe_machine = ('0x{0:x4}' -f $machine)
        $record.pe_optional_magic = ('0x{0:x4}' -f $optionalMagic)
        $record.installer_architecture = switch ($machine) {
            0x014c { 'x86' }
            0x8664 { 'x86_64' }
            default { 'unknown' }
        }
        if ($machine -ne 0x014c -or $optionalMagic -ne 0x10b) {
            throw 'Unexpected architecture; requires separate review.'
        }
    } finally {
        $reader.Dispose()
    }
    $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($temporary)
    $record.file_version = $info.FileVersion
    $record.product_version = $info.ProductVersion
    $record.company_name = $info.CompanyName
    $record.file_description = $info.FileDescription
    $record.original_filename = $info.OriginalFilename
    $record.prerelease_flag = $info.IsPreRelease
    $actual = '{0}.{1}.{2}.{3}' -f $info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart
    $record.file_version_fixed = $actual
    if ($actual -ne $Version) { throw "Wrong embedded version: $actual (expected $Version)." }
    if ($info.IsPreRelease) { throw 'Prerelease-flagged installer refused.' }
    }
    # This only reads the Authenticode signature; it never starts the executable.
    $signature = Get-AuthenticodeSignature -LiteralPath $temporary
    $record.authenticode_status = [string]$signature.Status
    $record.authenticode_message = $signature.StatusMessage
    $record.signer_subject = $signature.SignerCertificate.Subject
    $record.signer_thumbprint = $signature.SignerCertificate.Thumbprint
    $record.timestamp_subject = $signature.TimeStamperCertificate.Subject
    [IO.File]::Move($temporary, $target, $false)
    $record.status = 'downloaded_version_verified'
    $record.completed_utc = [DateTime]::UtcNow.ToString('o')
} catch {
    $record.status = 'failed'
    $record.error = $_.Exception.Message
    if (Test-Path -LiteralPath $temporary) { $record.retained_partial_path = $temporary }
} finally {
    if ($response) { $response.Dispose() }
    $request.Dispose()
    $client.Dispose()
    $json = $record | ConvertTo-Json -Depth 8 -Compress
    $writer = [IO.StreamWriter]::new($log, $true, [Text.UTF8Encoding]::new($false))
    try { $writer.WriteLine($json) } finally { $writer.Dispose() }
}
$record | ConvertTo-Json -Depth 8
if ($record.status -eq 'failed') { exit 1 }
