[CmdletBinding()]
param([Parameter(Mandatory)][string]$ArchiveRoot)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $ArchiveRoot).ProviderPath.TrimEnd('\')
$logPath = Join-Path $root 'Windows_DOWNLOAD_LOG.jsonl'
$attempts = @(Get-Content -LiteralPath $logPath | ForEach-Object { ConvertFrom-Json -InputObject $_ -AsHashtable })
$selections = @(
    @{
        version = '2.5.0.154'; bytes = 12844360
        sha256 = '71fbddf1838aae7dcf5cd2e1ea15321fdeaa3f19b9d862465b5d55b203c75091'
        md5 = 'eff02b1ad15aae9050d4f10e7bbf0fc2'
        release_date_reported = '2006-11-29'
        sources = @('https://www.oldversion.com/windows/skype/skype-2-5-0-154/', 'https://kirils.org/skype/stuff/versions/windows/', 'https://www.afterdawn.com/software/network/net_telephony/skype.cfm/v6_6_0_106')
        rationale = 'Last stable standard Windows 2.x release identified. Higher 2.6.0.97/103/105 Windows versions are beta builds; some catalog duplicate labels omit Beta.'
        note = 'Fixed numeric VERSIONINFO is 2.5.0.154. Text FileVersion incorrectly says 2.5.0.1; text ProductVersion says 1.0.0.0. Catalog MD5 matches. Inno Setup data marker 5.0.4skp is present.'
    },
    @{
        version = '3.8.0.188'; bytes = 22285608
        sha256 = 'bf94e0c33a99811bf89f6761caea891ab2fd331ac831f2f48c440b238db93f24'
        md5 = 'e869a3e950c21c937c114d3c7a8ea2e0'
        release_date_reported = '2008-11-19'
        sources = @('https://www.oldversion.com/windows/skype/skype-3-8-0-188/', 'https://kirils.org/skype/stuff/versions/windows/', 'https://www.oldversion.com/windows/skype/')
        rationale = 'Highest stable standard Windows 3.x build in the checked archive histories; version and catalog MD5 independently match the downloaded mirror file.'
        note = 'Original full-size EXE, not a portable repack. Installer PE architecture is checked; inner application architecture was not separately extracted.'
    },
    @{
        version = '4.2.0.187'; bytes = 19075976
        sha256 = 'f8c75bc85411e17484b80c8653219f703ce13cfb5046e408913d5ef5a5a0b840'
        md5 = '3440548d69923b0fa0c81633576ea91e'
        release_date_reported = '2010-09-07'
        sources = @('https://www.oldversion.com/windows/skype/skype-4-2-0-187/', 'https://www.oldversion.com/windows/skype/')
        rationale = 'Highest stable standard Windows 4.x build in the checked archive histories; downloaded original has matching version, signature, and catalog MD5.'
        note = 'The kirils.org candidate was only 7077134 bytes and had no readable VERSIONINFO. It was rejected and replaced with this independently verified OldVersion file; its current retained location is listed separately.'
    },
    @{
        version = '5.10.0.116'; bytes = 25653936
        sha256 = '13f7723327948e8c24e7cdd6de26f32d9e32a39f90bde86d64214f5255b85937'
        md5 = '1bfd2d72861ff7da31f33212df2ea40b'
        release_date_reported = '2012-07-17'
        sources = @('https://www.oldversion.com/windows/skype/skype-5-10-0-116/', 'https://www.afterdawn.com/software/network/net_telephony/skype.cfm/v6_6_0_106', 'https://community.chocolatey.org/packages/skype/5.10.0.116')
        rationale = 'Last stable standard Windows 5.x release identified. The subsequent 5.11.0.102 was Beta, before 6.0; partner-channel 5.10.66.116 is not a later patch level.'
        note = 'Original SkypeSetupFull EXE obtained using the normal OldVersion POST download form and its archive-storage redirect.'
    },
    @{
        version = '6.22.0.107'; bytes = 40042496
        sha256 = '9d4941315bf50e3e914f0c7a1efd3647f6feb976533184628aea13aa298e0e22'
        sha1 = '65dddf6ccab61f017e87a987e1bbb31da098bba6'
        release_date_reported = '2014-12-02; official MSI captured 2014-12-03'
        sources = @('https://web.archive.org/web/20141203110350/http://download.skype.com/msi/SkypeSetup_6.22.0.107.msi', 'https://web.archive.org/cdx/search/cdx?url=download.skype.com%2Fmsi%2FSkypeSetup_6.22.0.107.msi&output=json&filter=statuscode%3A200&collapse=digest', 'https://www.gfi.com/lannetscan/3pfullreport2014.asp', 'https://stahnu.cz/volani-pres-internet/skype')
        rationale = 'Last stable standard Windows 6.x patch identified before 7.0. Archived official-channel MSI proves ARPVERSION and Skype.exe version 6.22.0.107, not 6.22.64/81/85 UI-channel variants.'
        note = 'MSI ProductVersion is the three-part 6.22.107; ARPVERSION and File table contain 6.22.0.107. Intel;1033 package; embedded Product.CAB present. SHA1 equals the decoded Wayback CDX digest MXO563GKWYPQC7UHVGD6DO5TDWQJRO5G.'
    }
)

$entries = @()
foreach ($selection in $selections) {
    $version = $selection.version
    $download = @($attempts | Where-Object { $_.expected_version -eq $version -and $_.status -like 'downloaded*' })[-1]
    if (!$download) { throw "Missing successful download evidence: $version" }
    $path = $download.destination
    $item = Get-Item -LiteralPath $path
    $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($item.Length -ne $selection.bytes -or $sha256 -ne $selection.sha256 -or $sha256 -ne $download.sha256) {
        throw "Integrity mismatch: $path"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne 'Valid') { throw "Signature is no longer valid: $path" }
    $entry = [ordered]@{
        major = [int]$version.Split('.')[0]
        version = $version
        platform = 'Windows desktop'
        status = 'downloaded_version_hash_signature_verified'
        full_path = $path
        size_bytes = $item.Length
        sha256 = $sha256
        sha1 = (Get-FileHash -LiteralPath $path -Algorithm SHA1).Hash.ToLowerInvariant()
        md5 = (Get-FileHash -LiteralPath $path -Algorithm MD5).Hash.ToLowerInvariant()
        download_url = $download.request_url
        download_method = $download.method
        source_pages = $selection.sources
        release_date_reported = $selection.release_date_reported
        selection_rationale = $selection.rationale
        format_magic = $download.magic
        installer_architecture = $download.installer_architecture
        x86_status = 'downloaded_verified'
        x86_64_status = 'not_found_in_checked_archives_release_nonexistence_unverified'
        native_x86_64_nonrelease_proven = $false
        authenticode_status = [string]$signature.Status
        signer_subject = $signature.SignerCertificate.Subject
        signer_thumbprint = $signature.SignerCertificate.Thumbprint
        timestamp_subject = $signature.TimeStamperCertificate.Subject
        installer_executed = $false
        offline_installation_runtime_tested = $false
        notes = $selection.note
    }
    if ($selection.md5 -and $entry.md5 -ne $selection.md5) { throw "Catalog MD5 mismatch: $version" }
    if ($selection.sha1 -and $entry.sha1 -ne $selection.sha1) { throw "Wayback digest mismatch: $version" }
    $entry.catalog_hash_match = $true
    if ($item.Extension -eq '.exe') {
        $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($path)
        $entry.numeric_file_version = '{0}.{1}.{2}.{3}' -f $info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart
        $entry.text_file_version = $info.FileVersion
        $entry.text_product_version = $info.ProductVersion
        $entry.prerelease_flag = $info.IsPreRelease
        if ($entry.numeric_file_version -ne $version -or $info.IsPreRelease) { throw "Version mismatch: $version" }
        $entry.offline_package_status = 'full_size_original_exe_not_runtime_tested_payload_not_extracted'
        $stream = [IO.File]::OpenRead($path)
        $reader = [IO.BinaryReader]::new($stream)
        try {
            if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'MZ mismatch.' }
            $stream.Position = 0x3c
            $offset = $reader.ReadUInt32()
            $stream.Position = $offset
            if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x14c) { throw 'PE/machine mismatch.' }
            $entry.pe_machine = '0x014c'
            $stream.Position = $offset + 24
            if ($reader.ReadUInt16() -ne 0x10b) { throw 'PE32 optional header mismatch.' }
            $entry.pe_optional_magic = '0x010b'
        } finally { $reader.Dispose() }
    } else {
        $stream = [IO.File]::OpenRead($path)
        try {
            $header = [byte[]]::new(8)
            if ($stream.Read($header, 0, 8) -ne 8 -or [Convert]::ToHexString($header) -ne 'D0CF11E0A1B11AE1') { throw 'MSI magic mismatch.' }
        } finally { $stream.Dispose() }
        $entry.numeric_file_version = $download.file_version_fixed
        $entry.msi_template = $download.msi_template
        $entry.msi_properties = $download.msi_properties
        $entry.msi_files = $download.msi_files
        $entry.msi_cabinets = $download.msi_cabinets
        $entry.msi_stream_names = $download.msi_stream_names
        $entry.offline_package_status = $download.offline_payload_status
    }
    $entries += $entry
}

$remaining = @(
    'No native Windows x86_64 installer was found for any selected major. Native x86_64 non-release is not proven by the sources checked; do not invent or relabel packages.'
    'EXE installer PE architecture is x86; their inner Skype.exe payloads were not separately extracted. The MSI package template is Intel (x86).'
    'Offline installation, login, calls, network behavior, and safety at runtime were not tested. These obsolete clients are archival artifacts, not a recommendation to run them.'
    'Selection is the final stable standard consumer desktop channel found in the checked histories, not a claim that partner channel numbers sort chronologically. Windows Store/RT, mobile, Skype for Business, previews, and repacks are excluded.'
)
$mirrorFailures = @(
    @{ url = 'https://kirils.org/skype/stuff/versions/windows/SkypeSetup_4.2.0.187.exe'; status = 'rejected_no_readable_version'; recovered_by = 'verified OldVersion download' },
    @{ url = 'https://stahnu.cz/volani-pres-internet/skype/download/65712'; status = 'download_page_explicitly_reports_application_no_longer_downloadable'; recovered_by = 'official MSI via Wayback' },
    @{ url = 'https://download.skype.com/688cac4ce903adeb2a7e12678d6f4da0/SkypeSetupFull.exe'; status = 'DNS_host_unknown'; recovered_by = 'official MSI via Wayback' },
    @{ url = 'https://download.skype.com/msi/SkypeSetup_6.22.0.107.msi'; status = 'DNS_host_unknown'; recovered_by = 'official MSI via Wayback' },
    @{ url = 'https://www.oldversion.com/windows/skype/skype-6-22-0-107/'; status = 'HTTP_404'; recovered_by = 'official MSI via Wayback' },
    @{ url = 'https://www.skaip.org/skype-6-22-0-107-for-windows'; status = 'TLS_connection_failed_not_bypassed'; recovered_by = 'official MSI via Wayback' }
)
$unverified = @($attempts | Where-Object { $_.retained_partial_path -and (Test-Path -LiteralPath $_.retained_partial_path) })
$quarantineManifest = Join-Path $root 'Windows_QUARANTINE\Windows_QUARANTINE.json'
if (Test-Path -LiteralPath $quarantineManifest) {
    $quarantine = Get-Content -LiteralPath $quarantineManifest -Raw | ConvertFrom-Json -AsHashtable
    foreach ($candidate in $quarantine.entries) {
        if (!(Test-Path -LiteralPath $candidate.retained_partial_path) -or
            (Get-FileHash -LiteralPath $candidate.retained_partial_path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $candidate.sha256) {
            throw 'Quarantine record does not match its retained file.'
        }
        $unverified += $candidate
    }
}
$verifiedTotal = 0L
foreach ($entry in $entries) { $verifiedTotal += $entry.size_bytes }
$index = [ordered]@{
    schema = 'skype-windows-archive-v1'
    generated_utc = [DateTime]::UtcNow.ToString('o')
    archive_root = $root
    scope = 'Windows desktop, final stable standard builds in majors 2 through 6'
    initial_inventory = @{ observed_before_downloads = $true; root_was_empty = $true; preexisting_entries = @() }
    policy = @{ existing_files_overwritten = $false; originals_deleted = $false; installers_executed = $false; antivirus_disabled = $false; blocks_bypassed = $false; installers_committed_or_published = $false }
    verified_file_count = $entries.Count
    verified_total_bytes = $verifiedTotal
    entries = $entries
    remaining_gaps_and_limits = $remaining
    rejected_files_retained_not_accepted_as_installers = $unverified
    quarantine_manifest = if (Test-Path -LiteralPath $quarantineManifest) { $quarantineManifest } else { $null }
    source_investigation_failures = $mirrorFailures
    download_attempts = $attempts
}

$stem = 'Windows_INDEX'
if ((Test-Path -LiteralPath (Join-Path $root "$stem.json")) -or (Test-Path -LiteralPath (Join-Path $root "$stem.md"))) {
    $stem += '_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
}
$jsonPath = Join-Path $root "$stem.json"
$mdPath = Join-Path $root "$stem.md"
$md = [Collections.Generic.List[string]]::new()
$md.Add('# Skype Windows Archive: Final Stable Majors 2-6')
$md.Add('')
$md.Add("Generated UTC: $($index.generated_utc)")
$md.Add("Archive root: ``$root``")
$md.Add('')
$md.Add('Five original signed installer files are present. The destination was inventoried empty before downloads. Existing files, other platform work, and server sources were not modified. No installer was executed, no antivirus setting was changed, and nothing was uploaded or committed.')
$md.Add('')
$md.Add('## Version Selection')
$md.Add('')
foreach ($entry in $entries) {
    $md.Add("### $($entry.version)")
    $md.Add('')
    $md.Add($entry.selection_rationale)
    $md.Add("Reported release date: $($entry.release_date_reported). This is source-reported chronology; exact embedded versions and file hashes are independently checked.")
    $md.Add("- Path: ``$($entry.full_path)``")
    $md.Add("- Size: $($entry.size_bytes) bytes")
    $md.Add("- SHA-256: ``$($entry.sha256)``")
    $md.Add("- SHA-1: ``$($entry.sha1)``")
    $md.Add("- MD5: ``$($entry.md5)`` (catalog comparison only, not a security guarantee)")
    $md.Add("- Magic: $($entry.format_magic); numeric version: $($entry.numeric_file_version); installer/package architecture: $($entry.installer_architecture)")
    $md.Add("- Authenticode: $($entry.authenticode_status); signer: $($entry.signer_subject)")
    $md.Add("- Full/offline package evidence: $($entry.offline_package_status)")
    $md.Add("- Native x86_64: $($entry.x86_64_status)")
    $md.Add("- Download request ($($entry.download_method)): [archive endpoint]($($entry.download_url))")
    $md.Add("- Notes: $($entry.notes)")
    foreach ($source in $entry.source_pages) { $md.Add("- Source: [direct source page]($source)") }
    $md.Add('')
}
$md.Add('## Remaining Gaps and Limits')
$md.Add('')
foreach ($gap in $remaining) { $md.Add("- $gap") }
$md.Add('')
$md.Add('## Rejected Candidate Preserved / Quarantined')
$md.Add('')
foreach ($entry in $unverified) {
    $md.Add("- ``$($entry.retained_partial_path)``; $($entry.size_bytes) bytes; SHA-256 ``$($entry.sha256)``. Not counted as an accepted installer. Reason: $($entry.error)")
    $md.Add("- Original download source: [archive file]($($entry.request_url)).")
    if ($entry.original_partial_path) {
        $md.Add("- Original path: ``$($entry.original_partial_path)``. Quarantined without changing bytes; see ``$quarantineManifest`` for containment and hash checks.")
    }
}
$md.Add('')
$md.Add('## Source Failures and Recovery')
$md.Add('')
foreach ($failure in $mirrorFailures) { $md.Add("- [source]($($failure.url)): $($failure.status). Recovery: $($failure.recovered_by).") }
$md.Add('- The complete 6.22 MSI initially could not be renamed because a read-only COM object retained a file handle. After releasing COM objects, the same file was rehashed, revalidated, and finalized; it was not downloaded again or patched.')
$md.Add('')
$md.Add("The JSON companion contains all download attempts, resolved URLs, timestamps, signature details, and MSI table evidence. The append-only request log is ``$logPath``. Expiring OldVersion storage URLs in that log are provenance, not durable download links.")

function Write-NewText([string]$Path, [string]$Text) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
    try { $writer.Write($Text) } finally { $writer.Dispose() }
}
Write-NewText $jsonPath ($index | ConvertTo-Json -Depth 12)
Write-NewText $mdPath ([string]::Join("`r`n", $md) + "`r`n")
[pscustomobject]@{ json = $jsonPath; markdown = $mdPath; verified_files = $entries.Count; verified_bytes = $index.verified_total_bytes; rejected_files_retained = $unverified.Count } | ConvertTo-Json
