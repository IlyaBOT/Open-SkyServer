param(
    [string]$SkypeSharedXml = "$env:APPDATA\Skype\shared.xml",
    [string]$SourceBackup = "",
    [string]$StatePath = "",
    [string[]]$SeedEndpoints = @(
        "91.190.218.40:40001",
        "91.190.216.17:40002",
        "65.55.223.25:40003",
        "64.4.23.141:40004",
        "111.221.74.33:40005",
        "91.190.218.40:40006",
        "91.190.216.17:40007",
        "65.55.223.25:40008",
        "64.4.23.141:40009",
        "111.221.74.33:40010",
        "91.190.218.40:40011",
        "91.190.216.17:40012",
        "65.55.223.25:40013",
        "64.4.23.141:40014",
        "111.221.74.33:40015",
        "91.190.218.40:40016",
        "91.190.216.17:40017",
        "65.55.223.25:40018",
        "64.4.23.141:40019",
        "111.221.74.33:40020",
        "91.190.218.40:40021",
        "91.190.216.17:40022",
        "65.55.223.25:40023",
        "64.4.23.141:40024",
        "111.221.74.33:40025",
        "91.190.218.40:40026",
        "91.190.216.17:40027",
        "65.55.223.25:40028",
        "64.4.23.141:40029",
        "111.221.74.33:40030",
        "91.190.218.40:40031",
        "91.190.216.17:40032",
        "65.55.223.25:40033",
        "64.4.23.141:40034",
        "111.221.74.33:40035",
        "91.190.218.40:40036"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path $PSScriptRoot "skype55_hostcache_seed_local_state.json"
}

function Get-HostCacheHex {
    param([string]$Path)

    try {
        [xml]$xml = Get-Content -LiteralPath $Path -Raw
    }
    catch {
        return ""
    }

    $node = $xml.SelectSingleNode("/config/Lib/Connection/HostCache")
    if ($null -eq $node) {
        return ""
    }

    return ([string]$node.InnerText) -replace "\s+", ""
}

function Find-SourceBackup {
    param([string]$SharedXmlPath)

    $directory = Split-Path -Parent $SharedXmlPath
    $candidates = Get-ChildItem -LiteralPath $directory -Filter "shared.xml.skyserver-hostcache-backup-*" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending

    foreach ($candidate in $candidates) {
        $hex = Get-HostCacheHex -Path $candidate.FullName
        if (-not [string]::IsNullOrWhiteSpace($hex) -and ($hex.Length % 2) -eq 0 -and $hex.Contains("41050200")) {
            return $candidate.FullName
        }
    }

    return ""
}

function Convert-HexToBytes {
    param([string]$Hex)

    if (($Hex.Length % 2) -ne 0) {
        throw "HostCache hex length is odd."
    }

    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }

    return $bytes
}

function Convert-BytesToHex {
    param([byte[]]$Bytes)

    return -join ($Bytes | ForEach-Object { $_.ToString("X2") })
}

function Convert-SeedEndpoint {
    param([string]$Endpoint)

    if ($Endpoint -notmatch "^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$") {
        throw "Seed endpoint must be IPv4:port: $Endpoint"
    }

    $address = [Net.IPAddress]::Parse($Matches[1])
    $addressBytes = $address.GetAddressBytes()
    if ($addressBytes.Length -ne 4) {
        throw "Seed endpoint must use IPv4: $Endpoint"
    }

    $port = [int]$Matches[2]
    if ($port -le 0 -or $port -gt 65535) {
        throw "Seed endpoint port is out of range: $Endpoint"
    }

    return [pscustomobject]@{
        Endpoint = $Endpoint
        AddressBytes = $addressBytes
        Port = $port
    }
}

if (-not (Test-Path -LiteralPath $SkypeSharedXml)) {
    throw "Skype shared.xml not found: $SkypeSharedXml"
}

if (Get-Process Skype -ErrorAction SilentlyContinue) {
    Write-Warning "Skype.exe is running. Close Skype before seeding HostCache, otherwise it may rewrite shared.xml."
}

$resolvedSharedXml = (Resolve-Path -LiteralPath $SkypeSharedXml).Path
if ([string]::IsNullOrWhiteSpace($SourceBackup)) {
    $SourceBackup = Find-SourceBackup -SharedXmlPath $resolvedSharedXml
}

if ([string]::IsNullOrWhiteSpace($SourceBackup) -or -not (Test-Path -LiteralPath $SourceBackup)) {
    throw "Could not find a shared.xml backup with a non-empty HostCache. Pass -SourceBackup explicitly."
}

$sourceHostCache = Get-HostCacheHex -Path $SourceBackup
if ([string]::IsNullOrWhiteSpace($sourceHostCache)) {
    throw "Source backup does not contain HostCache: $SourceBackup"
}

$seedRecords = @($SeedEndpoints | ForEach-Object { Convert-SeedEndpoint -Endpoint $_ })
if ($seedRecords.Count -eq 0) {
    throw "At least one seed endpoint is required."
}

$bytes = Convert-HexToBytes -Hex $sourceHostCache
$entryCount = 0
for ($i = 0; $i -le ($bytes.Length - 10); $i++) {
    if ($bytes[$i] -ne 0x41 -or $bytes[($i + 1)] -ne 0x05 -or $bytes[($i + 2)] -ne 0x02 -or $bytes[($i + 3)] -ne 0x00) {
        continue
    }

    $seed = $seedRecords[$entryCount % $seedRecords.Count]
    $bytes[($i + 4)] = $seed.AddressBytes[0]
    $bytes[($i + 5)] = $seed.AddressBytes[1]
    $bytes[($i + 6)] = $seed.AddressBytes[2]
    $bytes[($i + 7)] = $seed.AddressBytes[3]
    $bytes[($i + 8)] = [byte](($seed.Port -shr 8) -band 0xFF)
    $bytes[($i + 9)] = [byte]($seed.Port -band 0xFF)
    $entryCount++
}

if ($entryCount -eq 0) {
    throw "No HostCache endpoint records were found in source backup: $SourceBackup"
}

$seededHostCache = Convert-BytesToHex -Bytes $bytes
$backup = "$resolvedSharedXml.skyserver-hostcache-seed-backup-$(Get-Date -Format yyyyMMddHHmmss)"
Copy-Item -LiteralPath $resolvedSharedXml -Destination $backup -Force

[xml]$xml = Get-Content -LiteralPath $resolvedSharedXml -Raw
$connection = $xml.SelectSingleNode("/config/Lib/Connection")
if ($null -eq $connection) {
    throw "Cannot seed HostCache: /config/Lib/Connection node not found."
}

$existingHostCache = $xml.SelectSingleNode("/config/Lib/Connection/HostCache")
$lastProbingFailed = $xml.SelectSingleNode("/config/Lib/Connection/LastProbingFailed")
$state = [pscustomobject]@{
    SkypeSharedXml = $resolvedSharedXml
    SourceBackup = (Resolve-Path -LiteralPath $SourceBackup).Path
    Backup = $backup
    SeedEndpoints = $SeedEndpoints
    EntryCount = $entryCount
    HostCacheHexLength = $seededHostCache.Length
    PreviousHostCache = if ($null -eq $existingHostCache) { "" } else { [string]$existingHostCache.InnerText }
    HadHostCache = $null -ne $existingHostCache
    LastProbingFailed = if ($null -eq $lastProbingFailed) { "" } else { [string]$lastProbingFailed.InnerText }
    HadLastProbingFailed = $null -ne $lastProbingFailed
}
$state | ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding ASCII

if ($null -eq $existingHostCache) {
    $existingHostCache = $xml.CreateElement("HostCache")
    [void]$connection.AppendChild($existingHostCache)
}

$existingHostCache.InnerText = $seededHostCache
if ($null -ne $lastProbingFailed) {
    [void]$lastProbingFailed.ParentNode.RemoveChild($lastProbingFailed)
}

$xml.Save($resolvedSharedXml)

Write-Host "Skype HostCache seeded with local endpoints: $resolvedSharedXml"
Write-Host "Source HostCache backup: $SourceBackup"
Write-Host "Endpoint records rewritten: $entryCount"
Write-Host "Seed endpoints: $($SeedEndpoints -join ', ')"
Write-Host "Backup copied: $backup"
Write-Host "Seed state saved: $StatePath"
