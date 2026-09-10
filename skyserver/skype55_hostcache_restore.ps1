param(
    [string]$StatePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path $PSScriptRoot "skype55_hostcache_backup.json"
}

if (-not (Test-Path -LiteralPath $StatePath)) {
    throw "HostCache restore state not found: $StatePath"
}

$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if (-not (Test-Path -LiteralPath $state.SkypeSharedXml)) {
    throw "Skype shared.xml not found: $($state.SkypeSharedXml)"
}

if (Get-Process Skype -ErrorAction SilentlyContinue) {
    Write-Warning "Skype.exe is running. Close Skype before restoring HostCache, otherwise it may rewrite shared.xml."
}

[xml]$xml = Get-Content -LiteralPath $state.SkypeSharedXml -Raw
$node = $xml.SelectSingleNode("/config/Lib/Connection/HostCache")

if ($state.HadHostCache) {
    if ($null -eq $node) {
        $connection = $xml.SelectSingleNode("/config/Lib/Connection")
        if ($null -eq $connection) {
            throw "Cannot restore HostCache: /config/Lib/Connection node not found."
        }

        $node = $xml.CreateElement("HostCache")
        [void]$connection.AppendChild($node)
    }

    $node.InnerText = [string]$state.HostCache
    $xml.Save($state.SkypeSharedXml)
    Write-Host "Skype HostCache restored: $($state.SkypeSharedXml)"
}
else {
    Write-Host "Original shared.xml did not have HostCache; nothing restored."
}

if ($state.PSObject.Properties.Name -contains "HadLastProbingFailed" -and $state.HadLastProbingFailed) {
    $connection = $xml.SelectSingleNode("/config/Lib/Connection")
    if ($null -eq $connection) {
        throw "Cannot restore LastProbingFailed: /config/Lib/Connection node not found."
    }

    $lastProbingFailed = $xml.SelectSingleNode("/config/Lib/Connection/LastProbingFailed")
    if ($null -eq $lastProbingFailed) {
        $lastProbingFailed = $xml.CreateElement("LastProbingFailed")
        [void]$connection.AppendChild($lastProbingFailed)
    }

    $lastProbingFailed.InnerText = [string]$state.LastProbingFailed
    $xml.Save($state.SkypeSharedXml)
    Write-Host "LastProbingFailed restored: $($state.SkypeSharedXml)"
}
