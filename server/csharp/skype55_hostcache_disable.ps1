param(
    [string]$SkypeSharedXml = "$env:APPDATA\Skype\shared.xml",
    [string]$StatePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path $PSScriptRoot "skype55_hostcache_backup.json"
}

if (-not (Test-Path -LiteralPath $SkypeSharedXml)) {
    throw "Skype shared.xml not found: $SkypeSharedXml"
}

if (Get-Process Skype -ErrorAction SilentlyContinue) {
    Write-Warning "Skype.exe is running. Close Skype before login tests, otherwise it may rewrite shared.xml."
}

$resolvedSharedXml = (Resolve-Path -LiteralPath $SkypeSharedXml).Path
$backup = "$resolvedSharedXml.skyserver-hostcache-backup-$(Get-Date -Format yyyyMMddHHmmss)"
Copy-Item -LiteralPath $resolvedSharedXml -Destination $backup -Force

[xml]$xml = Get-Content -LiteralPath $resolvedSharedXml -Raw
$node = $xml.SelectSingleNode("/config/Lib/Connection/HostCache")
$lastProbingFailed = $xml.SelectSingleNode("/config/Lib/Connection/LastProbingFailed")
if ($null -eq $node) {
    Write-Host "HostCache node not found; nothing to remove. Backup: $backup"
    $state = [pscustomobject]@{
        SkypeSharedXml = $resolvedSharedXml
        Backup = $backup
        HostCache = ""
        HadHostCache = $false
        LastProbingFailed = if ($null -eq $lastProbingFailed) { "" } else { [string]$lastProbingFailed.InnerText }
        HadLastProbingFailed = $null -ne $lastProbingFailed
    }
    $state | ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding ASCII

    if ($null -ne $lastProbingFailed) {
        [void]$lastProbingFailed.ParentNode.RemoveChild($lastProbingFailed)
        $xml.Save($resolvedSharedXml)
        Write-Host "LastProbingFailed removed: $resolvedSharedXml"
    }

    return
}

$state = [pscustomobject]@{
    SkypeSharedXml = $resolvedSharedXml
    Backup = $backup
    HostCache = [string]$node.InnerText
    HadHostCache = $true
    LastProbingFailed = if ($null -eq $lastProbingFailed) { "" } else { [string]$lastProbingFailed.InnerText }
    HadLastProbingFailed = $null -ne $lastProbingFailed
}
$state | ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding ASCII

[void]$node.ParentNode.RemoveChild($node)
if ($null -ne $lastProbingFailed) {
    [void]$lastProbingFailed.ParentNode.RemoveChild($lastProbingFailed)
}
$xml.Save($resolvedSharedXml)

Write-Host "Skype HostCache node removed: $resolvedSharedXml"
Write-Host "LastProbingFailed removed: $resolvedSharedXml"
Write-Host "Backup copied: $backup"
Write-Host "Restore state saved: $StatePath"
