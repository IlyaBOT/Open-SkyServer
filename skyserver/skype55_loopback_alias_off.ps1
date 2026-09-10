param(
    [string]$InterfaceAlias = "Loopback Pseudo-Interface 1",
    [string]$SkypeSharedXml = "$env:APPDATA\Skype\shared.xml",
    [string]$AliasStatePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($AliasStatePath)) {
    $AliasStatePath = Join-Path $PSScriptRoot "skype_ip_redirect.state.json"
}
# Rollback uses only the ownership journal; it never guesses addresses from HostCache.
& (Join-Path $PSScriptRoot "skype_ip_redirect.ps1") -Action Disable -StatePath $AliasStatePath
