param(
    [string]$InterfaceAlias = "Loopback Pseudo-Interface 1",
    [string]$SkypeSharedXml = "$env:APPDATA\Skype\shared.xml",
    [string]$AliasStatePath = "",
    [switch]$IncludeHostCache
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($AliasStatePath)) {
    $AliasStatePath = Join-Path $PSScriptRoot "skype_ip_redirect.state.json"
}
$interface = Get-NetIPInterface -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop
& (Join-Path $PSScriptRoot "skype_ip_redirect.ps1") -Action Enable -InterfaceIndex $interface.InterfaceIndex -SkypeSharedXml $SkypeSharedXml -IncludeHostCache ([bool]$IncludeHostCache) -StatePath $AliasStatePath
