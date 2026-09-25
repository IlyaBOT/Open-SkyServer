[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Plan','Enable','Disable','Status')][string]$Action = 'Plan',
    [int]$InterfaceIndex = 1,
    [string]$AddressListPath = (Join-Path $PSScriptRoot 'skype_ip_targets.txt'),
    [string]$SkypeSharedXml = (Join-Path $env:APPDATA 'Skype\shared.xml'),
    [bool]$IncludeHostCache = $true,
    [string[]]$AdditionalIPAddress = @(),
    [string]$StatePath = (Join-Path $PSScriptRoot 'skype_ip_redirect.state.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SkypeIpRedirect.psm1') -Force

if ($Action -eq 'Status') {
    $state = Read-SkypeRedirectState $StatePath
    if (-not $state) { Write-Host 'No IP redirect journal exists.'; return }
    $state | Format-List
    Get-SkypeRedirectPlan -IPAddress $state.TargetAddresses -InterfaceIndex $state.InterfaceIndex | Format-Table -AutoSize
    return
}

if ($Action -ne 'Disable') {
    $targets = @(Get-SkypeRedirectTargets -AddressListPath $AddressListPath -SkypeSharedXml $SkypeSharedXml -IncludeHostCache:$IncludeHostCache -AdditionalIPAddress $AdditionalIPAddress)
    $plan = @(Get-SkypeRedirectPlan -IPAddress $targets -InterfaceIndex $InterfaceIndex)
    $plan | Format-Table -AutoSize
    Write-Host 'Selected IPv4 destinations become local for ALL processes, TCP and UDP, on all ports.'
    Write-Host 'Unknown destinations are not redirected. No hosts, client profile, binary, firewall or VPN settings are changed.'
    if ($Action -eq 'Plan') { return }
}

if (-not $PSCmdlet.ShouldProcess('IPv4 loopback aliases recorded in ' + $StatePath, $Action)) { return }
$StatePath = [IO.Path]::GetFullPath($StatePath)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($StatePath)) | Out-Null
$lock = [IO.File]::Open($StatePath + '.lock', [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    if ($Action -eq 'Disable') { Disable-SkypeIpRedirect -StatePath $StatePath }
    else {
        Enable-SkypeIpRedirect -IPAddress $targets -InterfaceIndex $InterfaceIndex -StatePath $StatePath | Out-Null
        Write-Host 'Aliases enabled until reboot or Disable. Restart pending Skype connections after the server is listening.'
        Write-Host 'Server command (run from the repository):'
        Write-Host '.\skyserver\bin\Release\skyserver.exe --host 0.0.0.0 --api-host 127.0.0.1 --real-skype-probe --include-hostcache-probe'
    }
} finally { $lock.Dispose() }
