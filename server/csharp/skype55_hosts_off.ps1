param(
    [string]$HostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

$begin = "# BEGIN SKYSERVER SKYPE55"
$end = "# END SKYSERVER SKYPE55"
$existing = ""
if (Test-Path $HostsPath) {
    $existing = [System.IO.File]::ReadAllText($HostsPath)
    if ($null -eq $existing) {
        $existing = ""
    }
}
$pattern = "(?ms)^$([regex]::Escape($begin)).*?^$([regex]::Escape($end))\r?\n?"
$clean = [regex]::Replace($existing, $pattern, "")
Set-Content -LiteralPath $HostsPath -Value $clean.TrimEnd() -Encoding ASCII
ipconfig /flushdns | Out-Host
Write-Host "Skype 5.5 hosts entries removed."
