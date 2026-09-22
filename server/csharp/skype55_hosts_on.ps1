param(
    [string]$HostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

$names = @(
    "login.skype.com",
    "ui.skype.com",
    "api.skype.com",
    "apps.skype.com",
    "config.skype.com",
    "pipe.skype.com",
    "skype.com",
    "www.skype.com"
)

$begin = "# BEGIN SKYSERVER SKYPE55"
$end = "# END SKYSERVER SKYPE55"
$existing = ""
if (Test-Path $HostsPath) {
    $existing = [System.IO.File]::ReadAllText($HostsPath)
    if ($null -eq $existing) {
        $existing = ""
    }
}
$backup = "$HostsPath.skyserver-backup-$(Get-Date -Format yyyyMMddHHmmss)"
Copy-Item -LiteralPath $HostsPath -Destination $backup -Force

$pattern = "(?ms)^$([regex]::Escape($begin)).*?^$([regex]::Escape($end))\r?\n?"
$clean = [regex]::Replace($existing, $pattern, "")
$block = New-Object Text.StringBuilder
[void]$block.AppendLine($begin)
foreach ($name in $names) {
    [void]$block.AppendLine("127.0.0.1 $name")
}
[void]$block.AppendLine($end)

Set-Content -LiteralPath $HostsPath -Value ($clean.TrimEnd() + "`r`n" + $block.ToString()) -Encoding ASCII
ipconfig /flushdns | Out-Host
Write-Host "Skype 5.5 hosts entries enabled. Backup: $backup"
