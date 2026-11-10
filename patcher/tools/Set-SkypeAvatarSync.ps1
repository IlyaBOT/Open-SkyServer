<#
Experimental Skype 4.2 profile setting, not an EXE patch. Close the selected
portable client first. -Enabled 0 disables the override for a follow-up test.
#>
[CmdletBinding()]
param(
    [string]$Directory,
    [ValidateSet('0','1')][string]$Enabled = '1'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
if (-not $Directory) { $Directory = $PSScriptRoot }
$portableDirectory = [IO.Path]::GetFullPath($Directory)
$processes = @(Get-CimInstance Win32_Process -Filter "Name = 'Skype.exe'" | Where-Object {
    $_.ExecutablePath -and [IO.Path]::GetDirectoryName($_.ExecutablePath) -eq $portableDirectory
})
if ($processes.Count) { throw 'Close Skype from this portable folder before changing the setting. No process was stopped.' }
. (Join-Path $portableDirectory 'Launch-Skype.ps1')
Start-PatchedSkype -Directory $portableDirectory -ConfigureOnly
$profileDirectory = Join-Path $portableDirectory 'profile'
$paths = @((Join-Path $profileDirectory 'shared.xml'))
foreach ($account in @(Get-ChildItem -LiteralPath $profileDirectory -Directory -Force)) {
    if ($account.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
    $config = Join-Path $account.FullName 'config.xml'
    if (Test-Path -LiteralPath $config -PathType Leaf) { $paths += $config }
}
foreach ($path in $paths) {
    $changed = Set-SkypeXml -Path $path -Values @{'Lib/CentralStorage/SyncAvatar'=$Enabled}
    [pscustomobject]@{ Path=$path; SyncAvatar=$Enabled; Changed=$changed }
}
Write-Host 'Start this client through Start-Skype.cmd, then change the avatar again. This setting alone is not proof of avatar upload.'
