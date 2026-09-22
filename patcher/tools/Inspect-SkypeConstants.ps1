[CmdletBinding()]
param([int]$ProcessId = 0, [string]$ClientPath = 'C:\Program Files (x86)\Skype\Phone\Skype.exe')
$ErrorActionPreference = 'Stop'
$targetExe = $ClientPath
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'skypatch.ps1')
$ClientPath = $targetExe
if ($ProcessId -eq 0) {
    $candidates = @(Get-Process Skype -ErrorAction Stop | Where-Object { $_.Path -eq $ClientPath })
    if ($candidates.Count -ne 1) { throw 'Expected exactly one matching Skype process. Specify -ProcessId.' }
    $ProcessId = $candidates[0].Id
}
if ((Get-Process -Id $ProcessId).Path -ne $ClientPath) { throw 'Process executable does not match ClientPath.' }
if (-not ('PublicConstantInspector' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'PublicConstantInspector.cs') -ReferencedAssemblies System.Numerics
}
[PublicConstantInspector]::Scan($ProcessId, (Convert-Hex $OriginalLoginModulus), (Convert-Hex $OriginalCredentialsModulus), $ClientPath)
