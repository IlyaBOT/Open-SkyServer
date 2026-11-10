[CmdletBinding()]
param(
    [switch]$ConfigureOnly,
    [switch]$NoShortcut
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$configureRequested = [bool]$ConfigureOnly

try {
    # Dot sourcing binds the launcher's own ConfigureOnly parameter in this scope.
    . (Join-Path $PSScriptRoot 'Launch-Skype.ps1')
    Start-PatchedSkype -Directory $PSScriptRoot -ConfigureOnly
    if ($configureRequested) { return }

    if (-not $NoShortcut) {
        # A different portable installation may already own this shortcut.
        # Never redirect an existing shortcut or modify an installed client.
        try {
            $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
            if ($desktop) {
                $shortcutPath = Join-Path $desktop 'Skype 4.2.0.187 Patched.lnk'
                if (-not (Test-Path -LiteralPath $shortcutPath)) {
                    Assert-SkypeLocalPath $shortcutPath
                    $shell = New-Object -ComObject WScript.Shell
                    try {
                        $shortcut = $shell.CreateShortcut($shortcutPath)
                        try {
                            $shortcut.TargetPath = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
                            $shortcut.Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $PSCommandPath + '"'
                            $shortcut.WorkingDirectory = $PSScriptRoot
                            $shortcut.IconLocation = (Join-Path $PSScriptRoot 'Skype.exe') + ',0'
                            $shortcut.Description = 'Skype 4.2.0.187 Patched'
                            $shortcut.Save()
                        } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) }
                    } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
                }
            }
        } catch { Write-Warning "Could not create the optional desktop shortcut: $($_.Exception.Message)" }
    }
    Start-PatchedSkype -Directory $PSScriptRoot
} catch {
    if ($configureRequested) { throw }
    $message = "Skype could not start.`r`n`r`n" + $_.Exception.Message +
        "`r`n`r`nExtract the entire ZIP into a writable local folder and run Start-Skype.cmd again."
    [Console]::Error.WriteLine($message)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        [void][Windows.Forms.MessageBox]::Show($message, 'Open-SkyServer',
            [Windows.Forms.MessageBoxButtons]::OK, [Windows.Forms.MessageBoxIcon]::Error)
    } catch { }
    exit 1
}
