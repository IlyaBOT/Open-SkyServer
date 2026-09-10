[CmdletBinding()]
param([Parameter(Mandatory=$true)][int]$SkypeProcessId)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$process = Get-Process -Id $SkypeProcessId
$root = [IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot -Parent) 'diagnostics')).TrimEnd('\') + '\'
if ($process.ProcessName -ne 'Skype' -or -not $process.Path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Only an isolated lab Skype process can be inspected.'
}
$directory = Split-Path $process.Path -Parent
$manifest = Get-Content -LiteralPath (Join-Path $directory 'build.json') -Raw | ConvertFrom-Json
if ((Get-FileHash -LiteralPath $process.Path).Hash -ne $manifest.patched_sha256) { throw 'Client hash changed.' }
Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
public static class SkypeLabWindow {
    [StructLayout(LayoutKind.Sequential)] struct Rect { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr window, IntPtr dc, uint flags);
    public static void Capture(IntPtr window, uint expectedProcess, string path) {
        uint process; Rect rect;
        GetWindowThreadProcessId(window, out process);
        if (process != expectedProcess || !IsWindowVisible(window) || !GetWindowRect(window, out rect))
            throw new InvalidOperationException("Target window is not visible or changed owner.");
        int width = rect.Right - rect.Left, height = rect.Bottom - rect.Top;
        if (width < 1 || height < 1 || width > 4096 || height > 4096)
            throw new InvalidOperationException("Unexpected window size.");
        using (var bitmap = new Bitmap(width, height)) {
            using (var graphics = Graphics.FromImage(bitmap)) {
                var dc = graphics.GetHdc();
                try { if (!PrintWindow(window, dc, 2)) throw new InvalidOperationException("PrintWindow failed."); }
                finally { graphics.ReleaseHdc(dc); }
            }
            bitmap.Save(path, ImageFormat.Png);
        }
    }
}
'@
# PrintWindow reads only the target window; no activation, input, or desktop capture.
$output = Join-Path $directory ('profile\window-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.png')
[SkypeLabWindow]::Capture($process.MainWindowHandle, $process.Id, $output)
Write-Output $output
