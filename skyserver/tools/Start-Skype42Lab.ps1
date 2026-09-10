[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [string]$Username,
    [string]$Password
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$diagnostics = [IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot -Parent) 'diagnostics')).TrimEnd('\') + '\'
$Directory = [IO.Path]::GetFullPath($Directory)
if (-not $Directory.StartsWith($diagnostics, [StringComparison]::OrdinalIgnoreCase)) { throw 'Only isolated diagnostics builds may be launched.' }
$client = Join-Path $Directory 'Skype.exe'
$manifest = Get-Content -LiteralPath (Join-Path $Directory 'build.json') -Raw | ConvertFrom-Json
if ((Get-FileHash -LiteralPath $client).Hash -ne $manifest.patched_sha256 -or
    (Get-FileHash -LiteralPath ($client + '.bak')).Hash -ne $manifest.original_sha256) { throw 'Lab executable or original backup changed.' }
if ([string]::IsNullOrEmpty($Username) -ne [string]::IsNullOrEmpty($Password)) { throw 'Supply both test username and password, or neither.' }
foreach ($value in @($Username, $Password)) {
    if ($value -match '[\x00-\x20"\\]') { throw 'This lab launcher does not accept whitespace, quotes, or slashes in command-line credentials.' }
}
$profile = Join-Path $Directory 'profile'
if (-not (Test-Path -LiteralPath $profile)) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'))) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    $null = [IO.Directory]::CreateDirectory($profile, $acl)
}
$shared = Join-Path $profile 'shared.xml'
if (-not (Test-Path -LiteralPath $shared)) {
    $settings = New-Object Xml.XmlWriterSettings
    $settings.Indent = $true
    $writer = [Xml.XmlWriter]::Create($shared, $settings)
    try {
        $writer.WriteStartDocument()
        $writer.WriteStartElement('config')
        $writer.WriteAttributeString('version', '1.0')
        $writer.WriteStartElement('Lib')
        $writer.WriteStartElement('Connection')
        $writer.WriteElementString('DisableSupernode', '1')
        $writer.WriteElementString('ForceSupernode', '0')
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteEndDocument()
    } finally { $writer.Dispose() }
}
$arguments = @('/secondary', ('/datapath:"{0}"' -f $profile))
if ($Username) {
    # These native CLI switches are present in the exact 4.2 command parser.
    # Test accounts only: Windows process inspection can expose command-line args.
    $arguments += @(('/username:' + $Username), ('/password:' + $Password))
    Write-Warning 'Using native command-line login for a test account; do not use a real password.'
}
$process = Start-Process -FilePath $client -ArgumentList $arguments -WorkingDirectory $Directory -PassThru
[pscustomobject]@{ProcessId=$process.Id;ClientPath=$client;ProfilePath=$profile;CliLoginRequested=[bool]$Username}
