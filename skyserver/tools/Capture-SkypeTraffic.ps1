[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string[]]$Interfaces,
    [ValidateRange(5,180)][int]$Seconds = 60,
    [string]$WiresharkDirectory = 'C:\Program Files\Wireshark',
    [ValidateRange(1,2147483647)][int]$SkypeProcessId,
    [string]$SharedConfigPath = (Join-Path $env:APPDATA 'Skype\shared.xml'),
    [string]$ServerIp
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$candidates = @(Get-Process Skype -ErrorAction Stop | Where-Object { -not $SkypeProcessId -or $_.Id -eq $SkypeProcessId })
if ($candidates.Count -ne 1) { throw 'Expected exactly one matching Skype.exe. Use -SkypeProcessId when multiple copies are running.' }
$skype = $candidates[0]
$processId = $skype.Id
$started = $skype.StartTime
$dumpcap = Join-Path $WiresharkDirectory 'dumpcap.exe'
if (-not (Test-Path -LiteralPath $dumpcap)) { throw 'dumpcap.exe was not found.' }
foreach ($interface in $Interfaces) {
    if ($interface -notmatch '\A\\Device\\NPF_(?:\{[0-9A-Fa-f-]+\}|Loopback)\z') {
        throw 'Supply stable NPF identifiers from dumpcap -D, not transient interface numbers.'
    }
}

$hosts = New-Object 'Collections.Generic.HashSet[string]'
foreach ($ip in @('193.88.6.13','194.165.188.79','195.46.253.219','193.88.8.59','194.165.188.76','212.8.163.76')) {
    $null = $hosts.Add($ip)
}
$shared = $SharedConfigPath
if (Test-Path -LiteralPath $shared) {
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 1048576
    $reader = [Xml.XmlReader]::Create($shared, $settings)
    try {
        $document = New-Object Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
    } finally { $reader.Dispose() }
    $node = $document.SelectSingleNode('/config/Lib/Connection/HostCache')
    if ($node) {
        $hex = $node.InnerText.Trim()
        if ($hex.Length % 2 -ne 0 -or $hex -notmatch '\A[0-9A-Fa-f]*\z') { throw 'Invalid HostCache encoding.' }
        $bytes = New-Object byte[] ($hex.Length / 2)
        for ($i=0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring(2*$i,2),16) }
        for ($i=0; $i -le $bytes.Length-10; $i++) {
            if ($bytes[$i] -eq 0x41 -and $bytes[$i+1] -eq 5 -and $bytes[$i+2] -eq 2 -and $bytes[$i+3] -eq 0) {
                $null = $hosts.Add(($bytes[($i+4)..($i+7)] -join '.'))
            }
        }
    }
}
$tcp = @(Get-NetTCPConnection -OwningProcess $processId -ErrorAction SilentlyContinue)
$udp = @(Get-NetUDPEndpoint -OwningProcess $processId -ErrorAction SilentlyContinue)
foreach ($connection in $tcp) {
    if ($connection.RemoteAddress -notin @('0.0.0.0','::') -and $connection.RemoteAddress -match '\A[0-9.]+\z') {
        $null = $hosts.Add($connection.RemoteAddress)
    }
}
$terms = New-Object 'Collections.Generic.List[string]'
$terms.Add('tcp port 33033')
if ($ServerIp) {
    $address = [Net.IPAddress]::Parse($ServerIp)
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.Equals([Net.IPAddress]::Any) -or $address.GetAddressBytes()[0] -ge 224) {
        throw 'ServerIp must be a unicast IPv4 address.'
    }
    # A bare host filter for this machine would capture unrelated Internet use.
    $terms.Add('(host ' + $address.ToString() + ' and (port 33033 or port 12350 or port 12351 or port 13392 or port 10100 or port 23456))')
}
$localAddresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object -ExpandProperty IPAddress -Unique)
foreach ($hostIp in ($hosts | Sort-Object)) {
    # A patched HostCache may contain this PC, not a remote peer.
    if ($hostIp -eq $ServerIp -or $hostIp -in $localAddresses -or $hostIp.StartsWith('127.')) { continue }
    $terms.Add('host ' + $hostIp)
}
foreach ($endpoint in $udp) {
    $addresses = if ($endpoint.LocalAddress -eq '0.0.0.0') { $localAddresses } else { @($endpoint.LocalAddress) }
    foreach ($local in $addresses) {
        if ($local -notmatch '\A[0-9.]+\z') { continue }
        $terms.Add('(udp and ((src host ' + $local + ' and src port ' + $endpoint.LocalPort + ') or (dst host ' + $local + ' and dst port ' + $endpoint.LocalPort + ')))')
    }
}
$filter = '(tcp or udp) and (' + ($terms -join ' or ') + ')'

$directory = Join-Path (Split-Path -Parent $PSScriptRoot) ('diagnostics\capture-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'))) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
$null = [IO.Directory]::CreateDirectory($directory,$acl)
$metadata = [pscustomobject]@{ProcessId=$processId;StartUtc=$started.ToUniversalTime().ToString('o');ClientPath=$skype.Path;ClientSha256=(Get-FileHash -LiteralPath $skype.Path).Hash;SharedConfigPath=$shared;ServerIp=$ServerIp;Interfaces=$Interfaces;Filter=$filter;DurationSeconds=$Seconds}
$metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $directory 'capture.json') -Encoding UTF8
$argsList = @('-q','-p','-s','2048')
foreach ($interface in $Interfaces) { $argsList += @('-i', $interface, '-f', ('"' + $filter + '"')) }
$argsList += @('-a', ('duration:'+$Seconds), '-a','filesize:4096','-w',('"'+(Join-Path $directory 'skype.pcapng')+'"'))
$capture = Start-Process -FilePath $dumpcap -ArgumentList $argsList -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $directory 'dumpcap.out.log') -RedirectStandardError (Join-Path $directory 'dumpcap.err.log')
$null = $capture.Handle
$rows = New-Object 'Collections.Generic.List[object]'
Write-Host "Capture started for Skype PID $processId; $Seconds seconds. Repeat the login attempt now."
Write-Host "Protected output: $directory"
try {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds + 15)
    while (-not $capture.HasExited) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Capture did not finish within its duration limit.' }
        $current = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($null -eq $current -or $current.StartTime -ne $started) { throw 'Skype exited or restarted during capture.' }
        $now = [DateTime]::UtcNow.ToString('o')
        foreach ($c in @(Get-NetTCPConnection -OwningProcess $processId -ErrorAction SilentlyContinue)) {
            $rows.Add([pscustomobject]@{Utc=$now;ProcessId=$processId;Protocol='TCP';LocalAddress=$c.LocalAddress;LocalPort=$c.LocalPort;RemoteAddress=$c.RemoteAddress;RemotePort=$c.RemotePort;State=[string]$c.State})
        }
        foreach ($c in @(Get-NetUDPEndpoint -OwningProcess $processId -ErrorAction SilentlyContinue)) {
            $rows.Add([pscustomobject]@{Utc=$now;ProcessId=$processId;Protocol='UDP';LocalAddress=$c.LocalAddress;LocalPort=$c.LocalPort;RemoteAddress='';RemotePort='';State='Bound'})
        }
        Start-Sleep -Milliseconds 500
        $capture.Refresh()
    }
    $capture.WaitForExit()
    if ($null -eq $capture.ExitCode -or $capture.ExitCode -ne 0) {
        throw ('dumpcap failed (exit code ' + $capture.ExitCode + '): ' + (Get-Content -LiteralPath (Join-Path $directory 'dumpcap.err.log') -Raw -Encoding UTF8))
    }
    Write-Host "Capture complete: $directory"
} finally {
    if (-not $capture.HasExited) { $capture.Kill(); $capture.WaitForExit() }
    $rows | Export-Csv -LiteralPath (Join-Path $directory 'skype-sockets.csv') -NoTypeInformation -Encoding UTF8
    $capture.Dispose()
}
