[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [string[]]$ProfileNames = @('profile','profile-second'),
    [string]$SqlitePath = 'C:\platform-tools\sqlite3.exe'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$root = [IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot -Parent) 'diagnostics')).TrimEnd('\') + '\'
$Directory = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
if (-not $Directory.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw 'Only isolated lab profiles may be inspected.' }

function Get-StatusName($value) {
    if ($null -eq $value) { return 'Unset' }
    # Skype 4.2 VA 00666240/006663C0/00664D50. Internal states must not
    # be confused with values accepted by SET USERSTATUS.
    switch ([int]$value) {
        1 { 'Offline' }
        2 { 'Online' }
        3 { 'Away' }
        4 { 'NotAvailable' }
        5 { 'DoNotDisturb' }
        6 { 'Invisible' }
        8 { 'OfflineLikeInternal8' }
        default { 'Internal(' + $value + ')' }
    }
}

$query = @'
SELECT 'account' AS kind,skypename,availability,status AS account_state,
       set_availability AS requested_status,NULL AS buddy_status,NULL AS authorized,NULL AS blocked
FROM Accounts
UNION ALL
SELECT 'contact',skypename,availability,NULL,NULL,buddystatus,isauthorized,isblocked
FROM Contacts WHERE buddystatus>1
ORDER BY kind,skypename LIMIT 256;
'@
foreach ($name in $ProfileNames) {
    if ($name -notmatch '\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\z') { throw 'Invalid lab profile name.' }
    $profile = Join-Path $Directory $name
    $item = Get-Item -LiteralPath $profile
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked profiles are not supported.' }
    foreach ($account in @(Get-ChildItem -LiteralPath $profile -Directory)) {
        if ($account.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        $path = Join-Path $account.FullName 'main.db'
        if (-not (Test-Path -LiteralPath $path)) { continue }
        if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked databases are not supported.' }
        $json = & $SqlitePath -readonly -json -cmd '.timeout 2000' $path $query
        if ($LASTEXITCODE -ne 0) { throw ('Presence inspection failed for ' + $name) }
        $rows = ($json -join "`n") | ConvertFrom-Json
        foreach ($row in $rows) {
            [pscustomobject]@{
                Utc = [DateTime]::UtcNow.ToString('o')
                Profile = $name
                Kind = $row.kind
                Login = $row.skypename
                Availability = $row.availability
                StatusName = Get-StatusName $row.availability
                RequestedStatus = $row.requested_status
                RequestedName = Get-StatusName $row.requested_status
                AccountState = $row.account_state
                BuddyStatus = $row.buddy_status
                Authorized = $row.authorized
                Blocked = $row.blocked
            }
        }
    }
}
