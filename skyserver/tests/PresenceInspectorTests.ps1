$ErrorActionPreference = 'Stop'
$server = Split-Path $PSScriptRoot -Parent
$directory = Join-Path $server ('diagnostics\presence-inspector-test-' + [Guid]::NewGuid().ToString('N'))
$account = Join-Path $directory 'profile\fixture'
$null = New-Item -ItemType Directory -Path $account
$db = Join-Path $account 'main.db'
$sqlite = 'C:\platform-tools\sqlite3.exe'
$schema = @'
CREATE TABLE Accounts(skypename TEXT,availability INTEGER,status INTEGER,set_availability INTEGER);
CREATE TABLE Contacts(skypename TEXT,availability INTEGER,buddystatus INTEGER,isauthorized INTEGER,isblocked INTEGER);
INSERT INTO Accounts VALUES('fixture.owner',6,7,6);
INSERT INTO Contacts VALUES('offline',1,2,1,0),('online',2,2,1,0),('away',3,2,1,0),
 ('legacy-na',4,2,1,0),('busy',5,2,1,0),('invisible',6,2,1,0),('internal',8,2,1,0),
 ('not-a-buddy',2,0,0,0);
'@
& $sqlite $db $schema
if ($LASTEXITCODE -ne 0) { throw 'Fixture creation failed.' }
$before = (Get-FileHash -LiteralPath $db).Hash
$inspector = Join-Path $server 'tools\Get-Skype42Presence.ps1'
$rows = @(& $inspector -Directory $directory -ProfileNames @('profile') -SqlitePath $sqlite)
if ($rows.Count -ne 8) { throw 'Wrong number of presence rows.' }
$owner = $rows | Where-Object { $_.Kind -eq 'account' }
if ($owner.StatusName -ne 'Invisible' -or $owner.RequestedName -ne 'Invisible' -or $owner.AccountState -ne 7) {
    throw 'Requested status and account state were conflated.'
}
$expected = @{ offline='Offline'; online='Online'; away='Away'; 'legacy-na'='NotAvailable'; busy='DoNotDisturb'; invisible='Invisible'; internal='OfflineLikeInternal8' }
foreach ($row in @($rows | Where-Object { $_.Kind -eq 'contact' })) {
    if ($row.StatusName -ne $expected[$row.Login] -or $null -ne $row.RequestedStatus) { throw 'Incorrect contact status mapping.' }
}
if ((Get-FileHash -LiteralPath $db).Hash -ne $before) { throw 'Inspector modified the database.' }
$rejected = $false
try { & $inspector -Directory $directory -ProfileNames @('..') -SqlitePath $sqlite | Out-Null }
catch { $rejected = $true }
if (-not $rejected) { throw 'Traversal profile accepted.' }
Write-Output 'PASS presence inspector: status mapping, nullable fields, multiple rows, account/contact separation, read-only hash and profile boundary.'
