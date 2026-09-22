param([Parameter(Mandatory=$true)][string]$Bundle,[Parameter(Mandatory=$true)][string]$Original,[Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a new test directory.' }
$null = New-Item -ItemType Directory -Path $OutputDirectory
$client = Join-Path $OutputDirectory 'Skype.exe'
$profile = Join-Path $OutputDirectory 'profile'
Copy-Item -LiteralPath $Original -Destination $client
$originalHash = (Get-FileHash -LiteralPath $client).Hash
$manifest = Get-Content -LiteralPath (Join-Path $Bundle 'client.json') -Raw | ConvertFrom-Json
$patcher = Join-Path $Bundle 'skypatch.ps1'
& $patcher -ClientPath $client -ProfilePath $profile
if ((Get-FileHash -LiteralPath $client).Hash -ne $manifest.patched_sha256) { throw 'Patch failed.' }
$account = Join-Path $profile 'test-account'
$null = New-Item -ItemType Directory -Path $account
$xml = New-Object Xml.XmlDocument
$xml.LoadXml('<config><Unrelated>preserve</Unrelated></config>')
$xml.Save((Join-Path $account 'config.xml'))
& $patcher -ClientPath $client -ProfilePath $profile
$xml.Load((Join-Path $account 'config.xml'))
if ($xml.SelectSingleNode('/config/Lib/ContactSearch/ForceServer').InnerText -ne '1' -or
    $xml.SelectSingleNode('/config/Unrelated').InnerText -ne 'preserve') { throw 'Account search config failed.' }
if ((Get-FileHash -LiteralPath ($client + '.bak')).Hash -ne $originalHash) { throw 'Backup changed.' }
& $patcher -Action Restore -ClientPath $client -ProfilePath $profile
if ((Get-FileHash -LiteralPath $client).Hash -ne $originalHash) { throw 'Restore failed.' }
$names = @(Get-ChildItem -LiteralPath $Bundle -File | Select-Object -ExpandProperty Name | Sort-Object)
if ($names.Count -ne 3 -or @(Compare-Object $names @('client.json','Skype.exe','skypatch.ps1')).Count) { throw 'Unexpected package contents.' }
Write-Host 'PASS patch, repeated patch, backup hash, restore, package allowlist.'
