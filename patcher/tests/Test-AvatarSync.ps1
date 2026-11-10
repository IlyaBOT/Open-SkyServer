[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ClientDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$patcher = Split-Path -Parent $PSScriptRoot
$root = Join-Path ([IO.Path]::GetTempPath()) ('OpenSky-AvatarSettings-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'profile\test-account'))
foreach ($name in @('Skype.exe','Skype.exe.bak','client.json')) {
    [IO.File]::Copy((Join-Path $ClientDirectory $name), (Join-Path $root $name))
}
[IO.File]::Copy((Join-Path $patcher 'Launch-Skype.ps1'), (Join-Path $root 'Launch-Skype.ps1'))
$account = Join-Path $root 'profile\test-account\config.xml'
[IO.File]::WriteAllText($account, '<config><Unrelated>preserve</Unrelated></config>')
$before = (Get-FileHash -LiteralPath (Join-Path $root 'Skype.exe')).Hash
$helper = Join-Path $patcher 'tools\Set-SkypeAvatarSync.ps1'
foreach ($enabled in @('1','1','0')) {
    & $helper -Directory $root -Enabled $enabled
    foreach ($path in @($account, (Join-Path $root 'profile\shared.xml'))) {
        $xml = [Xml.XmlDocument]::new()
        $xml.Load($path)
        if ($xml.SelectSingleNode('/config/Lib/CentralStorage/SyncAvatar').InnerText -cne $enabled) {
            throw "Avatar setting mismatch: $path"
        }
    }
}
$xml = [Xml.XmlDocument]::new()
$xml.Load($account)
if ($xml.SelectSingleNode('/config/Unrelated').InnerText -cne 'preserve') { throw 'Unrelated settings changed' }
if ((Get-FileHash -LiteralPath (Join-Path $root 'Skype.exe')).Hash -cne $before) { throw 'Client was modified' }
if ([IO.File]::ReadAllText($account + '.opensky.bak') -cne '<config><Unrelated>preserve</Unrelated></config>') {
    throw 'The initial account XML backup was not preserved'
}
$clients = @(Get-CimInstance Win32_Process -Filter "Name = 'Skype.exe'" | Where-Object {
    $_.ExecutablePath -eq (Join-Path $root 'Skype.exe')
})
if ($clients.Count) { throw 'The configuration helper started a client' }
Write-Host "PASS shared/account enable, repeated enable, disable, unrelated XML, exact backup, unchanged EXE and no client launch. Artifacts: $root"
