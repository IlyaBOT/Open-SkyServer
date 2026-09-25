param(
    [string]$ServerExe = (Join-Path $PSScriptRoot "bin\Release\skyserver.exe"),
    [string]$Database = (Join-Path $PSScriptRoot "bin\Release\skyserver.db")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

& $ServerExe --db $Database --init-db
& $ServerExe --db $Database --remove-account "admindev@test.lol"
& $ServerExe --db $Database --remove-account "second@test.lol"

Write-Host "Demo accounts removed from $Database"
