param(
    [string]$ServerExe = (Join-Path $PSScriptRoot "bin\Release\skyserver.exe"),
    [string]$Database = (Join-Path $PSScriptRoot "bin\Release\skyserver.db")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

& $ServerExe --db $Database --init-db

& $ServerExe --db $Database --add-account "admindev@test.lol" "Admin" "AdminDev"
& $ServerExe --db $Database --add-account "second@test.lol" "Test Second Accout" "SecondTest"

& $ServerExe --db $Database --set-email "admindev@test.lol" "admindev@test.lol"
& $ServerExe --db $Database --set-email "second@test.lol" "second@test.lol"

& $ServerExe --db $Database --add-contact "admindev@test.lol" "second@test.lol"
& $ServerExe --db $Database --add-contact "second@test.lol" "admindev@test.lol"

Write-Host "Demo accounts created in $Database"
