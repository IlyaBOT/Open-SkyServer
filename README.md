# Open-SkyServer

**Stage 4.1 status:** patched Skype 4.2 login, contact synchronization, directory search, presence, messages and call signaling are working in the C# reference implementation. Native self-registration and cross-NAT media relay remain incomplete. See `server/csharp/DEPLOYMENT.md` and `server/csharp/CALL_AUDIO.md`.

Open-source reverse engineering of the classic Skype protocol, a compatible community server, and tooling for patching supported legacy clients.

## Repository layout

- `server/csharp/` — primary server implementation. C# / .NET Framework 4.0.
- `server/native/` — native C helpers used by the C# implementation.
- `server/go/` — Linux-oriented Stage 4.1 parity port. Auth, account RPCs, SQLite data model, HTTP API, TCP bootstrap/node transport and UDP bootstrap are implemented; live patched-client validation is still required before replacing the C# reference server.
- `patcher/` — client patching, integrity tooling and release staging.
- `skypeopensource2/`, `skypeproto/` — historical reverse-engineering source material retained for development.

## Keys

Private deployment keys are generated locally into `server/csharp/keys/` and are ignored by Git.

```powershell
.\server\csharp\skyserver-keygen.ps1 -ClientIntegrity -ServerIp 203.0.113.10
```

The generator creates/reuses the server key set under `server/csharp/keys/` and emits the public-only patcher as `patcher/dist/skypatch.ps1`.

Never commit or distribute `*.private.xml` or `*.private.pem`. Any authority key that has previously appeared in repository history must be considered compromised and rotated before an Internet-facing deployment.

## C# server

The production/reference implementation targets .NET Framework 4.0 and uses native C helpers.

```powershell
.\server\csharp\build.ps1 -Test
.\server\csharp\bin\Release\skyserver.exe --host 0.0.0.0 --api-host 127.0.0.1 --real-skype-probe
```

The server checks `SKYSERVER_KEYS_DIR` / `--keys-dir` first and otherwise looks for a `keys` directory next to the executable or in the project directory.

## Go server

See server/go/README.md for the Debian build and migration procedure.

    cd server/go
    sh ./build-linux.sh
    sudo ./bin/openskyserver --check-keys --keys-dir /etc/openskyserver/keys

The Go implementation now covers the Stage 4.1 server surface, but must still pass live native-client interoperability testing before it replaces the C# reference implementation.

## Demo Accounts

```
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 --add-account "admindev@test.lol" "Admin Dev" "AdminDev"
```
```
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 --set-email "admindev@test.lol" "admindev@test.lol"
```
Created accounts:

- `admindev@test.lol` / AdminDev, display name Admin
- `second@test.lol` / SecondTest, display name Test Second Accout

## Patcher and releases

`patcher/client/` is intentionally empty in Git. Put a locally built/patched client there when preparing a tag/release. Proprietary Skype executables and deployment secrets are not tracked in the source repository.

Generated patch scripts go to `patcher/dist/`.
