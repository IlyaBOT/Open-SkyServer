# skyserver

Community test server for the reconstructed Epycs/Skype client path.

**Native lab status (2026-09-19): login and contact-list synchronization work in
the isolated patched Skype 4.2 client. Directory search is under verification;
contact invitations, native chat and full profile editing remain unfinished.**
See [the current checkpoint](NATIVE_CLIENT_CHECKPOINT.md) for native launch
commands, evidence, backups and protocol notes. The instructions below primarily
describe the reconstructed client and older probe experiments.

The server has two listeners:

- `33033`: reconstructed Skype auth transport with DH-384 and RC4.
- `33034`: local HTTP API for accounts, contacts, profiles, messages, and history.

Data is stored in SQLite (`skyserver.db` next to `skyserver.exe` by default). The server expects `sqlite3.exe` in `PATH`, or a custom path in `SKYSERVER_SQLITE` / `--sqlite`.

## Build

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\skyserver\build.ps1 -Test
```

## Demo Accounts

```powershell
powershell -ExecutionPolicy Bypass -File skyserver\create_demo_acc.ps1
```

Created accounts:

- `admindev@test.lol` / `AdminDev`, display name `Admin`
- `second@test.lol` / `SecondTest`, display name `Test Second Accout`

Remove them:

```powershell
powershell -ExecutionPolicy Bypass -File skyserver\remove_demo_acc.ps1
```

## Run

```powershell
.\skyserver\bin\Release\skyserver.exe --host 127.0.0.1 --port 33033 --api-port 33034
```

Point the client at it:

```powershell
$env:SKYAUTH_HOST = "127.0.0.1"
$env:SKYAUTH_PORT = "33033"
$env:SKYSERVER_HOST = "127.0.0.1"
$env:SKYSERVER_API_PORT = "33034"
```

The auth DLL sends a local RC4-protected credential frame after the reconstructed login packets. The server validates that frame against SQLite before returning the success frame expected by this repo's `skyauth4_dll`.

## Stock Skype Probe (Not Native Authentication)

Direct-IP redirection is now authorized for local development. See
[IP redirection](IP_REDIRECT.md) for the reversible Windows implementation and
[cryptographic compatibility](CRYPTO_COMPATIBILITY.md) for the remaining login work.

Inspect the current IP list:

```powershell
.\skyserver\skype_ip_redirect.ps1 -Action Plan
```

Enable from an Administrator PowerShell, then start one server instance:

```powershell
.\skyserver\skype_ip_redirect.ps1 -Action Enable
.\skyserver\bin\Release\skyserver.exe --host 0.0.0.0 --api-host 127.0.0.1 --real-skype-probe --include-hostcache-probe
```

The redirect uses temporary IPv4 loopback aliases for known Skype destinations,
including addresses read from HostCache. It does not edit hosts or the client.
It covers TCP and UDP for those IPs across all processes; unknown destinations
need to be added to the list. Protocol listeners must accept the aliased addresses,
while the custom HTTP API remains on 127.0.0.1.

Inspect/undo:

```powershell
.\skyserver\skype_ip_redirect.ps1 -Action Status
.\skyserver\skype_ip_redirect.ps1 -Action Disable
```

The ownership journal preserves pre-existing aliases and interface settings.
Old loopback on/off entry points delegate to the journaled implementation; they
do not guess which unjournaled addresses can be removed.

Probe mode is not native Skype authentication. After the outer login records, it
logs `auth stock unsupported` and closes without a fabricated success or a DB
session. Native AES/RSA credentials, registration, profiles and contacts are not
implemented. The compatibility response is sent only after DB password validation
for the reconstructed auth DLL.

HostCache bootstrap and client supernode promotion are different functions.
Clearing HostCache does not disable promotion and can prevent bootstrap.
The profile-editing HostCache scripts are retained as old experiments, not part
of the current redirect procedure.
