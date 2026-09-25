# Closed Beta Deployment

Updated 2026-09-22. Windows host, experimental Skype 4.2.0.187 only. Do not expose this development protocol implementation to the whole Internet. `global` configures addressing, not a completed NAT/media relay implementation.

## Security Before Moving To A Public IP

The cleaned branch no longer tracks deployment private keys, databases, profiles, diagnostics or build output. Historical commits before cleanup still contained old authority material, so those historical keys remain compromised and must not be reused. A key rotation requires rebuilding every client package. Never send friends server private keys, databases, logs or profile directories. Use separate beta passwords, not passwords used on any other service.

## Build On A New Windows Machine

Install Visual Studio Build Tools with MSBuild and Desktop development with C++
(x86 compiler and Windows SDK), .NET Framework 4.x runtime, Git, and the SQLite
command-line executable. The build script obtains .NET 4.0 reference assemblies
from NuGet if absent. Run from the repository root in PowerShell:

```powershell
$env:SKYSERVER_SQLITE = 'C:\Tools\sqlite3.exe'
powershell -NoProfile -ExecutionPolicy Bypass -File .\server\csharp\build.ps1 -Test
```

The build compiles both native helpers. To deploy without compilers, copy ONLY
`skyserver.exe`, `skype_blob_worker.exe` and `skype_rc4_helper.dll` from
`server/csharp/bin/Release` into the server application directory. Install the
.NET runtime and provide `sqlite3.exe` on that host. Store data and keys
separately; back up the database while the server is stopped.

For an existing community, transfer its keys privately using protected storage.
For a new authority, generate NEW keys (requires OpenSSL for client integrity):

```powershell
.\server\csharp\skyserver-keygen.ps1 -OutputDirectory C:\SkyData\keys `
  -PatcherOutput C:\SkyData\legacy-template.ps1 -ServerIp 192.168.1.101 -ClientIntegrity
```

Do not use the generated legacy-template patcher for packed Skype 4.2. Use the
package workflow below. Existing complete keys are reused, not silently rotated.

## Accounts And Registration

The native Skype registration dialog is NOT supported. No public registration
HTTP endpoint is implemented. Administrators can create working accounts in DB:

```powershell
$server = '.\server\csharp\bin\Release\skyserver.exe'
& $server --db C:\SkyData\skyserver.db --sqlite C:\Tools\sqlite3.exe --init-db
& $server --db C:\SkyData\skyserver.db --sqlite C:\Tools\sqlite3.exe `
  --add-account friend.one 'Friend One' 'REPLACE-WITH-UNIQUE-BETA-PASSWORD'
```

WARNING: `--add-account` is an upsert: an existing login has its password and
display name replaced. Do not use it as unauthenticated registration. Command
arguments may be visible in process inspection/history. Use test-only passwords.
Passwords are stored as salted verifiers, including the legacy login verifier.
Tests cover account creation and valid/invalid native password authentication,
not registration through the original client's UI.

## Local And Global Modes

Local testing, with clients configured for the LAN address:

```powershell
& $server --mode local --host 0.0.0.0 --advertise-ip 192.168.1.101 `
  --real-skype-probe --keys-dir C:\SkyData\keys `
  --db C:\SkyData\skyserver.db --sqlite C:\Tools\sqlite3.exe
```

Closed WAN server (replace example public IP and paths):

```powershell
& $server --mode global --advertise-ip 203.0.113.10 `
  --closed --allowlist C:\SkyData\allowlist.txt `
  --real-skype-probe --keys-dir C:\SkyData\keys `
  --db C:\SkyData\skyserver.db --sqlite C:\Tools\sqlite3.exe
```

`203.0.113.10` is documentation-only. Use your actual public IPv4.
Global defaults to bind `0.0.0.0`; `--host` can select a NIC. `--advertise-ip`
is the address clients see, including in directory replies and UDP IV handling.
Behind NAT, forward the SAME external/internal ports. Hairpin NAT or separate
LAN testing may be necessary; one advertised IP is used for all clients.
The EXE package must have been built for that same address and authority keys.

`--host` no longer changes the API bind. API 33034 stays on `127.0.0.1`;
global mode rejects a non-loopback `--api-host`. Never forward 33034.

Copy `allowlist.example.txt` outside the source tree and replace its entries:

```text
127.0.0.1
203.0.113.25
198.51.100.16/28
```

One IPv4 or CIDR per line, `#` comments. Include each friend's public source IP,
not their private LAN IP. No implicit localhost exemption. `--allowlist` itself
enables filtering; `--closed` additionally requires the file argument. Missing
or invalid file prevents startup; empty file denies everyone. The file is loaded
once: RESTART after editing. Filtering covers auth, API, TCP probes and UDP.
Denied TCP connects are closed before parsing; denied UDP is silently dropped.
This is not an identity mechanism, does not prevent source-IP spoofing, and does
not filter direct peer-to-peer traffic between clients. Apply the same source
restrictions in the machine/provider firewall as a first layer.

Default development listeners to allow/forward only from approved addresses:

| Transport | Ports |
| --- | --- |
| TCP | 80, 443, 12350, 12351, 13392, 33033, 40001-40036 |
| UDP | 12350, 12351, 13392, 33033, 40001-40036 |

These are protocol/probe listeners, not a promise every service is implemented.
80/443 are NOT an HTTPS web site. Check startup logs for bind failures/conflicts.
Do not use `--include-hostcache-probe` for deployment. Additional dynamically
chosen client P2P/media ports are not a server media relay. Cross-NAT audio
remains unimplemented/unverified. Existing TCP sessions from allowed hosts are
bounded (auth 32, API 32, bootstrap 128); this is not a DDoS-resistant service.

## Build A Client Package For Your Address

Only this original SHA256 is supported:
`A2E175CE7C9888C125E2B3D4C2343229832BA0D0CD8A8A1CE120CE92624E856C`.
Install Python 3, Git's OpenSSL or specify its path, then from the repo root:

```powershell
py -3 -m pip install --only-binary=:all: --target patcher/.packages/analysis pefile==2024.8.26 unicorn==2.1.4
py -3 patcher/tools/Inspect-PackedSkype.py --client C:\CleanSkype\Skype.exe --seconds 120 --output patcher/diagnostics/release.image.bin
py -3 patcher/tools/Build-Skype42Lab.py --client C:\CleanSkype\Skype.exe --image patcher/diagnostics/release.image.bin --keys-dir C:\SkyData\keys --server-ip 203.0.113.10 --output-dir patcher/diagnostics/release-client
.\patcher\tools\New-ClientBundle.ps1 -BuildDirectory .\skyserver\diagnostics\release-client -OutputDirectory .\patcher\dist\release-client
```

Use fresh output paths. The first tool reconstructs the packed image offline;
the second replaces known seed/service endpoints and authority moduli, repairs
PE initialization and signs the integrity table. It does not replace arbitrary
IP-looking byte sequences or disable password checks. No private key is needed
on a friend's computer: the operator signs the image before packaging.

The ZIP contains ONLY `Skype.exe`, `skypatch.ps1`, `client.json`. Its manifest pins
the original/patched SHA256 and server IPv4. A checksum detects corruption, not
an attacker replacing both files: obtain packages from a trusted operator.
The package built on 2026-09-22 targets **192.168.1.101**, NOT a public address.
Changing JSON alone cannot retarget the EXE; rebuild for a new address/key pair.

## Friend: Install Or Restore

Download the operator's client ZIP, extract it, close ALL Skype instances and
run in PowerShell (elevated if the installation is in Program Files):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\skypatch.ps1
# Optional explicit locations:
.\skypatch.ps1 -ClientPath C:\CleanSkype\Skype.exe -ProfilePath C:\SkypeBetaProfile
# Roll back EXE; profile data stays intact:
.\skypatch.ps1 -Action Restore -ClientPath C:\CleanSkype\Skype.exe
```

The script finds the usual installation location, accepts only the exact known
original or this exact patched build, preserves the original `.bak` and never
overwrites an unknown backup. No interactive prompts. It also sets directory
routing and disables the client's supernode role. After FIRST login, exit Skype
and run it again: the account-specific search config exists only after login.
Profile XML changes have separate `.skypatch-*.bak` backups for manual restore.
For a custom profile, launch Skype with `/secondary /datapath:"C:\SkypeBetaProfile"`.
No hosts changes or IP redirection are required for this workflow.

Alternatively the packaged EXE is the prepatched executable, but it still needs
the profile settings above. Do not distribute your own initialized profile.

## Publication Status

The allowlisted LAN client ZIP was prepared locally, not published to GitHub.
A Git tag points at a commit; binaries are Release assets. Publication still requires rotating every authority that appeared in old Git history,
rebuilding and retesting clients, then publishing a reviewed tag and Release asset.
The cleaned branch removes those secrets from the current tree but does not rewrite old commits.
