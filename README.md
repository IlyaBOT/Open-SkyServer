# Open-SkyServer

| English | Русский |
| --- | --- |
| [Read in English](README.md) | [Читать на русском](README-ru.md) |

A community server for classic Skype. We currently work with **Skype 4.2.0.187 for Windows**: reverse engineering its protocol, rebuilding the server side, and testing it with the real client.

Most development focuses on the Go server for Linux. The C# version remains in the repository as a reference. The client connects to our network after its server addresses and public keys are replaced. Editing `hosts` alone is not enough.

## Current Progress

| Feature | Status |
| --- | --- |
| Sign-in and registration from Skype | Tested with the Go server, including sign-in from a fresh local profile. |
| User search | Works through the server directory. |
| Contact list loading | Tested with existing contact documents. The full request, accept, and reject flow is not finished yet. |
| Text messages | Two clients on the same PC exchanged messages directly over P2P. Delivery across different NATs and a server-side queue have not been confirmed. |
| Presence | Updates between contacts, but with delays, especially when switching to "Invisible" or "Offline". |
| Calls | Call initiation and acceptance have been observed. Audio has not been confirmed, and a complete media relay is not available. |
| Profile and avatar | Some fields are restored from the server. Full profile synchronization and avatar loading into a fresh profile do not work yet. |
| Online counter | Not restored yet. It should count Online, Away, and DND, excluding Invisible and Offline. |

The main task now is connecting clients in different networks. A working local chat does not mean Internet connectivity is ready. See [WAN_CHECKPOINT.md](server/go/WAN_CHECKPOINT.md) for details and the next test plan.

## Connect a Client

### Ready-to-Run Portable Archive

If the server operator provides an `OpenSky-Skype-4.2.0.187-Portable-*.zip` archive, no installation or patching is needed. Extract the entire archive into a normal writable folder and run `Start-Skype.cmd`. Windows 10/11 and Windows PowerShell 5.1 are required; Python is not. On first launch, a **Skype 4.2.0.187 Patched** desktop shortcut is created unless one already exists.

Sign in with your account on our server. The archive contains no saved login, other users' history, or private keys. Your profile lives in the `profile` folder next to the client. Do not share that folder after using it: distribute the original ZIP instead. Launch through the CMD file or its desktop shortcut, not `Skype.exe` directly: the helper selects the isolated profile and maintains directory-search settings.

The server address and public keys are already embedded in the client. Each archive only works with the network it was built for. It does not change `hosts`, routes, the firewall, or an installed Skype. Server-side limitations, including unfinished support for different NATs, still apply.

### Patch Your Own EXE

You need Windows, Windows PowerShell 5.1, Python 3, and an original `Skype.exe` version 4.2.0.187. The patcher's first run requires Internet access to download two Python modules. They are installed inside the patcher folder.

1. Get a ZIP patch package from the server operator. It must be built for that server's address and keys. The source checkout does not include a ready-made `community.patch.json`.
2. Extract the archive into a normal writable folder.
3. Run `Patch-Skype.cmd` and select the original `Skype.exe`. You can also drag the EXE onto that CMD file.
4. Wait for patching to finish, then open the **Skype 4.2.0.187 Patched** desktop shortcut.

The patcher creates a separate folder containing the client, an exact `Skype.exe.bak` backup, and a fresh profile. It does not modify the selected source file. The shortcut starts the client through a helper that configures directory search and watches for account settings after the first sign-in. Settings files are updated automatically; whether Skype picks up these changes during the first session still needs verification.

Only the original EXE with this SHA-256 is supported:

```text
A2E175CE7C9888C125E2B3D4C2343229832BA0D0CD8A8A1CE120CE92624E856C
```

Other 4.2 builds, Skype 4.4, and Skype 5.5 are not supported by this patcher. Ready-made packages are not published automatically with the source. Instructions for building your own package are below and in the [patcher documentation](patcher/README.md).

## Set Up the Server

The example below targets Debian or Ubuntu on x86-64. You need Go 1.22 or newer, GCC with 32-bit build support, and the SQLite CLI. Check `go version`: older distributions may ship an outdated Go package.

```sh
sudo apt update
sudo apt install -y golang-go sqlite3 build-essential gcc-multilib libc6-dev-i386 file

git clone https://github.com/IlyaBOT/Open-SkyServer.git
cd Open-SkyServer/server/go
sh ./build-linux.sh
```

The build produces two files: `bin/openskyserver` and `bin/skype_blob_worker`. The latter is a separate 32-bit decoder for protocol lists. Both are needed for the client to work.

### Keys and Database

The server must use the keys for the same network as the client patch. For a new network, generate them on Windows first by following "Prepare a Patch Package" below. For an existing server, reuse its keys.

```sh
sudo install -d -m 700 /etc/openskyserver/keys /var/lib/openskyserver
```

Copy these four files into `/etc/openskyserver/keys`: `login.private.xml`, `login.public.xml`, `credentials.private.xml`, and `credentials.public.xml`. Restrict access to the private files. The `client-integrity` key is only needed on the patcher build machine; it does not need to be copied to the server.

Check the keys and initialize the database:

```sh
sudo ./bin/openskyserver --check-keys --keys-dir /etc/openskyserver/keys
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 --init-db
```

### Two Test Accounts

For a quick contact test, create two accounts and add them to each other's contact lists. Run these commands from `server/go`, using the same database as the server:

```sh
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --add-account "admindev@test.lol" "Admin" "AdminDev"
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --set-email "admindev@test.lol" "admindev@test.lol"

sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --add-account "second@test.lol" "Test Second Account" "SecondTest"
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --set-email "second@test.lol" "second@test.lol"

sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --add-contact "admindev@test.lol" "second@test.lol"
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --add-contact "second@test.lol" "admindev@test.lol"
```

| Login | Test Password |
| --- | --- |
| admindev@test.lol | AdminDev |
| second@test.lol | SecondTest |

These are public test credentials, not passwords for regular accounts. Running `--add-account` again changes the existing account's password and display name. Adding mutual contacts through the database is useful for testing communication, but the normal contact-request flow from the client needs separate testing.

You can remove the accounts after testing:

```sh
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 --remove-account "admindev@test.lol"
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 --remove-account "second@test.lol"
```

You can also register from Skype. Accounts created this way do not have a password in the HTTP API's format: client sign-in works, but plain-password API sign-in is not supported for them.

### Start the Server for Internet Testing

Our test server uses public address `176.101.124.66` and LAN address `192.168.1.170`. For your own deployment, replace the public IP in the command and rebuild the client patch for it.

Create `/etc/openskyserver/allowlist.txt` and list testers' public IPs, one per line. IPv4 addresses, CIDR subnets, and `#` comments are supported. An empty file denies all connections. Restart the server after changing the list.

From `server/go`:

```sh
sudo ./bin/openskyserver \
  --mode global --host 0.0.0.0 --advertise-ip 176.101.124.66 \
  --real-skype-probe \
  --closed --allowlist /etc/openskyserver/allowlist.txt \
  --keys-dir /etc/openskyserver/keys \
  --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --blob-worker ./bin/skype_blob_worker
```

If the server is behind a router, forward these ports to it. External and internal port numbers must match:

| Protocol | Ports |
| --- | --- |
| TCP | 80, 443, 12350, 12351, 13392, 33033, 40001-40036 |
| UDP | 12350, 12351, 13392, 33033, 40001-40036 |

The HTTP API listens on `127.0.0.1:33034`. Do not expose or forward it to the Internet. Ports 80 and 443 carry the legacy Skype protocol here, not a website.

Clients on the same LAN that use the public server IP need router NAT loopback. Use `--hairpin-source` only for the specific router address that replaces the connection's source address. Without it, the server preserves the client's observed source address. The `--mode global` flag does not add a relay or guarantee NAT traversal.

For LAN-only testing, use `--mode local --host 0.0.0.0 --advertise-ip 192.168.1.170` and a client patch built for that LAN address.

## Prepare a Patch Package

The server operator does this on Windows. Python 3, Windows PowerShell 5.1, and OpenSSL are required. OpenSSL from Git for Windows is used by default; pass `-OpenSslPath` to select another executable.

From the repository root, for a new network:

```powershell
.\patcher\tools\New-CommunityPatch.ps1 `
  -ClientPath C:\CleanSkype\Skype.exe `
  -KeysDirectory C:\SkyData\keys `
  -ServerIp 176.101.124.66 `
  -OutputDirectory .\patcher\dist\community `
  -GenerateKeys
```

For an existing server, point to its key directory and omit `-GenerateKeys`. Complete existing key sets are reused. Changing the server address requires rebuilding the package. The output folder must be new.

The script creates a `community` folder and a `community.zip` archive. Distribute the ZIP: it contains tools and public changes for the exact original EXE. It contains no private keys, profiles, or complete Skype client. Store key backups separately. If keys ever appeared in public Git history, replace them and rebuild the client packages before a public deployment.

### Build a Ready-to-Run Portable Client

If you already have a folder created by `Patch-Skype.ps1`, you can package a full ZIP that needs neither Python nor installation on the user's machine:

```powershell
.\patcher\tools\New-PortableClientBundle.ps1 `
  -ClientDirectory .\patcher\client\Skype-4.2.0.187-WAN `
  -OutputDirectory .\patcher\dist\OpenSky-Skype-4.2.0.187-Portable
```

The output directory must be new. A ZIP and its `.sha256` file are created alongside it. The builder verifies the EXE and original `.bak`, includes only explicitly listed files, and creates clean settings. Even if the source folder has been used to sign in, its profile, databases, logs, and keys are not copied into the archive. This is a complete client package, not the ZIP patcher described above. Binaries and generated archives stay out of Git.

## Debugging

Add `--detailed-debug` to the server command for verbose logging. On Linux, save output with `2>&1 | tee skyserver.log`. Check key-loading and port-binding messages first: a port-binding failure can leave some services unavailable.

We use two isolated Skype profiles to test the protocol. Local testing helps reproduce bugs, but WAN testing needs a second PC on another network, such as a mobile connection. Test sign-in, search, contact requests, presence, messaging, and calls in that order. Record the time of each action so it can be matched to the logs.

If Wireshark is installed, list interfaces with:

```powershell
& 'C:\Program Files\Wireshark\dumpcap.exe' -D
Get-Process Skype | Select-Object Id, Path
```

Use [Capture-SkypeTraffic.ps1](patcher/tools/Capture-SkypeTraffic.ps1) to capture a specific client's traffic. Supply its PID, the NPF interface ID from `dumpcap -D`, the path to `profile\shared.xml`, and the server IP:

```powershell
.\patcher\tools\Capture-SkypeTraffic.ps1 `
  -SkypeProcessId 1234 -Interfaces '\Device\NPF_{INTERFACE_GUID}' `
  -SharedConfigPath 'C:\SkypePatched\profile\shared.xml' `
  -ServerIp 176.101.124.66 -Seconds 60
```

Replace the PID, interface, and path with your own values. For messaging and calls, capture traffic at both ends. Logs, captures, and databases may contain account data; do not add them to the public repository.

After building the Go server, run from `server/go`:

```sh
SKYSERVER_BLOB_WORKER="$PWD/bin/skype_blob_worker" go test ./...
```

Run patcher checks from the repository root:

```powershell
python -m unittest discover -s patcher/tests -p test_client_patch.py -v
powershell -NoProfile -ExecutionPolicy Bypass -File .\patcher\tests\Test-PublicPatch.ps1
```

Tools for isolated lab profiles, presence inspection, and client builds remain in `patcher/tools`. Build the C# reference with `server/csharp/build.ps1 -Test`; Visual Studio and native helper requirements are covered in the [C# server deployment guide](server/csharp/DEPLOYMENT.md).

## Repository Layout

- [server/go](server/go/README.md) - Linux server and implementation details.
- [server/csharp](server/csharp/README.md) - C# reference and earlier experiments.
- `server/native` - native protocol helpers.
- [patcher](patcher/README.md) - user-facing patcher and build tools.
- `skypeopensource2`, `skypeproto` - source material and earlier protocol research.
- [WAN_CHECKPOINT.md](server/go/WAN_CHECKPOINT.md) - verified results and remaining WAN work.
- [CALL_AUDIO.md](server/csharp/CALL_AUDIO.md) - analysis of missing call audio and the call test plan.

Some older reports describe the state at the time of an experiment. The current overview is in this README and the WAN checkpoint. Skype binaries, keys, databases, and profiles are not included in the source checkout.
