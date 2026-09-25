# Go server

Linux-oriented port of the Open-SkyServer C# reference implementation.

The current Go tree is a **Stage 4.1 parity candidate**. It builds and its unit tests run on Linux, but native Skype 4.2 interoperability must still be validated against the same patched client used for the C# reference server before the C# implementation can be retired.

## Implemented

- the same RSA XML authority set (login RSA-1536 and credentials RSA-2048), including raw private/public operations and self-tests;
- Skype DH-384 handshake and MD5 handshake tags;
- reconstructed RC4 account transport and legacy Skype IV-expanded RC4 for TCP/UDP;
- native RSA/AES login request handling and community credential issuance;
- native account RPCs used by the Stage 4.1 client: login, account email, contact-list index, native document synchronization and directory search;
- experimental Skype 4.2 contact-request queue (0x1784) and inbox poll (0x1780); an empty 0x1781 fetch is supported, but pending inbox-event delivery is not yet implemented;
- the C# SQLite schema and account/contact/profile/message operations;
- the HTTP management/message API and /healthz;
- TCP bootstrap/node sessions, slot-directory replies, signed transient location records and transport acknowledgements;
- UDP bootstrap probes;
- Stage 4.1 deployment controls: --mode local|global, --advertise-ip, --closed and --allowlist;
- graceful SIGINT/SIGTERM shutdown.

The same known Stage 4.1 limitations still apply: native self-registration is not implemented, contact-request acceptance/decline is not yet identified, and cross-NAT media relay is not implemented. A pending 0x1781 fetch currently fails explicitly rather than returning an invented event or marking the request delivered. Native contact authorization is **not** end-to-end. Call/media behavior still depends on the legacy client's direct-connect/NAT behavior.

## Skype 4.2 notification RE checkpoint

Read-only Ghidra analysis of the installed patched 4.2.0.187 executable (SHA-256 `603E4A1612403448C1DCEAFA469B92C23282F2DBA0F35FA2517A57C7AFA895B0`) found:

- Callback `00696D90` rejects statuses other than `0x1450` for `0x1780`/`0x1781`. For `0x1780` it tests `0/2E` for nonzero and then issues `0x1781` with `0/2D` equal to the client's `Lib/Notification/LastID`.
- The `0x1781` response uses `0/2F` as an event count and indexed `5/20` event records. The client reads nested `0/22`, `0/21`, `0/28`, `0/3B`, `0/25`, `0/2A`, `3/26`, and optionally `4/24`. The previous flat `0/2E,3/26,3/27,0/22` response was not consumed by this parser. Field semantics and required signing still need evidence before constructing a nonempty event.
- Startup path `006960C0` can issue a one-off `0x1780` when `Lib/Notification/LastPoll` is stale (the observed comparison uses `0x2A300` seconds, 48 hours). Otherwise it installs the notification listener. Callback `00697570` consumes notification `0/0F` as a high-water mark and schedules `00695D20`, which issues `0x1780` when that mark exceeds `Lib/Notification/LastID`. This explains why storing a request alone does not cause an already-online recipient to poll. The transport and wire envelope that delivers this notification remain to be identified; `0x2B08` may be related but is not yet proven.
- `00696D90` advances `Lib/Notification/LastID` only after processing event records, so receiving a TCP fetch is not evidence of delivery. The database row ID is not the protocol cursor.
- `006C3F40` issues account operation `0x2B08`. Its virtual response callback at `006C4060` checks `status % 1000 == 200` in state 1; other statuses call the failure path `006C41D0`. That callback retains the response fields for later use, so the comparison alone does not establish a valid empty success body or the operation's persistent server-side effect. A two-client live run on 2026-09-25 reproduced `0x2B08` from each client after publishing a location record; the current Go parser rejects it before an account response. Neither client subsequently issued `0x1780`/`0x1781` in that observation window.

The first live interoperability milestone is a real recipient `0x1780` after a server notification, followed by a captured `0x1781` exchange and actual contact-request UI. Unit tests only establish the current server-side invariants, not that milestone.

## Why there are two Linux binaries

The main server is a normal amd64 Go/cgo executable. The historical Skype 0x42 decompressor stores pointers in 32-bit u32 fields, so running it inside the 64-bit server process would truncate pointers.

For compatibility and fault containment, compressed 0x42 lists are normalized by a separate 32-bit helper:

    bin/openskyserver
    bin/skype_blob_worker

The server starts without the worker, but any protocol request containing a compressed 0x42 list that needs decoding will fail until --blob-worker points to it.

## Debian / Ubuntu build

Install the Go compiler, SQLite CLI, C compiler and 32-bit development runtime:

    sudo apt update
    sudo apt install -y golang-go sqlite3 build-essential gcc-multilib libc6-dev-i386

From the repository root:

    cd server/go
    sh ./build-linux.sh

Verify the authority set:

    sudo ./bin/openskyserver --check-keys --keys-dir /etc/openskyserver/keys

## Local compatibility test

Reuse the same database, authority keys and already patched Skype client that work with the C# server. Stop the C# instance first because the listeners overlap.

Example for a LAN server at 192.168.1.101:

    sudo ./bin/openskyserver \
      --host 0.0.0.0 \
      --api-host 127.0.0.1 \
      --advertise-ip 192.168.1.101 \
      --real-skype-probe \
      --keys-dir /etc/openskyserver/keys \
      --db /var/lib/openskyserver/skyserver.db \
      --sqlite /usr/bin/sqlite3 \
      --blob-worker ./bin/skype_blob_worker

For a first migration test, copying the known-good C# skyserver.db is preferable to creating new accounts: the Go database layer intentionally uses the same schema.

## Global mode

Global mode refuses to expose the HTTP API on a non-loopback address and requires the public IPv4 address that the patched client advertises:

    sudo ./bin/openskyserver \
      --mode global \
      --advertise-ip 203.0.113.10 \
      --real-skype-probe \
      --keys-dir /etc/openskyserver/keys \
      --db /var/lib/openskyserver/skyserver.db \
      --sqlite /usr/bin/sqlite3 \
      --blob-worker ./bin/skype_blob_worker

For a closed beta:

    sudo ./bin/openskyserver \
      --mode global \
      --advertise-ip 203.0.113.10 \
      --real-skype-probe \
      --closed \
      --allowlist /etc/openskyserver/allowlist.txt \
      --keys-dir /etc/openskyserver/keys \
      --db /var/lib/openskyserver/skyserver.db \
      --sqlite /usr/bin/sqlite3 \
      --blob-worker ./bin/skype_blob_worker

Do not expose the API port 33034 to the Internet.

## Database commands

The Go executable accepts the management commands needed for a fresh server:

    ./bin/openskyserver --db ./skyserver.db --init-db
    ./bin/openskyserver --db ./skyserver.db --add-account "user" "Display Name" "password"
    ./bin/openskyserver --db ./skyserver.db --set-email "user" "user@example.test"
    ./bin/openskyserver --db ./skyserver.db --add-contact "user" "friend"
    ./bin/openskyserver --db ./skyserver.db --remove-account "user"

## Authority-key model

The public client contains only the public login/credentials authorities and the public integrity authority. The public server needs the login and credentials private keys. The client-integrity private key is a build-time signing key and should not be copied to the public server.
