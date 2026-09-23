# Go server

Linux-oriented port of the Open-SkyServer C# reference implementation.

The current Go tree is a **Stage 4.1 parity candidate**. It builds and its unit tests run on Linux, but native Skype 4.2 interoperability must still be validated against the same patched client used for the C# reference server before the C# implementation can be retired.

## Implemented

- the same RSA XML authority set (login RSA-1536 and credentials RSA-2048), including raw private/public operations and self-tests;
- Skype DH-384 handshake and MD5 handshake tags;
- reconstructed RC4 account transport and legacy Skype IV-expanded RC4 for TCP/UDP;
- native RSA/AES login request handling and community credential issuance;
- native account RPCs used by the Stage 4.1 client: login, account email, contact-list index, native document synchronization and directory search;
- experimental Skype 4.2 contact-request/inbox RPCs: 0x1784 request queue plus 0x1780 poll and 0x1781 fetch;
- the C# SQLite schema and account/contact/profile/message operations;
- the HTTP management/message API and /healthz;
- TCP bootstrap/node sessions, slot-directory replies, signed transient location records and transport acknowledgements;
- UDP bootstrap probes;
- Stage 4.1 deployment controls: --mode local|global, --advertise-ip, --closed and --allowlist;
- graceful SIGINT/SIGTERM shutdown.

The same known Stage 4.1 limitations still apply: native self-registration is not implemented, contact-request acceptance/decline is not yet identified, and cross-NAT media relay is not implemented. The 0x1784/0x1780/0x1781 contact inbox wire shape is an experimental reconstruction from live 4.2 captures plus the historical skycontact4 flow and must be validated against the real client. Call/media behavior therefore still depends on the legacy client's direct-connect/NAT behavior.

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
