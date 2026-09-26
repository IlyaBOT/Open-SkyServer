# Go server

Linux-oriented port of the Open-SkyServer C# reference implementation.

The current Go tree is a **Stage 4.1 parity candidate**. It builds and its unit tests run on Linux, but native Skype 4.2 interoperability must still be validated against the same patched client used for the C# reference server before the C# implementation can be retired.

## Implemented

- the same RSA XML authority set (login RSA-1536 and credentials RSA-2048), including raw private/public operations and self-tests;
- Skype DH-384 handshake and MD5 handshake tags;
- reconstructed RC4 account transport and legacy Skype IV-expanded RC4 for TCP/UDP;
- native RSA/AES login request handling and community credential issuance;
- experimental native signup RPC `0x139a`: validates registration metadata, atomically creates an account without replacing an existing login, and stores the client's native password verifier;
- native account RPCs used by the Stage 4.1 client: login, account email, contact-list index, native document synchronization and directory search;
- experimental Skype 4.2 contact-request queue (0x1784) and inbox poll (0x1780); an empty 0x1781 fetch is supported, but pending inbox-event delivery is not yet implemented;
- the C# SQLite schema and account/contact/profile/message operations;
- the HTTP management/message API and /healthz;
- TCP bootstrap/node sessions, slot-directory replies, signed transient location records and transport acknowledgements;
- UDP bootstrap probes;
- Stage 4.1 deployment controls: --mode local|global, --advertise-ip, --closed and --allowlist;
- graceful SIGINT/SIGTERM shutdown.

The same known Stage 4.1 limitations still apply: contact-request acceptance/decline is not yet identified, and cross-NAT media relay is not implemented. Native registration transmits a password digest, not plaintext; such accounts support native login but cannot use the plaintext-password HTTP API. A pending 0x1781 fetch currently fails explicitly rather than returning an invented event or marking the request delivered. Native contact authorization is **not** end-to-end. Call/media behavior still depends on the legacy client's direct-connect/NAT behavior.

There is no authoritative native presence registry in the Go server yet. A signed location record is a peer-routing hint with a lease, not proof of Online/Away/DND status; counting these records would also count Invisible and Offline clients. Fresh-profile avatar recovery was tested and failed as described below. Detailed profile fields still need a native publish/fetch capture before a server response can be implemented faithfully.

On 2026-09-26 a patched Skype 4.2 client completed native signup through `0x139a` against the Go server and opened its main window. A second, empty client profile then authenticated with `0x1399` using that new account. The server returned persisted `p/profile` and `p/email` documents via `0x1788` and returned the account email separately via `0x139c`. The email appeared in the new profile's local `Accounts` row; `Accounts.fullname` remained empty and no avatar was present. The new client then issued `0x178a` to delete `p/profile`; the first client republished the same short-name document later. This test establishes native registration and fresh-profile login, but not detailed-profile or avatar recovery, and it does not isolate which email response populated the local row.

After changing the avatar in the first profile, its local `Accounts.avatar_image` held 4203 bytes. The server saw a new signed location record and a `p/profile` update, but that document was only 30 bytes and contained the short name and country fields, not image data. A third empty profile logged into the same account, fetched both documents, and restored the short name, country code and email; its `Accounts.avatar_image` remained NULL. It then rewrote `p/profile` with two additional zero-valued numeric fields. This confirms partial profile-document synchronization and that avatar bytes are not transferred through the currently implemented document operations.

Static analysis of the unpacked 4.2 client finds a separate `p/avatar` document name in the avatar update path (`005A8DF0`) and a `Lib/CentralStorage/SyncAvatar` setting. In an isolated test profile, setting `SyncAvatar` to `1`, restarting, and changing the avatar again updated local `Accounts.avatar_image` from 4203 to 3832 bytes, but no `p/avatar` or other image-sized document was written to the server. A bounded network capture during the change showed only the periodic `0x2B08` dynamic-content requests to the server, not an avatar upload. The presence of the client-side string does not establish the upload trigger or wire format; native avatar recovery is still unresolved.

On 2026-09-26 two native clients reproduced a delayed Invisible transition: Admin's own `Accounts.availability` changed from 2 to 6, while Second's contact row initially remained 2. After a delay it became 1 (Offline), which is the correct outward appearance of Invisible. During the delay Second queried Admin's location and the server returned a signed record; Admin also republished a signed record while Invisible. Neither a location record nor a successful login is an authoritative Online/Away/DND signal. An online-user count derived from the directory would therefore include invisible/offline or stale clients and is intentionally not exposed as a real count. Skype 4.2 has a `UI/General/ShowOnlineUserCount` option enabled by default, but the native source of its displayed value has not been identified. The Go server's `--detailed-debug` mode now logs only the code, flags and field shapes of other node commands, to identify a possible status/notification path without logging their contents.

The node TCP handler also retained its 10-second handshake write deadline for the entire connection; live server logs showed later node replies failing with `i/o timeout`. The active node path now clears that deadline, bounds each encrypted reply write, and refreshes its idle read deadline after traffic. This fixes a concrete transport failure, but whether it shortens the observed Invisible propagation delay requires a fresh two-client test with the updated binary. Offline transition and an accurate global online count remain unverified.

## Skype 4.2 notification RE checkpoint

Read-only Ghidra analysis of the installed patched 4.2.0.187 executable (SHA-256 `603E4A1612403448C1DCEAFA469B92C23282F2DBA0F35FA2517A57C7AFA895B0`) found:

- Callback `00696D90` rejects statuses other than `0x1450` for `0x1780`/`0x1781`. For `0x1780` it tests `0/2E` for nonzero and then issues `0x1781` with `0/2D` equal to the client's `Lib/Notification/LastID`.
- The `0x1781` response uses `0/2F` as an event count and indexed `5/20` event records. The client reads nested `0/22`, `0/21`, `0/28`, `0/3B`, `0/25`, `0/2A`, `3/26`, and optionally `4/24`. The previous flat `0/2E,3/26,3/27,0/22` response was not consumed by this parser. Field semantics and required signing still need evidence before constructing a nonempty event.
- Startup path `006960C0` can issue a one-off `0x1780` when `Lib/Notification/LastPoll` is stale (the observed comparison uses `0x2A300` seconds, 48 hours). Otherwise it installs the notification listener. Callback `00697570` consumes notification `0/0F` as a high-water mark and schedules `00695D20`, which issues `0x1780` when that mark exceeds `Lib/Notification/LastID`. This explains why storing a request alone does not cause an already-online recipient to poll. The transport and wire envelope that delivers this notification remain to be identified.
- `00696D90` advances `Lib/Notification/LastID` only after processing event records, so receiving a TCP fetch is not evidence of delivery. The database row ID is not the protocol cursor.
- `006C3F40` issues account operation `0x2B08`. Its callers and adjacent diagnostic strings identify it as a `dyncontent::manager` bundle poll/download, not contact synchronization. The current Go parser rejects it; an invented empty success response would not implement dynamic content.

On 2026-09-25 two patched Skype 4.2 clients on one Windows host established a direct TCP connection after the directory returned the peer's signed location record. Native contact requests appeared in each client's UI, both contacts became online, and text messages arrived in both directions. This is observed P2P interoperability, **not** server-side message delivery or proof of cross-NAT operation. The server-side `0x1780`/`0x1781` offline inbox remains an unimplemented fallback.

Client-written `u/<login>` contact documents update the SQL contact membership in the same transaction as the document. The document's `3/10` identity must match the path and refer to an active account. A real client-written document decoded to `4/3[392],3/10,3/14,0/79=3,0/7D=1`. The server now persists signed peer records only after signature verification at directory publication and projects that five-field document only for mutual contacts. Old, recognizable three-field server documents are replaced when a verified peer record becomes available; client-written documents are preserved. The client's document used compressed `0x42` encoding and the server generates equivalent `0x41` fields.

On 2026-09-25, after restarting the `dc31298` server, a new empty Skype profile logged in as the admin account, loaded `second@test.lol` from the server, showed it online, and exchanged text in both directions with the second client. The server had an existing client-written `u/second@test.lol` document, so this verifies fresh-profile recovery of that document, not live acceptance of a newly projected `0x41` document. The server `messages` table remained empty: the observed text exchange used the direct peer connection and is not evidence of offline delivery or server-side history.

The signed location record lease is six hours. The prior five-minute lease expired while both test clients were still online, and a restarted client then saw its peer as offline because the directory no longer had a record. The longer lease allows staggered logins, at the cost of advertising a stale endpoint longer after an unclean disconnect; peer identity checks and direct-connect failure still apply. This change requires a server restart to take effect.

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
