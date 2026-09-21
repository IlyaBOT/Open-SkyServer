# Native Skype 4.2 Checkpoint

Updated 2026-09-20. Active workspace: `I:\Open-SkyServer`.

## Verified and Pending

- The isolated patched 4.2.0.187 lab client authenticates against SQLite and
  opens its main window. This is not compatibility with the unmodified EXE.
- Native CBL document synchronization persists uploads and projects DB contacts.
  `second@test.lol` appeared in the real client's contact list, confirmed by the
  user and a read-only inspection of the client's database/window.
- The directory is separate from contact synchronization. Native search now
  works, confirmed by the user on September 20 and by real `0x4278` requests:
  login PQ OR email CW OR name CP, 5 wire entries, 1 result, 62-byte reply.
  The last blocker was configuration scope: ForceServer/UseServer must be in
  the account's config.xml, not shared.xml. The configuration tool now sets both
  scopes and backs up each modified XML file.
- Supported directory predicates: login EQ/PQ, email EQ/CW (whole address),
  and display-name EQ/PQ/CW/CP. Numeric property 17, comparison EQ, value 0
  separates OR branches; adjacent filters within a branch are ANDed. Maximum:
  8 predicates, 15 entries including separators, 20 unique returned accounts.
  Empty branches and unknown predicates are rejected, not silently ignored.
- Community name CW/CP matching uses space-delimited whole words/word prefixes,
  respectively, in any order. This is a bounded implementation choice, not a
  claim of byte-for-byte equivalence with Skype's international name matching.
  SQLite NOCASE/lower currently provide ASCII case folding only. Phone and
  advanced demographic/location predicates remain unsupported.
- Native contact invitation/acceptance, text delivery, password changes and
  full profile editing remain unfinished. A search result grants no contact
  authorization. CBL blobs alone do not update all public-profile API fields.
- Bootstrap still replays historical configuration data, and native sessions
  can reconnect after about 30 seconds. Do not describe online state as stable.

## Run the Lab

From the repository root, with existing community keys (do not regenerate them):

```powershell
.\skyserver\bin\Release\skyserver.exe --host 0.0.0.0 --api-host 127.0.0.1 --real-skype-probe --keys-dir I:\Open-SkyServer\skyserver\private-keys --sqlite C:\platform-tools\sqlite3.exe
```

This uses `skyserver.db` next to the server EXE. The API remains loopback-only.
The lab client uses `192.168.1.101`. It is not redirected by the reconstructed
client's `SKYAUTH_HOST` environment variables.

When the lab client is stopped:

```powershell
.\skyserver\tools\Set-Skype42LabDirectory.ps1 -ProfilePath I:\Open-SkyServer\skyserver\diagnostics\portable-20260910-v5\profile
.\skyserver\tools\Start-Skype42Lab.ps1 -Directory I:\Open-SkyServer\skyserver\diagnostics\portable-20260910-v5 -Username admindev@test.lol -Password AdminDev
```

The directory configuration script preserves unrelated XML and makes uniquely
named `.bak` files. It sets `Lib/ContactSearch/ForceServer=1`, `UseServer=1` in
each initialized account's config.xml. The native `*Lib/Connection/SearchServers`
key belongs to shared.xml; its XML value is `192.168.1.101:12350`. Shared
DisableSupernode/ForceSupernode settings are retained. It does not patch the EXE
or hosts. The lab must be stopped and at least one account initialized first.
CLI passwords are for these demo accounts only. Roll back configuration by
restoring the chosen `shared.xml.directory-*.bak` while the lab client is stopped.

## Reverse-Engineering Map

Addresses refer to the imported RVA-layout image at base `00400000` in the
Ghidra `Skype42` project, not file offsets in the packed installed EXE.

- `00643530`: server directory request `0x4278`, repeated `5/20` terms containing
  property `0/21`, comparison `0/22`, and typed value `*/23`. Top-level `0/24`
  controls fallback. Property map at `00C769B8`: 0=login, 1=email, 2=full name.
- `00644140`: directory completion `0x81B0`, partial response `0x81B6`.
- `00643A40`: repeated result records `5/64`: string `3/66` login, `3/65` full
  name, optional `3/67` country, `3/68` region, `3/69` city, `0/6A` rank.
- `00C98D80`: comparison labels EQ, GT, GE, LT, LE, PQ, PG, PL, CW, CP.
  Do not equate CW (8) or CP (9) with arbitrary substring matching.
- `00641010`: general search builds login PQ OR email CW OR full-name CP OR
  phone CW; exact search builds login EQ OR email CW. `00641500` removes invalid
  predicates (an email need not be accepted as a Skype name or phone number).
  `00646920` inserts internal property 3/value 0 between alternatives, mapped
  to wire property 17 by `00643530`; `00642800` splits those alternatives into
  separate DHT queries. Do not treat the default query as an AND of all fields.
- `00645880`, `00644AA0`: dedicated search-server pool and ForceServer/UseServer
  selection. Original server string is `194.165.188.85:12350`; the lab build
  already replaces that string.
- **`0x1787` is NOT directory search.** `005C5930` submits it from
  `user_manager_t::postQueryUserPrivileges`. Its `3/27` is a target identity.
  Earlier temporal association with an email search was misleading.
- `0074E2A0`, `0074D090`, `0074F5E0`: CBL download/upload/delete/manifest
  `0x1788`..`0x178C`, revision `0/36`, checksums `4/35` (big-endian), documents
  `5/37{3/34 name,4/33 body}`. CRC starts FFFFFFFF, reflected, no final XOR.
- `00696D90`: `0x1780` inbox poll, `0/2E` causes `0x1781` fetch. Not implemented.

Analysis logs: `diagnostics/pe-analysis-20260907-233415/directory-*.log`.

## Evidence and Next Test

- `diagnostics/directory-tests-20260919-c.log`: all 31 protocol tests passed.
  Coverage includes encrypted general/exact UI-shaped OR queries, email CW,
  literal SQL characters, name word boundaries, malformed logical expressions,
  active-account restriction across OR branches and no implicit contact grant.
  Tests use synthetic native envelopes; they do not prove a UI search.
- Read-only invocation of the deployed DB search against the live database,
  email CW OR name CP for `second@test.lol`, returned exactly the account
  `second@test.lol` with display name `Test Second Accout`.
- Directory acceptance log: `diagnostics/directory-20260919-c-195939/server.log`.
- Current server output: `diagnostics/chat-20260920-005655/server.log`.
  Server restarted after the passing tests; API still binds to loopback only.
- Pre-restart SQLite snapshot and previous EXE/PDB `.bak` files are in
  `diagnostics/directory-20260919-c-195939/`. Keys and client EXE were unchanged.
- Current isolated client: `diagnostics/portable-20260910-v5/Skype.exe`.
- Real directory searches are now confirmed. Do not undo the account-scoped
  ForceServer fix when revisiting the older September 19 diagnostics.

## Native Chat Investigation

- The second lab process uses `portable-20260910-v5/profile-second`, not the
  admin profile. Both clients authenticated; the user attempted one message
  each way. Neither arrived. Read-only inspection of the two client databases
  shows sending_status=1, chatmsg_status=1 for the test messages (IDs 83 and 22).
  Do not mark those rows delivered or copy rows between client databases.
- Capture: `diagnostics/capture-20260920-004446-5fdf1f54/`. Traffic is still
  bootstrap/account service traffic, with repeated node-session disconnects.
  The clients report each other offline. A functioning route/presence exchange
  must precede native chat synchronization.
- `skypeopensource2/goodsendrelay4_dll/goodsendrelay4_dll/chatsend_newchat_init.c`
  maps the reconstructed peer sequence: 7D/7A, 0D chat init, 23 sign request,
  24 signed chat identity, 0F/29/10, 2A signed headers, 13 header list, 15,
  then 2B message body. This is not the HTTP message API.
- Found and corrected historical address replay in TcpProbeServer's command-30
  reply. Blob 2/11 now carries the observed peer IPv4/port. Source evidence:
  skysearch4_dll/skysearch4_dll/tcp_setup.c:453 reads it into MY_ADDR. Other
  bootstrap fields are still historical and need separate verification.
- Message persistence now retrieves last_insert_rowid on the inserting SQLite
  connection, avoiding the former INSERT / separate MAX(id) race. The legacy
  receive API still consumes on read; do not reuse that as a native network ACK.
- SQLite stdin/stdout/stderr now explicitly use UTF-8. A new test exposed OEM
  code-page bytes and replaced emoji in previously written message bodies.
  This fixes new writes; it cannot reconstruct already corrupted text.
- `diagnostics/chat-tests-20260920-d.log`: 31 protocol tests and the added
  concurrent message-storage suite pass. Native bootstrap framing/address is
  covered; storage covers eight independent writers, exact Unicode/multiline
  bodies, recipient isolation, consumption and persistent history. Earlier b/c
  test runs failed (fixture setup, then real encoding corruption); d is the
  passing run. `chat-storage-20260920-d.db` is a separate passing storage fixture.
- Deployment snapshot and previous EXE/PDB: `diagnostics/chat-20260920-005655/`.
  Follow-up packet capture: `diagnostics/capture-20260920-005709-d3055375/`.
  New replies contain the two observed endpoints, 192.168.1.101:57712 and
  :57713, instead of the historical external IP. This alone is not chat delivery.
- Native chat delivery, signed peer sessions, offline queue acknowledgments and
  history synchronization are NOT implemented end to end yet.

## Native Presence Investigation (September 20)

- Presence, not message delivery, is the current prerequisite. Do not mark
  contacts online merely because their accounts exist or authenticated earlier.
- Original-client functions 00664D50 and 006663C0 establish requested states:
  1 Offline, 2 Online, 3 Away, 4 NA (legacy), 5 DND, 6 Invisible.
  Account login-state and availability are different enums. In particular,
  Accounts.status=7 does not mean availability=7.
- Contact renderer 00666240 maps availability=8 to OFFLINE. Its precise internal
  meaning is still unknown; it is not evidence of missing contact authorization.
  Both lab contacts have isauthorized=1 but availability=8. The last persisted
  own states were admin=3 and second=2; persisted state alone is not live presence.
- `tools/Get-Skype42Presence.ps1 -Directory <isolated-lab-directory>` reads only
  account/contact status columns using SQLite -readonly. No passwords, chat
  bodies or database writes. `tests/PresenceInspectorTests.ps1` passes mapping,
  nullable-field, account/contact separation, read-only hash and path tests.
- 0076A4B0 schedules 0076A560, named sendNotificationListToParent. The latter
  builds a contact/node list and calls 00708730 with field ID 1B. That serializer
  writes type-4 node information, 21 or 27 bytes depending on extra endpoint.
  It then queues command 31 via 006A7540, with a 30-second request lifetime.
  This is a reverse-engineered sending path, not an implemented subscription.
- Correction from September 21: the old 8203 "keepalive" interpretation was
  wrong. Native 006BCF60 handles BCM inventories (0x2F) and content requests
  (0x30); 006BCAE0 expects signed 4/3 content. Removed historical inventory
  announcements and the invalid echo response. Do not restore this echo.
- Follow-up capture `diagnostics/capture-20260920-104753-b1d4000e/` completed
  after restarting the two isolated profiles with the demo CLI login. TCP
  traffic reaches local port 12350; captured UDP requests to that port have no
  responses. A subsequent read-only status check still reports peer state 8.
  This is not a successful presence test; the capture does not cover every
  interface or establish the exact reason that registration stops.
- Analysis evidence under `diagnostics/pe-analysis-20260907-233415/`:
  `presence-status-map-20260920.log`, `presence-notify-20260920.log`,
  `presence-send-20260920.log`, `presence-queue-20260920.log`.
  Next trace: parent registration/selection, queued notification transport and
  the receiver's status handler. Preserve Invisible semantics and subscription
  permissions; do not patch client database availability as a workaround.

## Native Location Exchange (September 21)

- Real progress in `diagnostics/presence-live-20260921-g/server.log`: both lab
  clients published command 0x0C with signed 4/B records. Admin's 442-byte
  partial-recovery signature and second's 392-byte full-recovery signature
  passed authority, client signature, credential-binding hash and expiry checks.
- `NativeSignedRecord` implements verified message recovery. `NativeRecordDirectory`
  stores these client-issued records and serves exact 0x0E lookups as 0x0F,
  using 5/0 result rows and the original unchanged 4/B record. Publication ACK
  is 0x0D. Native Searcher 0062DA40 consumes result rows; 0062F480 establishes
  the 0x0E/0x0F command pair. Do not replace signed profiles with made-up status.
- At 2026-09-21 04:46 UTC, read-only native database inspection confirmed:
  admin own availability=3, second contact=2; second own=2, admin contact=3.
  The same states were seen again afterward. Previous peer availability was 8.
  Thus real reciprocal Online/Away discovery now works; no client DB edits.
- Follow-up requests use 6/2 excluded IDs. Build h adds stable 0/10
  record IDs and exclusion handling, with tests for repeat suppression.
- Current deployment: `diagnostics/presence-live-20260921-h/server.log`;
  server PID 38460 at deployment, admin lab PID 36640, second lab PID 32052.
  Verify process paths before stopping anything; these IDs are only a snapshot.
- Abrupt-disconnect test: stopped only second PID 21700 after backing up its
  main.db to `presence-live-20260921-g/second-before-offline-test.db`. Admin
  continued reporting second=2 on subsequent checks. Offline expiry has NOT
  passed. Second was relaunched afterward. DND/Invisible transition tests are
  still pending; an optional user question asks for a native UI status change.
- Build h live recheck: both publications reached the directory, admin found
  second, contact values remained second=2/admin=3. Second's own state briefly
  read 14 during reconnection. A follow-up 6/2 still contained 0 despite the
  new 0/10 field, so the native meaning/type of the result ID needs verification;
  synthetic exclusion tests do not prove native duplicate suppression.
- Limitations: the directory is an in-memory, one-location-per-user cache
  capped at 1024 records with a two-minute lease. It is not an authoritative
  online-status database. Multi-device indexing, native notification lookup
  0x12/0x13 and persistent subscriptions are not implemented. Parent connections
  still reconnect and auxiliary account RPCs remain unsupported. Do not claim
  all transitions, Invisible semantics, or remote-network behavior are tested.
- Earlier transport fixes: dynamic observed 2/11 peer address and actual 0/10
  listening port; variable-length, compound native command parser; transport
  receipt ACK; command 6/8 username-slot routing to the actual local endpoint.
  Capability-pool 0/4 requests are not mistaken for slot 0/0 requests.
- Full tests passed in `presence-tests-20260920-e.log`, `presence-tests-20260920-f.log`,
  `presence-tests-20260921-g.log` and `presence-tests-20260921-h.log`. Added signature-tamper, credential-binding,
  expiry, record lookup/lease and framing tests. These synthetic tests alone
  do not prove native UI status transitions.
- Lab executables and community keys remain unchanged. Each server deployment
  has previous EXE/PDB `.bak` files and a SQLite backup under its presence-live
  diagnostics directory. Never copy local diagnostics into a public release.

Do not publish diagnostics, private keys, client profile databases, or a patched
commercial EXE. These paths contain local development state, not release assets.
