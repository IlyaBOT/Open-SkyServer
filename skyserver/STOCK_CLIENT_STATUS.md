# Stock Skype status, 2026-09-06

Latest update: client patching is now authorized. See [PATCHING.md](PATCHING.md)
for the generated community key pairs, server crypto support, tested backup/rollback
engine, and the protected-client analysis. The installed 4.2.0.187 still has no
verified binary patch profile and remains unchanged. Native login is not achieved.

2026-09-07: the server now verifies the native password digest against SQLite and
sends a community-signed credential response with `--keys-dir`. Historical public
signatures and the response envelope are covered by regression tests, including
an end-to-end synthetic TCP exchange. The installed original client still does
not trust these keys; its login/profile/contact UI has not been reached.

This report records the earlier hosts-only experiment. The user subsequently
authorized OS-level direct-IP redirection. See [IP_REDIRECT.md](IP_REDIRECT.md) for
the new journaled alias scripts, tested without applying privileged network changes,
and [CRYPTO_COMPATIBILITY.md](CRYPTO_COMPATIBILITY.md) for the key-replacement analysis.
The historical observations below do not claim native login was completed.

The historical report below predates that implementation. Registration, native
profile retrieval and contact synchronization remain unimplemented. The
SQLite/HTTP API works with the reconstructed client only. Passing its tests does
not establish compatibility with an original Skype executable.

## Current machine evidence

- Workspace: `I:\SkypeReverse\skypeopensource2` (the former `J:` path no longer exists).
- Running client: Skype **4.2.0.187**, PID 21232 during the capture.
- File: `C:\Program Files (x86)\Skype\Phone\Skype.exe`.
- Authenticode status before and after testing: `Valid`, signer Skype Technologies SA.
- SHA-256: `A2E175CE7C9888C125E2B3D4C2343229832BA0D0CD8A8A1CE120CE92624E856C`.
- Existing hosts mappings point the Skype DNS names at `127.0.0.1`.
- A fresh login attempt was submitted through the existing Skype login controls
  using the demo admin account. No EXE, DLL, client memory patch, HostCache edit,
  registry edit, IP alias, routing rule, or proxy change was used.
- TCP observations: [skype-tcp.csv](diagnostics/20260906-000114/skype-tcp.csv).
  The client attempted `91.190.218.40:40001`, `91.190.216.17:40002`,
  `65.55.223.25:40003`, `64.4.23.141:40004`, then ports 443 and 80.
  Another observed destination was `111.221.74.33:40005` (also 443/80).
- The local server had listeners ready, but received no application requests in
  this capture. An external TCP `Established` state does not prove Skype login.
- Both demo accounts and reciprocal contacts already exist in SQLite.
- Final native client state: "Could not establish a connection";
  [window capture](diagnostics/20260906-000114/skype-final.png). No native login,
  registration, profile or contacts were obtained. The EXE hash remained unchanged.
- Visual Studio build succeeded with locally restored .NET 4.0 reference assemblies.
  All 9 protocol tests passed. The existing reconstructed `authsmoke.exe` returned
  `RET=1`, and its server-side login was validated against SQLite.
- Loopback HTTP API checks passed for admin login, the Admin profile and the second
  account in Admin's contacts. These are reconstructed-client API results only.
- The BAT entry point correctly invokes the hosts script from another working
  directory. Its `on` operation stopped at the existing Administrator check because
  this terminal is not elevated. Existing hosts mappings remained unchanged.

## Two independent blockers

**Routing:** hosts only changes name resolution. An IP literal in the client or its
HostCache bypasses it. Adding `127.0.0.1 91.190.218.40` cannot redirect that IP's TCP
or UDP connections. Previous captures used IP aliases and HostCache changes; those
are outside the current hosts-only constraint and were not reapplied.

**Native authentication:** successful DH/RC4 decoding only reveals the outer
records. `skyauth4_dll/skyauth4_dll/skype_login.c`, `Produce_Session_Key`, encrypts
session material with a 1536-bit Skype login RSA public modulus, exponent 65537.
`SkypePrepareLoginPackets` then protects the login payload with AES. The auth
server would need the corresponding private key to recover that session material.
The public modulus in this repository cannot perform this operation.

The account credentials also contain the client's RSA public key signed by Skype's
authority. See `skype/skype_basics.h`, `skype_credentials_key` (2048-bit public
modulus), and `goodrecvrelay4_dll/goodrecvrelay4_dll/cred_util.c` and `miramax.c`.
The provided client code does not implement the authority's private signing key.
Old signed credentials belong to their original identities and client keys; they
are not credentials for a newly created database account.

This architecture is independently described in Biondi/Desclaux's original research,
[Silver Needle in the Skype](https://www.blackhat.com/presentations/bh-europe-06/bh-eu-06-biondi/bh-eu-06-biondi-up.pdf),
slides "Finding friends", "Phase 2: Authentication", "Phase 3: Certificate creation"
and "Parallel world: build your own Skype Private Network". That older research
supports the architecture; it is not a new successful test of this installed client.

The old `real_skype_probe.log` includes two decoded outer records (235 and 251
bytes) and a fabricated 292-byte success response. This is historical transport
evidence only. The response used generated bytes, not an AES-encrypted, signed
credential. Current probe mode closes unauthenticated at that stage instead of
claiming success or creating a DB session.

With the supplied materials there is no demonstrated hosts-only path to native
login/registration. Further packet-format emulation alone does not supply the
missing RSA decryption/signing capability. Client modifications remain excluded.

## Supernode roles

Connecting to a bootstrap supernode and becoming a supernode are different actions.
Removing HostCache endpoints or disabling probe listeners does not disable the
client's ability to become a supernode, and can prevent bootstrap altogether.

Skype's documented `DisableSupernode` policy disables promotion locally. It is a
registry setting, not a hosts entry. No such policy was changed during this run,
and no verified server-side no-promotion command has been implemented. We cannot
claim that this client's supernode role has been disabled.

## Reproduce server checks

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\skyserver\build.ps1 -Test
```

The build script uses Visual Studio MSBuild and restores Microsoft's .NET 4.0
reference assemblies locally if missing. It does not retarget the project or
install a system runtime. Protocol tests use an isolated SQLite database and
synthetic TCP clients: valid/invalid local credentials, missing credentials,
fragmented headers/records, invalid record types, DH hash verification, and stock
transport closing without a fake success or DB session. They do not test native
Skype login, registration, profile or contacts.

For DNS mappings only, from an Administrator terminal:

```bat
skyserver\skype_hosts.bat on
skyserver\skype_hosts.bat off
```

These commands are not sufficient to make native Skype log in.
