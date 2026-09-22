# Community keys and client patching

Current Skype 4.2 package workflow (2026-09-22): see [DEPLOYMENT.md](DEPLOYMENT.md).
`tools/New-ClientBundle.ps1` packages the verified rebuilt image with a
hash-checked installer/restorer and account-scoped directory settings.
The limitations below apply to the older constant-patcher template, not that
package workflow. A changed server address requires a new signed client build.

## Status: NOT a working patch for the installed Skype yet

`skyserver-keygen.ps1` works. `skypatch.ps1` implements verified, fixed-size byte
patching, original `.bak` backups, idempotency, a transaction journal, and rollback.
**Its verified production profile list is empty.** The installed protected Skype
4.2.0.187 is explicitly rejected, not patched. Do not distribute the generated
script as a working Skype fix. No native login/profile/contact success is claimed.

No system-wide IP redirection is added by these scripts. Existing hosts settings
from previous experiments are not modified or required by the patch engine.

## Developer script

Run from the repository root with Windows PowerShell 5.1:

```powershell
.\skyserver\skyserver-keygen.ps1
```

This produces:

- `skyserver/private-keys/login.private.xml`: login RSA-1536 private key.
- `skyserver/private-keys/login.public.xml`: corresponding public key.
- `skyserver/private-keys/credentials.private.xml`: credential RSA-2048 private key.
- `skyserver/private-keys/credentials.public.xml`: corresponding public key.
- `skyserver/dist/skypatch.ps1`: standalone script with only public moduli and
  `$ServerIp = '192.168.1.101'` embedded as variables.

Both pairs use exponent 65537 and the Windows cryptographic RNG. Sizes match the
legacy protocol found in this repository; RSA-1536 is not recommended for a new
protocol. Private XML is plaintext, protected by NTFS ACLs for the creating user
and SYSTEM. Back it up securely; do not distribute the private directory.

A second invocation validates and reuses existing pairs, never silently rotating
the authority. To create a different authority, pass a new `-OutputDirectory`.
Use `-ServerIp 127.0.0.1` for a loopback-only public patcher, or another unicast
IPv4 address. Never point `-PatcherOutput` at the private directory.

## Server integration

```powershell
.\skyserver\build.ps1 -Test
.\skyserver\bin\Release\skyserver.exe --keys-dir .\skyserver\private-keys --check-keys
```

For serving, add `--keys-dir <absolute-directory>` to the existing server command,
or set `SKYSERVER_KEYS_DIR`. The server validates private/public consistency,
sizes, exponents and RSA round trips before starting listeners. Incorrect keys
fail startup. Logs contain public modulus SHA256 fingerprints, never private keys.

`CommunityKeys.cs` implements blinded raw RSA decryption, raw private credential
block operations, the native session KDF, and AES-CTR. The latter two are checked
against the original C primitives in `tests/LoginCryptoReference.c`, including
the distinct request/response counters. `NativeLoginRequest.cs` decodes and
validates native requests. `NativeCredentials.cs` now constructs and signs an
identity credential and returns an encrypted success envelope after DB password
validation. This is NOT a completed or original-client-verified login workflow.

The remaining server work includes native failure responses, registration,
profile/contact operations, and confirmation/correction of the inferred response
fields against a client that trusts the community authority.

### Native login request implementation

`SkypeBlobCodec.cs` parses uncompressed 41 lists with size/depth/field limits.
For compressed 42 lists it runs `skype_blob_worker.exe`, built from the repository's
existing decoder, in a separate hidden process. Input is limited to 16 KiB,
normalized output to 64 KiB, decoder allocations to a cumulative 2 MiB, and the
parent kills a worker exceeding three seconds. The worker is fault-contained,
not a Windows security sandbox or a proof of parser memory safety.

The source-derived login key exchange contains the encrypted RSA-1536 block in
field `04-08`. The request path decrypts it with the community login key, derives
AES-256 material, checks the native CRC, decrypts the login record and extracts
the username, MD5 password digest and client's 1024-bit public modulus. Unknown
commands, duplicate required fields, malformed records and corrupted data are
rejected. This currently supports the login command `0x13a3`, not registration.

`native_password_verifiers` stores PBKDF2-SHA1 of the native MD5 digest with an
independent random salt and 100,000 iterations; it does NOT store the raw digest.
Account creation/password updates maintain both verifier formats transactionally.
Old accounts are provisioned only after successful ordinary-password validation,
without resetting passwords, profiles, contacts or messages. An unprovisioned
account fails native authentication closed. Existing PBKDF2 hashes alone cannot
be converted into native verifiers.

Synthetic TCP tests cover DH/RC4, compressed 42 RSA exchange, AES request parsing,
correct/incorrect database credentials and CRC rejection. The valid test receives
a 292-byte response and verifies its CRC, AES response counter, authority
signature, username, client modulus and expiry. Incorrect passwords and malformed
requests receive no credential. No HTTP API bearer session is created by this
native path; the signed credential is the native identity artifact. These tests
are not evidence that the original client has logged in.

### Credential response implementation (2026-09-07)

Three historical public signatures from `skyauth3/Debug/a_cred.txt`,
`goodrecvrelay3/Debug/a_cred.txt` and `goodsendrelay3/Debug/a_cred.txt` recover under
the original RSA-2048/e65537 public authority key. Their recovered blocks contain
`4B BB...BB BA <41 list> <SHA1(list)> BC`. Payload lengths are 170, 194 and 197
bytes; SHA-1 checks pass for all three. Client private primes/passwords in those
files are not copied to the test fixture or logs.

`tests/NativeCredentialsTests.cs` contains ONLY the public authority modulus and
the public 285-byte decrypted response from `skyauth3/Debug/log.txt:349`. It
verifies the old signature and reproduces the recovery block and response
envelope byte-for-byte. The full-message SHA-1 implicit-trailer format is also
consistent with the primary
[Bouncy Castle ISO9796-2 implementation](https://github.com/bcgit/bc-csharp/blob/master/crypto/src/crypto/signers/Iso9796d2Signer.cs).
Only full recovery is supported; oversized identities fail instead of truncating.

Generated credentials bind `3/0` to the authenticated DB login, `4/1` to the
client's 1024-bit public modulus, and `0/4` to a 30-day expiry in Unix minutes.
`0/3=0` follows the old samples. **Nested `5/2 -> 0/9` remains an opaque field.**
For this experimental response it is set to issuance time plus 365 days, following
the interpretation in `goodrecvrelay4_dll/goodrecvrelay4_dll/cred_util.c`.
That interpretation is a compatibility hypothesis, not an established creation
timestamp. Later samples also have an optional `5/7 -> 3/999` field that is not
present in the earliest sample and is not emitted here.

The success envelope matches the observed two-list structure: `0/1=0x1068`,
`0/2=1`, then `0/3a=2`, `0/3c=0`, `4/24=<authority-id + signature>`, and the observed
empty `5/32` extension. This is not a profile or contact list. It is encrypted with
the response AES counter (1), followed by low-16 CRC and outbound RC4 wrapping.
Actual client acceptance, unknown field semantics and post-login synchronization
still need verification. No executable patch is inferred from these server tests.

Two original C packer defects were corrected in the copy used by the worker:
`get_4142_packed_length_7148D0` treated byte offsets as `u32` indexes, and binary
field sizing omitted the payload length. These caused a worker access violation
and malformed normalized packets before the fixes.

## Public script behavior

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\skyserver\dist\skypatch.ps1 -Action Inspect
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\skyserver\dist\skypatch.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\skyserver\dist\skypatch.ps1 -Action Restore
```

Discovery uses the Skype App Paths registry entries and standard installation
directories. A portable installation can use `-ClientPath`. No `Read-Host`, UAC
request or interactive choice occurs. A protected installation directory requires
the caller to already have write access; this agent's current process is not
elevated. The engine stops only the exact target process, and only after the
binary and patch profile have passed preflight.

A supported profile pins the complete original SHA256 and architecture, and
contains exact original bytes and offsets for both RSA roles and server addresses.
The engine rejects out-of-bounds/overlapping hunks, mismatches and incomplete
roles. A developer may pass an explicit JSON `-ProfilePath`; this does not verify
that a profile actually supports Skype or covers every endpoint. The test suite
uses a synthetic PE fixture only, not a validated Skype profile.

Before replacement, `<exe>.bak` is verified byte-for-byte by SHA256 and
`<exe>.skypatch.json` records original/new hashes. The backup is never overwritten.
Rollback keeps the backup, accepts interrupted transactions, and refuses to
overwrite unrelated changes. A persistent `.skypatch.lock` uses an exclusive OS
file handle for ownership, not file existence. Process termination releases it
automatically; a leftover lock file does not block recovery.

Any executable modification invalidates its original Authenticode signature.
Only restoring the exact original bytes restores that original signature.
The patch engine does not pretend otherwise or disable signature checks globally.

## Installed client investigation, 2026-09-06

Original file: `C:\Program Files (x86)\Skype\Phone\Skype.exe`, 13,351,304 bytes.
Version: 4.2.0.187. SHA256:
`A2E175CE7C9888C125E2B3D4C2343229832BA0D0CD8A8A1CE120CE92624E856C`.

The two known public moduli are absent on disk in both full little-endian and
big-endian representations. The tested bootstrap/login addresses are also absent
as ASCII, UTF-16 and packed IPv4. In the running image at base `0x00400000`, these
authentication address strings were observed read-only:

| String | Image RVA (decimal) |
| --- | ---: |
| `193.88.6.13` | 8955404 |
| `194.165.188.79` | 8955422 |
| `195.46.253.219` | 8955443 |

These are runtime addresses, NOT file offsets. A subsequent read-only scan of
184,732,160 bytes across readable committed process memory did not find either
known full RSA modulus in four byte/word layouts or their bitwise complements.
That is a snapshot, not proof that the keys are absent or that this version uses
the same exact keys as the reconstructed source. No process dump or private
process data was saved.

After continuation, the read-only `tools/Inspect-SkypeConstants.ps1` scan tested
132 modulus layouts (8/15/16/28/30/31/32-bit digits in several storage widths),
plus periodic XOR transforms of 4/8/16 bytes. No match was found on disk or in
173,559,808 bytes of readable process memory. This still does not identify the
client's deobfuscation routine or establish that it uses these exact public keys.

The EXE has `.ext1` with 11,673,600 virtual bytes and only 512 file bytes. A verified
unpacking/deobfuscation and integrity-aware patch is needed before a production
profile can be created. Blind four-byte IP replacement cannot cover protected
constants, cached endpoints, DNS destinations and addresses returned by servers.

Observed patcher result:
`UNSUPPORTED_PACKED_SKYPE_4_2_0_187`, exit 1, original client unchanged.

Historical primary research also describes Skype packing/self-integrity and
embedded authority keys: [Biondi/Desclaux, Silver Needle in the Skype](https://www.blackhat.com/presentations/bh-europe-06/bh-eu-06-biondi/bh-eu-06-biondi-up.pdf).
It is background, not a verified patch recipe for this particular version.

## Verification

```powershell
Invoke-Pester .\skyserver\tests\SkyPatch.Tests.ps1
.\skyserver\build.ps1 -Test
```

Tests cover backup/patch/restore/reapply, configuration updates, interrupted
transactions, unknown builds, corrupt backups, unrelated client edits, bad hunks,
key generation/reuse/private ACLs/public-only output, and native crypto vectors.
Passing these tests must not be reported as successful native Skype login.
