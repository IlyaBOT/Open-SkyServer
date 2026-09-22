# Skype 4.2 unpacking checkpoint

Updated 2026-09-09. These are developer analysis tools, not a distributable patch.
The installed client has NOT been modified and original-client login has NOT
been achieved. A separate rebuilt copy now reaches the registration UI. Do not
launch a `.image.bin` as an executable or distribute the rebuilt commercial EXE.

## Exact Target

- Installed file: `C:\Program Files (x86)\Skype\Phone\Skype.exe`, version 4.2.0.187.
- Original SHA256: `A2E175CE7C9888C125E2B3D4C2343229832BA0D0CD8A8A1CE120CE92624E856C`.
- Actual repository: `I:\SkypeReverse\skypeopensource2`; the old `J:` path is stale.
- Ghidra: `E:\ghidra_11.2.1_PUBLIC`.
- Analysis directory: `skyserver/diagnostics/pe-analysis-20260907-233415`.
- Ghidra project `Skype42` contains both the original PE (with decoded loader
  modifications in the analysis database only) and a raw memory-layout import
  `Skype-uncompressed.image.bin`, base `0x00400000`, x86 Windows compiler.

## Reproduced Layers

1. Entry VA `0x0050f16e`: XOR byte with AL, rotate EAX left by 3, starting
   `0x8c705817`, range `0x004f92e0..0x0050f364`, skipping the entry's own 0x27 bytes.
   `tools/DecodeSkypeLoader.java` reproduces this only in Ghidra.
2. Descriptor VA `0x0101b000`: derive key from 0x204 bytes at `0x0050f160`
   with `h = (2*h + byte) XOR (h >> 31)`. Result `0x953dabff`. Decode offsets
   `4..0x87` by rotating left 3 BEFORE XOR. See `DecodeSkypeDescriptor.java`.
3. Descriptor fields 0x14/0x18 define checksum range `0x004f92e0..0x0050f364`.
   ELF-style checksum with seed `0xa9c35b72` gives `0x0d22e7fc`, XOR descriptor
   0x20 (`0x0d7216ec`) gives stage-two VA `0x0050f110`.
4. Stage two calls `0x004f93d0`. The payload cipher is `0x0050eee0`, descriptor
   in ECX. Its two DWORD ranges are `(0x00401000,0x3e0b8 words)` and
   `(0x0050f364,0x2bb127 words)` with initial state `0xea1713df`.
5. The decompressor is `0x0050e9f0`, ECX=descriptor, EDX=image base. Stack argument
   points at the bump allocator `{used, arenaBase}` used by `0x004f9330`.

`tools/Inspect-PackedSkype.py` uses pinned, repo-local Unicorn 2.1.4 and pefile
2024.8.26. It emulates ONLY the cipher and decompressor, with executable permission
only for the decoded loader pages, bounded time/instructions and no Windows API
implementation. It does not attach to a process or execute the client on Windows.

```powershell
py -3 skyserver/tools/Inspect-PackedSkype.py --seconds 120
```

Optional `--output <new diagnostics path>` creates a static memory-layout image,
not a rebuilt PE. It refuses overwrite and paths outside `skyserver/diagnostics`.
The original file is read-only. Three offline runs reproduced the same hashes:

- After cipher: `fdefe6834e0e1a9f598aa337fdadb08f0ac77ff55e23f089d3d6fa3b039fa897`.
- After decompression: `53ecb3032e76afe1db0a01eeb81e81f81c84e72d7cfae79dad3f197ca171d1ac`.

The payload restores ordinary PE sections and the main import directory at RVA
`0x00c5f000`, size `0x521a`. EntryRVA still points at the old packer, so changing
only keys and section raw offsets does NOT yet make a launchable client.

## Located Constants

RVA values below refer to the uncompressed IMAGE, never offsets in the original
packed FILE. Whole moduli are stored as LOWERCASE ASCII HEX, not binary integers.
This explains the negative binary-modulus scans from the previous checkpoint.

| Item | RVA | Length / Details |
| --- | --- | --- |
| Login RSA-1536 modulus | `0x00870ec9` | 384 ASCII hex characters |
| Credentials RSA-2048 modulus | `0x00871950` | 512 ASCII hex characters |
| Login server list | `0x0088a60c` | `193.88.6.13:33033 194.165.188.79:33033 195.46.253.219:33033` |
| Event server list | `0x0088a668` | `193.88.8.59:12350 194.165.188.76:12350 212.8.163.76:12350` |

The first three login IP RVAs also match the earlier READ-ONLY live-image scan:
`0x88a60c`, `0x88a61e`, `0x88a633`. Their settings names are
`*Lib/Connection/LoginServers` and `*Lib/Connection/EventServers`.
Constructor near VA `0x0056b090` references the login list at `0x0056b0b5`.
All these are public static program constants, not captured account data.

## Recovered Entry And Imports

The stage-two return value is masked AGAIN at `0x0050f195`:
`PUSH EAX; CALL stage2; XOR [ESP],EAX; RET`. The saved final stage-one rotation
value is `0x0bc6382c`. `--checksums-image <existing image>` reproduces the full
image checksum calculations and accounts for this final mask. Do not use the
intermediate masked return as an entry address.

Verified checksum results: before `6fad26b4`, after `0d02c7f0`, mixed `62afe144`.
Actual GUI entry is `0x01019fd4`. The secondary calculation gives private base
`0x004f1000`, initializer `0x00a90ee6`, import RVA `0x0080ab9c` relative to that
PRIVATE base, size `0x154`. There are 31 main and 16 private import descriptors.
The private INT/IAT/name RVAs need a `0xf1000` delta when merged into main imports;
ordinal imports keep their high-bit representation.

Original loader tail at `0x004f993a` also calls `0x0052b690` with EAX=main base
and one cdecl stack argument=SizeOfImage, sets byte `0x00d19a98` to 1, then calls
private CRT initialization as stdcall `(privateBase, 1, NULL)`. The lab PE keeps
this order in an added `.skyinit` section, preserves TLS, fixes section raw
offsets and imports, and jumps to the real GUI entry. No authentication check
or server RSA verification instruction is removed.

## Internal Integrity Table

The first lab build launched but displayed `Error: Unfortunately the Skype
executable is corrupted. Please re-install.` The user confirmed the exact text.
Call chain: initialization `0x01015bd0` -> `0x004f2b90` -> `0x0052ac10`.
This is an image-integrity check, not a server signature or Windows Authenticode
check. It verifies 13 regions using a 16-step MD5-like transform. Its table is
at `0x0052bd10`: triples of relative displacement, byte length, checksum.
DWORDs at `0x0052bd10..0x0052be0b` are zeroed while hashing. A partial final
block is zero-filled, without MD5's usual length suffix.

`tools/Skype42Integrity.py` reproduces ALL 13 original table values exactly.
The builder updates checksums as data, retaining the original checking code.
Tests execute that unchanged function offline in Unicorn: the rebuilt image
passes, and a one-byte key modification fails. Windows' optional PE CheckSum
is left zero because it and the internal table otherwise depend on each other.
The rebuilt file has no Authenticode signature; the original `.bak` is intact.

## Isolated Lab Build

```powershell
py -3 skyserver/tools/Build-Skype42Lab.py `
  --image skyserver/diagnostics/pe-analysis-20260907-233415/Skype-uncompressed.image.bin `
  --output-dir skyserver/diagnostics/portable-NEW
py -3 skyserver/tests/Skype42LabTests.py
```

Output must be a new diagnostics directory. The exact original and image hashes
are mandatory. Only the two PUBLIC XML files are read, never private key data.
The builder writes `Skype.exe.bak`, a rebuilt `Skype.exe`, and `build.json` with
patch/import/checksum inventories. It does not overwrite installed files or
existing backups. Current patch scope is both authority strings and 13 verified
server lists; non-list service endpoints, DNS names and cached IPs remain work
to do. Localhost/multicast/version strings are intentionally not treated as
server addresses. Production `skypatch` still has no verified packed profile.

`portable-20260909-v1` hash: `6a32558de76ddddc062e02a9a675b8e88057a5e39cbaf429aa70503d6b760355`.
This failed the integrity check and its owned PID 33764 was stopped.
`portable-20260909-v2` hash: `0cae8ebb71ade8c86f48a767b6dbcdc6f4ffc5e6228266e71b94cdc3b43d6e85`.
This started as PID 29788 with `/secondary /datapath:"<lab>/profile"`, created
that isolated `shared.xml`, and opened `Skype - Register`. Installed PID 26536
and its normal profile were not replaced. Login acceptance is still unverified.
Five offline lab tests pass, including original/rebuilt integrity and rejection
of tampering. This is not an end-to-end login test.

## Capture And Server

Wireshark CLI is now installed at `C:\Program Files\Wireshark`.
`tools/Capture-SkypeTraffic.ps1` uses explicit NPF GUIDs (interface numbers changed
between enumerations), a bounded filtered capture and a socket-ownership CSV.
Output ACL permits only the current user and SYSTEM. It does not modify hosts,
aliases, Skype settings or another Wireshark/dumpcap process.
Use `-SkypeProcessId` and `-SharedConfigPath` for a lab copy when multiple clients
are open. Optional `-ServerIp` adds port-scoped server traffic, not all traffic
from this machine's NIC. The capture also records the exact executable hash.

The corrected 90-second capture `capture-20260909-174118-79c95c79` contained no
packets and no Skype-owned TCP sockets. No login attempt was confirmed during
that interval; this is NOT proof of a protocol failure.

Server restarted with existing keys, native auth on `0.0.0.0:33033`, custom API
on `127.0.0.1:33034`; log directory `native-server-20260909-173734`.
The native signed response and historical credential tests are described in
`PATCHING.md`. Last full test run passed 12 TCP scenarios plus credential/crypto
tests; Pester passed 17 cases. Real DB remained 2 accounts, 2 contacts, 4 messages,
2 native verifiers, integrity check OK. Do not reset it or rotate the keys.
