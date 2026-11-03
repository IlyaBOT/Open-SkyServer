# Client patcher

This directory contains public client-patching tooling and the developer build tools.

## User workflow

Obtain a server-specific public patch package from the operator. Run
`Patch-Skype.cmd` and select the original `Skype.exe`, or drop the original EXE
onto that command file. Currently only Skype 4.2.0.187 with SHA-256
`A2E175CE7C9888C125E2B3D4C2343229832BA0D0CD8A8A1CE120CE92624E856C` is supported.
Python 3 is required; the script installs pinned analysis modules in the package
directory on first use, without changing system Python packages.

The script reconstructs the original image locally, applies the operator's
public delta, checks the final hash, and creates a portable output directory
with `Skype.exe`, an exact original `.bak`, and an isolated profile. It creates
a desktop shortcut named `Skype 4.2.0.187 Patched`. The shortcut's launcher
configures search for newly created accounts, including after the first login.
The selected original executable is preserved. No hosts or IP redirect is needed.

Command-line use, including alternate output and diagnostic options:

```powershell
.\patcher\Patch-Skype.ps1 -ClientPath C:\CleanSkype\Skype.exe
.\patcher\Patch-Skype.ps1 -ClientPath C:\CleanSkype\Skype.exe `
  -PatchFile C:\CommunityPatch\dist\community.patch.json `
  -OutputDirectory C:\SkypePatched
```

The source checkout does not contain a deployment patch recipe. The recipe
belongs to a specific server address and authority. Its hashes detect damaged
or mismatched files; obtain the package from a trusted operator. Users receive
no private keys. Changing the server IP requires rebuilding the recipe.

## Operator workflow

Build a package using the same existing authority as the server:

```powershell
.\patcher\tools\New-CommunityPatch.ps1 `
  -ClientPath C:\CleanSkype\Skype.exe -KeysDirectory C:\SkyData\keys `
  -ServerIp 176.101.124.66 -OutputDirectory .\patcher\dist\wan-community
```

For a LAN-only package use `-ServerIp 192.168.1.170`. WAN clients use the public
address; a LAN client using that address requires working NAT loopback on the
router. A new authority can be generated explicitly with `-GenerateKeys`; this
requires installing its matching login/credential private keys on the server.
Do not replace an existing community authority just to rebuild its patch.

The wrapper reuses `skyserver-keygen.ps1`, reconstructs the offline image,
builds/signs the client, and emits a public delta plus user tools. Existing
complete key sets are reused. The optional `-ImagePath` reuses a hash-verified
canonical image, and `-PythonPath` / `-OpenSslPath` select developer tools.
Developer images and EXEs remain under ignored `patcher/diagnostics`; the public
package includes tools and changed byte spans, not private keys or profiles.

## Advanced tools

- `skypatch.ps1` is the older source template and public-constant input to the builder; use `Patch-Skype.ps1` for the simplified user workflow.
- `tools/` contains the Skype 4.2 inspection/rebuild/integrity utilities.
- `dist/` is generated output and is ignored except for `.gitkeep`.
- `client/` is local release staging for an already patched client build.

Generate a server-specific public patcher with:

```powershell
..\server\csharp\skyserver-keygen.ps1 -ServerIp 203.0.113.10 -ClientIntegrity
```

Private keys never belong in this directory.

`Start-Skype42Lab.ps1`, `Set-Skype42LabDirectory.ps1`, `Get-Skype42Presence.ps1`,
`Build-Skype42Lab.py` and the key generator remain available for isolated profiles,
protocol debugging and custom builds. The older full-client bundle/restore
workflow remains available through `New-ClientBundle.ps1`. For the current
server boundary and two-network test plan, see
[`WAN_CHECKPOINT.md`](../server/go/WAN_CHECKPOINT.md).
