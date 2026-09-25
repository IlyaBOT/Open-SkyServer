# Client patcher

This directory contains public client-patching tooling.

- `skypatch.ps1` is the source template. It contains placeholders for the server address and public authority moduli.
- `tools/` contains the Skype 4.2 inspection/rebuild/integrity utilities.
- `dist/` is generated output and is ignored except for `.gitkeep`.
- `client/` is local release staging for an already patched client build.

Generate a server-specific public patcher with:

```powershell
..\server\csharp\skyserver-keygen.ps1 -ServerIp 203.0.113.10 -ClientIntegrity
```

Private keys never belong in this directory.
