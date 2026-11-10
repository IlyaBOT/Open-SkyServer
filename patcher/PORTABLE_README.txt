Skype 4.2.0.187 - Open-SkyServer portable client

Server: {SERVER_IP}:{SERVER_PORT}

1. Extract the entire ZIP into a writable local folder, not Program Files.
2. Double-click Start-Skype.cmd. Python and a Skype installation are not needed.
3. Sign in with your account on this Open-SkyServer community.

Windows 10/11 with Windows PowerShell 5.1 is the tested launcher environment.
An optional desktop shortcut "Skype 4.2.0.187 Patched" is created on first start.
An existing shortcut is never replaced. Run Start-Skype.cmd from this folder
if that shortcut belongs to another installation. Moving this folder may
invalidate its desktop shortcut; Start-Skype.cmd still works from the new path.

Keep this folder writable and keep Launch-Skype.ps1, Start-PortableSkype.ps1,
client.json and Skype.exe.bak next to Skype.exe. Do not run Skype.exe directly:
the launcher selects the isolated profile and maintains directory-search settings.
The small hidden PowerShell helper stays running while Skype is open.

The profile folder starts with server settings only. After sign-in it contains
your account, history and settings. Never re-upload or share a used profile.
To start fresh, close this client and extract the original ZIP into a new folder.
No passwords, account databases or private server keys are included in this ZIP.

This package does not edit hosts, routes, the firewall or an installed Skype.
No administrator privileges are required. A VPN may need a bypass rule for
{SERVER_IP}. LAN clients using the public address need router NAT loopback.

The server must be running and use the matching authority keys. This is an
experimental network, not Microsoft's retired Skype service. Login and contact
loading have been tested; cross-NAT chat, calls and media relay are still under
development. This archive alone does not fix server-side WAN limitations.

Skype.exe.bak is the exact original client, retained for verification/rollback.
SHA256SUMS.txt lists the shipped file hashes. Hashes detect damage, not publisher
identity: obtain the archive from a trusted operator. The outer ZIP SHA-256 is
provided separately by the operator. Do not run client files from unknown sources.
