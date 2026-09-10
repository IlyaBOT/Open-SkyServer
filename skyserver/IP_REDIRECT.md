# Local redirection of Skype server IPs

`skype_ip_redirect.ps1` uses Windows NetTCPIP commands to add selected IPv4 /32
addresses to the loopback interface. Windows can then deliver connections to those
addresses to a locally listening server. This is local address assignment, not
DNAT to 127.0.0.1: the original destination IP and port are preserved. It covers TCP
and UDP for those IPs, for all processes on this computer.

The default list contains the five bootstrap IPs observed from the installed
4.2.0.187 client and three login servers from the supplied protocol logs. The
current HostCache is also read through the server's existing parser. Unknown IPs,
IPv6 and destinations learned later are not automatically intercepted. Add an
observed IP to `skype_ip_targets.txt` or pass `-AdditionalIPAddress` and enable again.
This list is not a claim to enumerate every Skype server/version.

## Use

From the repository directory, inspect the plan without elevation:

```powershell
.\skyserver\skype_ip_redirect.ps1 -Action Plan
.\skyserver\skype_ip_redirect.ps1 -Action Enable -WhatIf
```

From an Administrator PowerShell:

```powershell
.\skyserver\skype_ip_redirect.ps1 -Action Enable
```

If execution policy prevents running the script, invoke it with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\skyserver\skype_ip_redirect.ps1 -Action Enable
```

The server must listen on the aliased addresses. A listener restricted to
127.0.0.1 cannot receive packets addressed to an alias. Keep the HTTP API local:

```powershell
.\skyserver\bin\Release\skyserver.exe --host 0.0.0.0 --api-host 127.0.0.1 --real-skype-probe --include-hostcache-probe
```

Run one server instance. Retry login after listeners and aliases are ready; an
already pending connection may still follow the previous route. Do not clear or
seed HostCache to disable supernode promotion: those are unrelated operations.

Inspect/undo:

```powershell
.\skyserver\skype_ip_redirect.ps1 -Action Status
.\skyserver\skype_ip_redirect.ps1 -Action Disable
```

If custom `-StatePath` or `-SkypeSharedXml` parameters are used, keep the same state
path for rollback and give the server the same XML file via `--skype-shared-xml`.
The older `skype55_loopback_alias_on/off.ps1` entry points now delegate to this
implementation. Old unjournaled aliases are preserved, not guessed and deleted.

## Ownership and limits

- Changes use **ActiveStore only**, so they expire at reboot. `SkipAsSource` avoids
  choosing the public aliases as source IPs for unrelated outgoing connections.
- The original weak-host send/receive settings and pre-existing addresses are
  recorded before applying changes. IPv4 weak-host mode is enabled only on loopback.
- Disable removes only journaled aliases, restores previous settings where they
  have not been changed by others, and preserves conflicts for manual inspection.
- The JSON journal includes the boot identifier and the pending address operation.
  Keep it until Disable. A previous boot's journal does not authorize changing the
  current network. Concurrent entry-point invocations use an exclusive file lock.
- hosts, the Skype binary/profile, DNS, VPN and firewall settings are not changed.
  Existing hosts mappings remain as they were. New aliases affect every application
  connecting to the listed IPs, not just Skype.exe.
- A VPN/WFP driver can still affect delivery. Live TCP/UDP routing and actual Skype
  packets must be verified after elevated application; a successful plan or a mocked
  test does not prove live traffic redirection.
- This only addresses routing. Native authentication still needs the RSA/AES and
  signed-credential implementation described in `STOCK_CLIENT_STATUS.md`.

## Verification

The implementation's ownership/rollback tests replace the OS network commands with
mocks. They do not change the machine's networking:

```powershell
Invoke-Pester .\skyserver\tests\IpRedirect.Tests.ps1
```

On 2026-09-06 the live plan found eight targets and no existing aliases. The agent
terminal was not elevated, so aliases were **not applied** and live routing was
not claimed as verified. Ten mocked tests passed: temporary addresses, restoration,
idempotence, pre-existing addresses, partial failure, interrupted operations,
external modifications, reboot, invalid state, and address conflicts.

Microsoft documents [New-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netipaddress)
and [netsh interface](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface).
`portproxy` supports TCP only, so it alone is not a TCP+UDP Skype redirector.
