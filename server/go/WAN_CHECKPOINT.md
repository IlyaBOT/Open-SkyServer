# WAN interoperability checkpoint

Updated 2026-11-04. PR #6 has been merged into `main`.

## Current boundary

Native Skype 4.2.0.187 registration, login, directory lookup and document sync
have live evidence. Two clients on one Windows host exchanged native text over
a direct peer TCP connection. These tests do not establish cross-NAT delivery,
offline native delivery or audio relay. The HTTP message API is a separate path.

The main branch includes registration, node deadline fixes, restored signed
records after restart and the public delta patcher. The root README contains
the current setup instructions; this report retains the protocol evidence.

The operator confirmed that the Debian server is powered off during this pass.
SSH to its LAN address timed out. No WAN login or relay claim follows from the
local build and patch tests in this pass.

## Address configuration

The server's public address is `176.101.124.66`, its LAN address is
`192.168.1.170`. Bind listeners to the LAN interface or `0.0.0.0`, and advertise
the public address to WAN clients. Client patches and profile search settings
must target that public address and the same authority used by the server.

From `server/go` on Debian, after building with `sh ./build-linux.sh`:

```sh
sudo ./bin/openskyserver \
  --mode global --host 0.0.0.0 --advertise-ip 176.101.124.66 \
  --real-skype-probe --detailed-debug \
  --closed --allowlist /etc/openskyserver/allowlist.txt \
  --keys-dir /etc/openskyserver/keys \
  --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --blob-worker ./bin/skype_blob_worker
```

Forward the same external/internal TCP ports `80,443,12350,12351,13392,33033,
40001-40036` and UDP ports `12350,12351,13392,33033,40001-40036` to the LAN host.
The allowlist contains the testers' source IP addresses. The management API
stays on loopback port 33034. Listening probe ports do not implement media relay.

Command-30 endpoint observation previously replaced every private client IP
with the server's public IP. This corrupts genuine LAN endpoint observations.
The replacement now requires an exact, explicitly configured router SNAT source:
`--hairpin-source <observed-private-router-ip>` (repeatable). Leave it unset
unless a capture proves hairpin SNAT. Ordinary private and public client
addresses remain unchanged. This option cannot discover a client's UDP mapping
or make a router preserve the TCP source port.

## Missing protocol stages

- `0x06/0x08` implements username-slot discovery; capability-pool discovery and
  node `0x2C` service requests have no allocator.
- `0x0C/0x0D` publishes signed location records and `0x0E/0x0F` retrieves them.
  Their six-hour lease is a routing cache, not an online-status registry.
- `0x1784` queues contact requests; `0x1780` reports pending notifications.
  Nonempty `0x1781` event delivery, notification push and acceptance/decline
  semantics remain incomplete. Existing mutual contact documents do not test
  acceptance of a new request.
- UDP ignores `DA 01` and returns a generic `B3 04` probe response for other
  supported packets. Relay candidate allocation, connection-ID pairing and
  encrypted peer/media forwarding are absent.
- Historical `skyrelay3` client code requests candidates with `E2 02`, obtains a
  TCP connection ID (`0/3`) and pushes an endpoint/ID with `AA 03`. This is a
  source lead, not a decoded Skype 4.2 server implementation.
- Invisible/Offline propagation and an account-bound presence registry still
  need work. Node `0x25` field `0:55` was experimentally disproved as a status.

## Focused client evidence

REA 6.4.0 / Ghidra 12.1.4 completed a dossier for the original endpoint
classifier at VA `0056E350` through `0056E3A7` (88 bytes). Evidence ID:
`ev_26becc81ed8920de8c432ce313ab9f2e7b01ced1fac3c12df33d7050e9852741`.
Its assembly checks reject loopback, zero, RFC1918 ranges and a first octet of
255, and reject port values above 65535. The existing builder's exception
admits only its configured service address/ports. This confirms the leaf
classifier's behavior, not all caller paths or a WAN connectivity diagnosis.

The analysis used `Slice-SkypeAnalysis.py`: a single page at original RVA
`0016E000`, copied byte-for-byte from the canonical unpacked image SHA-256
`53ecb3032e76afe1db0a01eeb81e81f81c84e72d7cfae79dad3f197ca171d1ac`.
The derived PE SHA-256 is
`334604bdb579a1127cab6fa08be16c4b16d1c21c8001692e2a46aa177cc5bd60`.
The complete app import exceeded REA's 330-second startup limit; the slice
retains original function addresses but excludes callers and most application
state. It was never executed as a Windows process. The focused dossier and
source-to-slice byte hashes are retained privately under `patcher/diagnostics`.

## Next live experiment

Use two physical PCs: one on the server LAN and another on mobile data or an
independent ISP. Use isolated Skype profiles and the same server authority.
Record times and capture both NICs, including dynamic peer TCP/UDP ports.
First compare signed advertised endpoints to actually observed mappings; then
test a new contact request and acceptance, text both ways, offline retry, and
an answered audio call. Correlate each transition with the server log.

Classify the first failing stage: discovery, reachability, identity handshake,
notification, peer payload, or media transport. Implement an observed missing
stage before returning success for an unknown service. A ringing call alone
does not establish media connectivity. See `../csharp/CALL_AUDIO.md`.

## Regression command

```sh
SKYSERVER_BLOB_WORKER="$PWD/bin/skype_blob_worker" go test ./...
```

Build the 32-bit worker first. Its absolute path is required because Go runs
package tests from their package directories. Keep keys, profiles, databases,
capture files and generated client artifacts out of source control.
