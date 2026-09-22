# Call Audio Investigation

2026-09-22. The tester reports ringing and answer working but no audio. Neither
Skype nor skyserver was running during this investigation, so no live call was
captured. The following is code/log evidence, not a confirmed diagnosis of one
particular call or proof that the microphone works.

## Confirmed Gaps

- `NativeNodeDirectory.SlotReply` only implements username-slot discovery.
  Capability-based pool requests are explicitly left unanswered.
- `TcpProbeServer.ProcessBootstrapFrames` handles directory/bootstrap/transport
  traffic; there is no media relay allocation or audio-forwarding implementation.
- `ProbeUdpServer.TryBuildUdpProbeReply` ignores DA01 openers and otherwise emits
  a generic B3 probe response. It does not pair peers, negotiate media or forward
  their encrypted media packets. A listening UDP socket is not a VoIP service.
- The existing `presence-live-20260921-h/server.log` contains repeated unanswered
  command `0x2C` requests with `0/13=7` and `0/13=11,6`, plus `da01-no-reply`.
  Those logs are background presence-era evidence, not time-correlated to a call.
  The exact service meanings of those numeric IDs have not been established.

## Interpretation

Working call signaling does not prove media connectivity. Missing relay/service
discovery is a plausible blocker when direct peer media cannot connect. It is
not sufficient to conclude it caused the observed silence: direct media might
work without this server relaying it. NAT/firewall, a bad advertised endpoint,
audio-device selection or two local clients sharing a device remain candidates.
No guessed success replies were added for unimplemented media services.

## Next Reproduction

Use two different PCs/accounts and known-working microphones. Record exact call
start/answer/end times. Capture both client NICs (loopback too if local), with
their dynamic UDP ports included; compare idle, ringing, answered and hangup.
The existing `tools/Capture-SkypeTraffic.ps1` inventories Skype sockets and runs
a bounded dumpcap capture; specify a Skype PID if more than one instance runs.
Compare outgoing and incoming packet rates/addresses on both peers, correlate
service requests with server logs, and inspect client call/debug logs. Absence
of UDP alone is not conclusive because a fallback may use TCP. Encrypted media
need not be recognized as RTP by Wireshark. Do not publish captures or profiles.

Then distinguish: no media negotiation, endpoint/relay allocation failure,
one-way transport, or bidirectional media with device/codec failure. Implement
only the observed missing protocol stage and repeat the same call test.
