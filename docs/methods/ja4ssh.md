# JA4SSH

**JA4SSH fingerprints one window of SSH packets.** SSH encrypts its payload, so the method
reads packet sizes and packet counts instead of content. **One connection produces one
value for each window it fills.**

## The value

**One JA4SSH value holds three parts, and one underscore separates each pair of parts.** R1
of `docs/specs/foxio/JA4SSH.md` holds the reading, and the image example is
`JA4SSH=c36s36_c55s75_c70s0`.

**Each part writes `c` and the client number, then `s` and the server number.** R4 holds
the form.

| Part | What it holds | Rules |
|---|---|---|
| a | The mode of the TCP payload length of each side. | R10 to R13 |
| b | The count of SSH packets of each side. | R14 |
| c | The count of bare ACKs of each side. | R15 to R17 |

**The mode is the payload length that the side sent most often.** R11 states that a tie
takes the lower value. **The mode is `0` when the side sent no SSH packet**, under R13.

**A bare ACK is one TCP packet whose flags equal `0x10` and whose payload is empty.** R16
holds the reading.

## The window

**The default window is 200 SSH packets.** R6 records that the Zeek package and the
Wireshark dissector each hold that number. **No bare ACK counts toward the window**, under
R7, and the counters reset when the window closes under R8.

## What this library emits

`JA4SSHFingerprinter` produces the value. `NewJA4SSH` takes the window size, and a size of
`0` selects the default of 200. `ProcessPacket` reads one packet.

**The fingerprinter emits a value at two points.** It emits when the packet count of the
window reaches the window size. It also emits on a packet that carries the FIN flag and the
ACK flag, which closes the connection.

**A window that a connection still holds open is an open window, and the caller decides
what happens to it.** Two methods reach one.

| Method | What it does |
|---|---|
| `CloseOpenWindows` | Emits the open window of every connection. |
| `CloseConnectionWindow` | Emits the open window of one connection, then removes it. |

**Each method is opt-in, and the library forces no flush.** A caller that never calls one
loses the open window. `Processor` dispatches to each of the two through the `WindowCloser`
interface and the `ConnectionWindowCloser` interface.

**`CleanupConnection` emits nothing.** Issue #216 holds that question, and the maintainer
owns it, because both candidate answers change the exported surface.

**The `Type` field holds `ja4ssh`.** `GetHASSHFingerprints` reports the HASSH values that
the fingerprinter read from the SSH key exchange.

## One question that the FoxIO implementations split on

**Which side of the connection sends the bare ACKs.** R23 records that the Wireshark
dissector and the reference Python read TCP port 22, and that the Zeek package and the
reference Rust read the connection direction.

**The library carries step 2 of the client direction, under a provisional decision of
2026-08-13.** `decideEndpoints` in `ja4ssh.go` holds it, and the doc comment of that
function names the reversal path. **A reversal deletes step 2.**

## Where the register records a difference

`testdata/deviations.json` holds 20 entries under keys of the form `JA4SSH.N`, measured on
this branch. Three rulings cover them: 4 under `#223`, 14 under `#484` and 2 under `#491`.

**Ruling `#223`, which the maintainer confirmed on 2026-08-12.**

> The maintainer ruled on 2026-08-12 that the part a mode reads its own window, and `python/ja4ssh.py:8` shares one payload list across the windows.

**Ruling `#484`, of 2026-08-14.**

> The maintainer ruled on 2026-08-14 that the library clears the counters at the first FIN+ACK packet, so a later FIN+ACK packet reaches an empty window.

**Ruling `#491`, of 2026-08-14.**

> The maintainer ruled on 2026-08-14 that the server count 21 describes the stalled tshark reassembly, and no consistent SSH framing rule reaches it.
