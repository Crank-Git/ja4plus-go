# JA4X

**JA4X fingerprints one X.509 certificate.** The image subtitle states the purpose:

> (fingerprints how a cert is created)

**The value reads object identifiers alone, and it reads no value of any field.** So two
certificates that one tool generated produce one value, whatever names they carry.

## The value

**One JA4X value holds three parts, and one underscore separates each pair of parts.** R1
of `docs/specs/foxio/JA4X.md` holds the reading, and the image example is
`96a6439c8f5c_96a6439c8f5c_aae71e8db6d7`.

| Part | What it holds | Rules |
|---|---|---|
| a | A truncated hash of the issuer object identifiers. | R4 |
| b | A truncated hash of the subject object identifiers. | R5 |
| c | A truncated hash of the certificate extension object identifiers. | R6 |

**Each list holds object identifiers and no value.** R7 quotes the image label:

> (does not include values)

**No step sorts a list.** R8 holds it, so each list keeps the certificate order. **Each
value reaches the list as the hex form of its content octets**, under R9, and a comma
separates each pair under R10. **Each hash is a SHA-256 truncated to twelve characters**,
under R11.

## What this library emits

`JA4XFingerprinter` produces the value. `NewJA4X` builds one, and `ProcessPacket` reads
one packet. Three functions read a certificate directly: `ComputeJA4XFromDER`,
`ComputeJA4XFromPEM` and `ComputeJA4XFromPacket`.

**One certificate produces one result.** The fingerprinter reassembles the TCP stream,
finds each TLS certificate handshake message, and reads every certificate of the chain.
**It writes one value for one certificate of one stream, and it repeats no value.**

**The result carries two forms of the fingerprint.**

| Field | What it holds |
|---|---|
| `Fingerprint` | The JA4X value. |
| `Raw` | `JA4X_r`, the unhashed form. |

**The raw form writes an empty part for an empty list, and it never writes the sentinel.**
The raw form hashes nothing, so it holds no hash to replace. `computeJA4XWithRaw` in
`ja4x.go` states the rule.

**The `Type` field holds `ja4x`.**

## Two readings this page carries

**One implementation of the FoxIO reference produces no JA4X value at all.** R13 records
that the Zeek package ships an empty load file for it.

**The FoxIO implementations split on the empty list.** R12 records that the reference Rust
and the Wireshark dissector write the zero sentinel `000000000000`, and that the reference
Python hashes the empty string and writes `e3b0c44298fc`. **The image itself shows both
forms**, in two different example values.

## Two defects that a deviation cluster measured

**A certificate that two live streams carried reached one value.** The state key held the
certificate hash alone until issue #489, and the key now names the stream too.
`docs/audit/ja4x-deviation-cluster.md` measured 36 deviations of that shape.

**The Go certificate parser refuses explicit elliptic curve parameters.** Issue #490
records the measurement, and `ja4x.go` falls back to `parser.ReadX509Identifiers` when
`crypto/x509` refuses the certificate.

## Where the register records a difference

`testdata/deviations.json` holds 6 entries under `JA4X` and 6 under `JA4X_r`, measured on
this branch. **Every one of the 12 sits under ruling `#375`**, and each one records this
reason:

> testdata/foxio/python/socks4-https.pcap.json and testdata/foxio/wireshark/socks4-https.pcap.json publish no JA4X key, and the port ruled at Crank-Git/ja4plus#138 that the three JA4X values on the SOCKS4 tunnel stay.
