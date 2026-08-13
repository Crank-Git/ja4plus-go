# Parity with the port

The port is the Python implementation at `Crank-Git/ja4plus`. A user who runs both
implementations must get one answer, so this page records what each name of the port maps
onto in this library.

**This page records a reading, and it records no ruling.** A reading concludes what a
source states, and only the maintainer makes a ruling.
`.claude/rules/rulings.md` holds the two words.

## Where the names were read

| Record | Value |
|---|---|
| Repository | <https://github.com/Crank-Git/ja4plus> |
| Version | `v1.1.0` |
| Commit | `21299645366591331eb93155355b65a76a3729f3` |
| File | `ja4plus/__init__.py` |
| Blob | `d901aa690c6d6f36b542d0317372ec053760a55b` |
| Read | 2026-08-12 |
| Promised names | 25 |

**Read the port at the tag, and never at the tip.** The tip carried five commits past
`v1.1.0` on the read date. A reading of a moving branch is a reading of something the next
reader cannot see.

Reproduce the record with these commands, from a clone of the port:

```
git -C ja4plus rev-parse v1.1.0
git -C ja4plus rev-parse v1.1.0:ja4plus/__init__.py
git -C ja4plus show v1.1.0:ja4plus/__init__.py
```

## Which names this page counts

**This page counts the `__all__` list of `ja4plus/__init__.py`, and it counts nothing
else.** That list holds 25 names.

**A promised name is a name of that list.** This page uses the word for that meaning alone.

The port states the reason in its own comment on the list. The list names what a caller may
import from `ja4plus`. **A name absent from the list is not promised.** The port also states
that a module declares its own public names in its own `__all__`. **A public name of a
submodule therefore reaches no row here**, because the port promises no submodule name.

The two counts differ, and this page names the one it counted. `ja4plus/cli.py`,
`ja4plus/watch.py`, `ja4plus/output.py`, `ja4plus/ja4db.py` and the ten modules of
`ja4plus/utils/` each hold public names that this page does not count.

## How to read a row

- **The port location** cites a file and a line at the commit above.
- **The Go equivalent** holds one exported name of package `ja4plus`, or it holds
  `` `none` `` with `applicable` or `not applicable`.
- **`applicable`** states that a Go equivalent belongs in this library and is absent.
- **`not applicable`** states that the name answers a Python question that Go does not ask.
- **The reason** carries one sentence. A row that names a Go equivalent needs none.

`parity_table_test.go` reads this table. It fails on each of these.

- A row disappears, or two rows name one port name.
- A row names a name that the port does not promise.
- The `Promised names` count differs from the count of rows.
- A row names a Go name that package `ja4plus` does not export.
- A row cites a port module without a line number.

## The table

<!-- parity-table:begin -->

| Port name | Kind | Port location | Go equivalent | Reason |
|---|---|---|---|---|
| `FingerprintResult` | class | `ja4plus/types.py:22` | `FingerprintResult` | |
| `Processor` | class | `ja4plus/processor.py:96` | `Processor` | |
| `JA4Fingerprinter` | class | `ja4plus/fingerprinters/ja4.py:355` | `JA4Fingerprinter` | |
| `JA4SFingerprinter` | class | `ja4plus/fingerprinters/ja4s.py:42` | `JA4SFingerprinter` | |
| `JA4HFingerprinter` | class | `ja4plus/fingerprinters/ja4h.py:61` | `JA4HFingerprinter` | |
| `JA4LFingerprinter` | class | `ja4plus/fingerprinters/ja4l.py:90` | `JA4LFingerprinter` | |
| `JA4XFingerprinter` | class | `ja4plus/fingerprinters/ja4x.py:123` | `JA4XFingerprinter` | |
| `JA4SSHFingerprinter` | class | `ja4plus/fingerprinters/ja4ssh.py:62` | `JA4SSHFingerprinter` | |
| `JA4TFingerprinter` | class | `ja4plus/fingerprinters/ja4t.py:36` | `JA4TFingerprinter` | |
| `JA4TSFingerprinter` | class | `ja4plus/fingerprinters/ja4ts.py:192` | `JA4TSFingerprinter` | |
| `JA4DFingerprinter` | class | `ja4plus/fingerprinters/ja4d.py:231` | `JA4DFingerprinter` | |
| `JA4D6Fingerprinter` | class | `ja4plus/fingerprinters/ja4d6.py:302` | `JA4D6Fingerprinter` | |
| `generate_ja4` | function | `ja4plus/fingerprinters/ja4.py:111` | `ComputeJA4` | |
| `generate_ja4s` | function | `ja4plus/fingerprinters/ja4s.py:359` | `ComputeJA4S` | |
| `generate_ja4h` | function | `ja4plus/fingerprinters/ja4h.py:547` | `ComputeJA4H` | |
| `generate_ja4l` | function | `ja4plus/fingerprinters/ja4l.py:607` | `none`, applicable | JA4L reads the SYN and the SYN-ACK, so a one-packet call reaches no value, and #356 asks the maintainer which shape a Go equivalent takes. |
| `generate_ja4x` | function | `ja4plus/fingerprinters/ja4x.py:46` | `ComputeJA4XFromPacket` | |
| `generate_ja4ssh` | function | `ja4plus/fingerprinters/ja4ssh.py:670` | `none`, applicable | JA4SSH reads a window of packets, so a one-packet call reaches no value, and #356 asks the maintainer which shape a Go equivalent takes. |
| `generate_ja4t` | function | `ja4plus/fingerprinters/ja4t.py:133` | `ComputeJA4T` | |
| `generate_ja4ts` | function | `ja4plus/fingerprinters/ja4ts.py:312` | `ComputeJA4TS` | |
| `generate_ja4d` | function | `ja4plus/fingerprinters/ja4d.py:188` | `ComputeJA4D` | |
| `generate_ja4d6` | function | `ja4plus/fingerprinters/ja4d6.py:257` | `ComputeJA4D6` | |
| `compute_ja4x_from_der` | function | `ja4plus/__init__.py:51` | `ComputeJA4XFromDER` | |
| `compute_ja4x_from_pem` | function | `ja4plus/__init__.py:64` | `ComputeJA4XFromPEM` | |
| `__version__` | attribute | `ja4plus/__init__.py:101` | `none`, not applicable | `runtime/debug.ReadBuildInfo` reads the version of a Go module from the running binary, so a library needs no version name of its own. |

<!-- parity-table:end -->

## What the table shows

**Twenty-two of the 25 promised names reach a Go name, and three reach none.** Two of the
three are one-shot functions for a method that reads more than one packet, and the third is
the version attribute.

**Eight `Compute*` functions answer ten `generate_*` functions.** `ComputeJA4`,
`ComputeJA4S`, `ComputeJA4H`, `ComputeJA4XFromPacket`, `ComputeJA4T`, `ComputeJA4TS`,
`ComputeJA4D` and `ComputeJA4D6` each read one packet, and each matching method reads one
packet.

**`generate_ja4l` and `generate_ja4ssh` each take a second parameter that holds the
connection state.** The port makes the caller hold that state, and this library holds it
inside `JA4LFingerprinter` and `JA4SSHFingerprinter`. Parity rule 2 states that the port
decides interface where this project shipped nothing. **The rule names an interface, and it
states no shape.** **#356 records the question, and this page records no answer.**

**Three Go names answer one port name.** The port promises `compute_ja4x_from_der`,
`compute_ja4x_from_pem` and `generate_ja4x`, and this library exports `ComputeJA4XFromDER`,
`ComputeJA4XFromPEM` and `ComputeJA4XFromPacket`. Each pair reads the same input.

## The one `not applicable` row, and how to reverse it

**The `__version__` row records a fact of the Go language, and it records no preference.**
`runtime/debug.ReadBuildInfo` returns the build information that the running binary carries,
and that information holds the module version. A Python module carries no such mechanism, so
the port declares the version as an attribute. `cmd/ja4plus/main.go:35` holds
`var Version = "dev"`, which the linker sets for the command and not for the library.

**A reader who disagrees reverses the row with one action.** Open an issue that states which
caller needs a version name in the library, and change the row to `` `none` ``,
`applicable`. **The maintainer confirms this row, or reverses it.** Until the maintainer
confirms it, a later reader reads it as unconfirmed.

**This page states no ruling.** Parity rule 2 assigns an interface question to the
maintainer, and #356 carries the two questions of this page that need one.

## What this page does not record

**A name the port adds after 2026-08-12 reaches no test on this page.** No test here reads
the port, because a cross-language test rig couples two repositories that move at different
speeds. FR-parity-58 of `docs/specs/features/08-python-parity.md` owns the drift of the
port's own register, and `docs/specs/foxio/port-register.md` holds the copy it reads.

**This page records no fingerprint value.** `testdata/deviations.json` holds one entry for
each accepted difference from a FoxIO value, and the `## Parity with ja4plus` section of
`docs/specs/spec.md` holds the divergence register.

**This page records no Go name that the port does not promise.** `Fingerprinter`,
`WindowCloser`, `SyncProcessor`, `GetShardKey`, `CloseOpenWindows`, `LookupFingerprint` and
the key log names each answer a Go question, and no row of the table reaches them.

Verified against: <https://github.com/Crank-Git/ja4plus> (`ja4plus/__init__.py` at
`v1.1.0`, blob `d901aa690c6d6f36b542d0317372ec053760a55b`, retrieved 2026-08-12).
