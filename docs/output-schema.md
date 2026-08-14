# The output schema

This page states each field that a run emits. It reads the emitted keys from the code,
and it infers none of them.

**Two schemas exist, and a reader must not confuse them.**

- **`FingerprintResult`** is the library result. `types.go` declares it, and it carries
  ten fields.
- **`jsonResult`** is the record that the command-line program writes.
  `cmd/ja4plus/main.go` declares it, and it carries eight fields.

**The program emits a subset of the library result.** `## What the program does not emit`
below names each field that the program drops.

## The library result

A call to `ProcessPacket` returns a slice of `FingerprintResult`. `types.go` declares the
type, and it carries no `json` tag, because the library marshals nothing.

| Field | Go type | What it holds |
|---|---|---|
| `Fingerprint` | `string` | The fingerprint value. |
| `Raw` | `string` | The raw form of the value. |
| `OriginalOrder` | `string` | The value that keeps the order of the packet. |
| `RawOriginalOrder` | `string` | The raw form that keeps the order of the packet. |
| `Type` | `string` | The method name that produced the value. |
| `SrcIP` | `string` | The source address. |
| `DstIP` | `string` | The destination address. |
| `SrcPort` | `uint16` | The source port. |
| `DstPort` | `uint16` | The destination port. |
| `Timestamp` | `time.Time` | The timestamp of the packet that produced the value. |

**`Timestamp` reads the packet metadata, and never the clock of the host.** A caller that
sets no timestamp on the packet gives the library the zero time.

**A method that reaches no raw form leaves the field empty.** Read the field of the method
you asked for, and never assume that every method fills all four value fields.

## The JSON output

`--json` writes one JSON array for the whole run, and it writes no other line. The program
indents the array with two spaces. It is one document, and never one object per line.

`jsonResult` in `cmd/ja4plus/main.go` declares the record:

| Key | Go type | Present |
|---|---|---|
| `type` | `string` | Always. |
| `src_ip` | `string` | Always. |
| `src_port` | `uint16` | Always. |
| `dst_ip` | `string` | Always. |
| `dst_port` | `uint16` | Always. |
| `fingerprint` | `string` | Always. |
| `timestamp` | `string` | Always. |
| `application` | `string` | Only with `--lookup`, and only for a fingerprint that the table holds. |

**`application` carries `omitempty`.** A run without `--lookup` writes no `application`
key at all. A run with `--lookup` writes the key for a fingerprint that the mapping table
names, and it drops the key for every other fingerprint. `omitempty` also drops an
application name that is an empty string. So a reader tests for the key, and never for an
empty value.

**`timestamp` is a string, and never a number.** The program formats the packet timestamp
as RFC 3339.

**`src_port` and `dst_port` are JSON numbers.** The Go type is `uint16`, so each one holds
0 through 65535.

## The CSV output

`--csv` writes a header row and then one row for each result. `writeCSV` in
`cmd/ja4plus/main.go` writes both.

The header without `--lookup`:

```text
type,src_ip,src_port,dst_ip,dst_port,fingerprint,timestamp
```

**`--lookup` appends one column.** The header then ends `timestamp,application`, and each
row carries the extra field.

**The CSV output writes the same column set for every row of the run.** The JSON output drops the
`application` key for one record, and the CSV output writes an empty field in the same
case. The two formats differ here, and a reader that converts between them must handle
it.

## The table output

The program writes the table when the run sets neither `--json` nor `--csv`. `writeTable`
separates the columns with a tab, through `text/tabwriter`.

| Column | What it holds |
|---|---|
| `Type` | The method name. |
| `Source` | The source address and the source port, as `address:port`. |
| `Destination` | The destination address and the destination port, as `address:port`. |
| `Fingerprint` | The fingerprint value. |
| `Application` | The application name. `--lookup` adds this column. |

**The table joins the address and the port into one column.** The JSON output and the CSV
output keep the two apart. A script reads JSON or CSV, and a person reads the table.

## What the program does not emit

**The program prints the `Fingerprint` field alone, and it drops the three other value
fields.** No output format of `cmd/ja4plus` carries `Raw`, `OriginalOrder` or
`RawOriginalOrder`.

A caller who needs a raw form calls the library and reads the field from
`FingerprintResult`. The [usage guide](usage.md) holds a program that does it.

## Which methods reach the output

`--types` selects the methods, and `cmd/ja4plus/types.go` holds the accepted tokens. Two
tokens need a note.

- **`ja4l` prints the client value and the server value.**
- **`ja4ls` prints the server value alone.**

The usage text of the program states both sentences, and the
[implementation notes](implementation-notes.md) state why one fingerprinter writes both
values.

## The application lookup

`--lookup` calls `LookupFingerprint` for each result. That function reads the mapping
table, and it performs no network input and no network output.

**A fingerprint that the table does not hold produces no application name.** The lookup
returns `nil`, and the output drops the field. That is a miss in the table, and never an
error of the run.

`ja4plus db info` reports which table the run reads. The
[usage guide](usage.md) states that subcommand.
