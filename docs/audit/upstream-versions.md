# The upstream versions that the FoxIO pin records

**A JA4 reference implementation runs inside a host, and the host decides what the
implementation sees.** The FoxIO Wireshark plugin reads a field that a Wireshark core
dissector produces. The FoxIO Zeek package reads a record field that the Zeek analyzer
produces. **So a reading of a FoxIO implementation often has to read the host.** A host
that no pin names is a host the next reader cannot see.

This page records which host version the FoxIO pinned commit itself states. **It records a
measurement. It decides no fingerprint value, and it moves none.**

Issue #537 asked the question. `.claude/rules/external-apis.md` holds the two rows that
this page supports.

## The pin

| Fact | Value |
|---|---|
| FoxIO commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Pin file | `testdata/foxio.pin` |
| Measurement date | 2026-08-14 |

`scripts/fetch-corpus.sh:167` writes the whole FoxIO repository to
`testdata/foxio/reference/`, so every FoxIO citation of this page reads at base 1 of
`docs/specs/foxio/README.md` `## How to read a citation`. `testdata/foxio/.fetched` held
the commit above at the measurement.

## The result

| Host | Version | Where the pin states it |
|---|---|---|
| The Wireshark core dissectors | `v4.6.0` | `.github/workflows/wireshark-release.yml:15`, `:30` and `:55` |
| The Zeek analyzer | `8.0.0` | `.github/workflows/zeek-test.yml:21` |

**The pin records a version of each host, so this project adopts no version of its own.**
The decision comment of #537 states that order: a version the pin already records outranks
a version this project chooses.

## What this measurement searched

**A negative result needs the search that produced it.** The table below names every place
a version could sit.

| What | Result |
|---|---|
| A submodule | **The pinned tree holds no `.gitmodules`.** `.github/workflows/wireshark-test.yml:20` sets `submodules: true` against a tree that declares none. |
| Every CI workflow | `.github/workflows/` holds eight files. **Two name a version**, and the rows below name both. |
| The Zeek package metadata | `zkg.meta:7` states a floor. |
| The plugin build files | `wireshark/build-scripts/` holds `CMakeLists.txt`, `linux_build.sh`, `macos_build.sh` and `out_of_tree.sh`. **None of them pins a version.** |
| The prebuilt plugin binaries | `wireshark/binaries/` names three Wireshark versions in its directory paths. |
| Every text file of the tree | Two greps over `testdata/foxio/reference/`, which `## Reproduce the measurement` below states. |

## The Zeek analyzer

**`.github/workflows/zeek-test.yml:21` states the version, and it is exact.**

```
      image: zeek/zeek:8.0.0
```

**That is the container FoxIO runs its own Zeek tests in.** The job runs `btest -d Scripts/`
against `zeek/tests/`, at `.github/workflows/zeek-test.yml:36`. So `8.0.0` is the analyzer
version that the FoxIO Zeek package is known to pass under at the pin.

**`zkg.meta:7` states a floor, and a floor is not a version.**

```
depends = zeek >=5.0.0
```

A floor admits every release above it, so it names no source a reader can open.

## The Wireshark core dissectors

**`.github/workflows/wireshark-release.yml` hard-codes `v4.6.0` three times.** That
workflow builds the plugin binaries that FoxIO publishes.

| Line | Text |
|---|---|
| `:15` | `run:  cd wireshark/build-scripts && sudo apt update -y && sudo apt install ninja-build -y && sudo ./linux_build.sh v4.6.0` |
| `:30` | `run:  cd wireshark/build-scripts && ./macos_build.sh v4.6.0` |
| `:55` | `ref: v4.6.0` |

`wireshark/build-scripts/linux_build.sh:17` clones
`https://gitlab.com/wireshark/wireshark.git` at the tag its argument names, so `v4.6.0`
selects the Wireshark source tree that the released plugin compiles against.

**`wireshark/README.md:63` corroborates the version, and it names a second one.**

```
Install Wireshark 4.4.0 or later. The plugin has been tested with Wireshark versions 4.4.0 and 4.6.0.
```

**`wireshark/README.md:53` states a floor, and a floor is not a version.**

```
Current JA4+ Wireshark plugin releases support Wireshark 4.4.0 or later.
```

### Why `v4.6.0` and not `4.4.0`

**The pin names two tested versions, and one of them builds the release.** `v4.6.0` is the
version of `.github/workflows/wireshark-release.yml`, and `4.4.0` reaches the pin as a
floor and as a second tested version. **FoxIO builds the shipped plugin against one core,
and a reader who traces a plugin field reads that core.** So the rule file names `v4.6.0`.

**This project reverses that choice through issue #537**, and the reversal costs one row of
`.claude/rules/external-apis.md` and one constant of `upstream_versions_test.go`.

### What records no Wireshark version

**`.github/workflows/wireshark-test.yml` records none.** Line 24 adds
`ppa:wireshark-dev/stable`, and lines 37 to 39 read the version out of the installed
program at run time:

```
          TSHARK_VERSION=$(tshark --version \
            | head -n1 \
            | sed -E 's/.* ([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
```

**A version that a run derives is a moving version.** The same commit tests against a
different core on a different day, so that workflow names no source a reader can open.

**`wireshark/build-scripts/CMakeLists.txt:15` records none.**

```
find_package(Wireshark CONFIG REQUIRED)
```

The call carries no version argument, so it accepts whichever Wireshark development
package the build host holds.

**`linux_build.sh:11` and `macos_build.sh:11` record none.** Each one prints a usage
message when the caller passes no argument:

```
then echo "Enter a wireshark version (e.g. wireshark-4.4.0, v4.6.0)"; exit
```

**Those are example strings inside a message**, and neither one pins a build.

**`wireshark/binaries/` names three versions, and it pins nothing.** The tree holds
`linux/4.0.6`, `linux/4.2.0`, `linux/4.4.0`, `macos/4.2.0`, `macos/4.4.0`,
`windows/4.2.0` and `windows/4.4.0`. **Those directories record which cores FoxIO has
shipped a binary for**, and the release workflow states which core it builds today.

## The reading of #371, at the pinned versions

**#371 read the Wireshark core at v4.4.2 and the Zeek analyzer at v7.0.3. Neither version
equals the version the pin records.** So this page measured both cited ranges at both
version pairs. **The result splits, and the conclusion of #371 survives.**

### The Zeek citation survives

`zeek/ja4d/main.zeek:73` tests `options?$client_fqdn`, and #371 cites
`src/analyzer/protocol/dhcp/dhcp-options.pac:682-708` of the Zeek analyzer for the record
field.

**That range is byte-identical at v7.0.3 and at v8.0.0.** A `diff` of the two extracted
ranges reports no difference. `process_client_fqdn_option` opens at `:695` in both, and
`${context.flow}->options->Assign(21, std::move(client_fqdn));` sits at `:704` in both.

**So the #371 Zeek citation reads without a change at the pinned version.**

### The Wireshark citation does not resolve, and its conclusion holds

`wireshark/source/packet-ja4.c:1521` tests `dhcp.fqdn.name`, and #371 cites
`epan/dissectors/packet-dhcp.c:2596-2603` of the Wireshark core for the field.

**At v4.4.2 that range holds the FQDN branch.** At v4.6.0 the same eight lines hold DHCP
option 77 user class code, which is unrelated. **The branch moved to `:2689-2696`**, which
is 93 lines lower.

**The rule that #371 states holds at both versions.** The branch tests the same flag and
writes the same field at each one:

```
		if (fqdn_flags & F_FQDN_E) {
```

`hf_dhcp_fqdn_name` is written inside that branch at `:2599` under v4.4.2 and at `:2691`
under v4.6.0. **One line of the branch changed**: `get_dns_name` takes `pinfo->pool` as its
first argument at v4.6.0 and takes no pool argument at v4.4.2. **That change moves no
field and no condition.**

**So #371 needs a citation repair and no re-reading of its conclusion.** Its Wireshark
range must read `:2689-2696` against the pinned `v4.6.0`. **This page repairs no line of
#371**, because that issue is closed and this issue writes no ruling of another issue.

## The port disagrees with the pin, and the maintainer holds that question

**The port pins `Wireshark core dissectors | Release 4.4.2`.** The string `4.4.2` appears
nowhere in the FoxIO tree at the pin. **So the port names a version that the pinned commit
does not record**, and this repository names one that it does.

**`.claude/rules/parity.md` asks that both repositories read one version**, and the two
now differ. **This page opens no port issue and settles nothing.** The decision comment of
#537 states that a version the pin records outranks a version this project chooses. **This
page applies that rule to this repository alone.**

**The port carries no Zeek row at all**, so the port gains one row and changes one.

## Reproduce the measurement

Run `make corpus` first, which fetches the FoxIO repository at the pin.

```sh
grep -rn -iE 'wireshark[- _]?v?[0-9]+\.[0-9]+' testdata/foxio/reference &&
  grep -rn -iE 'zeek[^a-z]{0,12}[0-9]+\.[0-9]+' testdata/foxio/reference
```

The first command reports the Wireshark rows of this page, and the second reports the two
Zeek rows.

**The two commands below read a source outside this repository, and they reach the
network.** Each one reads a public tag of a public repository, and neither one writes
anything.

```sh
curl -fsSL "https://gitlab.com/wireshark/wireshark/-/raw/v4.6.0/epan/dissectors/packet-dhcp.c" |
  awk 'NR>=2689 && NR<=2696'
curl -fsSL "https://raw.githubusercontent.com/zeek/zeek/v8.0.0/src/analyzer/protocol/dhcp/dhcp-options.pac" |
  awk 'NR>=682 && NR<=708'
```

**This repository commits no line of either source.** Both are third-party material, and
`NOTICE` states the terms this project carries.

Verified against <https://gitlab.com/wireshark/wireshark/-/tree/v4.6.0/epan/dissectors>
and <https://github.com/zeek/zeek/tree/v8.0.0/src/analyzer/protocol>, retrieved
2026-08-14.

## What this page does not do

- **It moves no fingerprint value.**
- **It writes no entry of `testdata/deviations.json`.**
- **It changes no count of `CHANGELOG.md`.**
- **It rules nothing.** `.claude/rules/rulings.md` states who rules, and a version record
  is neither a reading of a fingerprint rule nor a ruling.
