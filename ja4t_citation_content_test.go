package ja4plus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `docs/specs/foxio/JA4T.md` cites a line of a FoxIO reference implementation for each
// rule it states, and this file holds every one of those citations against the content of
// the line it names.
//
// TestNoCitationOfTheFoxioDirectoryNamesALinePastTheEndOfItsFile reads the same page, and
// it asserts a bound alone: the cited number is at or below the line count of the file. A
// citation that names the comment above the code it describes passes that bound, because
// the comment is in range. #726 measured three such citations on this page, and the port
// measured six on its own copy in `Crank-Git/ja4plus#637`. So a bound is not enough, and
// this file reads content.
//
// The table below is the whole guard. Each row names one citation of the page, and it
// names the text that the cited line must hold. A row fails when the citation moves, and
// it fails when a moved pin moves the source line.

// ja4tCitationPage is the page this file guards.
const ja4tCitationPage = "docs/specs/foxio/JA4T.md"

// ja4tCitationPreambleLine is the line of the page that states how to read a citation.
//
// That line names `zeek/ja4t/main.zeek:180` as an example of the join rule, and it states
// no fact about the content of line 180. So the table below holds no row for it, and
// TestThePreambleOfTheJA4TPageHoldsOneCitation fails when the preamble moves.
const ja4tCitationPreambleLine = 20

// ja4tCitationCorpusAbsentMessage states why this file checked nothing.
//
// A silent skip is not a guard. The sentence carries no word of `conformanceSkipMarker`,
// because `.github/workflows/ci.yml` fails the conformance job on that marker and this
// skip means something else.
const ja4tCitationCorpusAbsentMessage = "this guard read no FoxIO corpus at " +
	foxioCorpusReferenceDir + "; run `make corpus` to read the cited lines."

// ja4tCitation is one citation of the page, and the text the cited line must hold.
type ja4tCitation struct {
	// pageLine is the line of `docs/specs/foxio/JA4T.md` that holds the citation.
	pageLine int
	// path names the file, joined to `testdata/foxio/reference/`.
	path string
	// number is the cited line of that file.
	number int
	// want is the text that line holds. It is the literal the page quotes, where the page
	// quotes one, and the statement the page names otherwise.
	want string
}

// ja4tCitationContent holds one row for each substantive citation of the page, in page
// order. The preamble of line 20 carries no row, and `ja4tCitationPreambleLine` states
// why.
//
// Three rows carry a number that #726 repaired on 2026-08-15 UTC. R26 named
// `rust/ja4/src/tcp.rs:129`, which holds `.options` of the join chain. R28 named
// `wireshark/source/packet-ja4.c:673`, which holds the arguments and not the format
// string. R29 named `rust/ja4/src/tcp.rs:153`, which holds the comment above the
// assertion.
var ja4tCitationContent = []ja4tCitation{
	// R5 — the separator.
	{45, "zeek/config.zeek", 4, `option delimiter: string = "_";`},
	{46, "zeek/ja4t/main.zeek", 197, `c$conn$ja4t += FINGERPRINT::delimiter;`},
	{47, "wireshark/source/packet-ja4.c", 670, `"%d_%s_%02d_%02d"`},
	{48, "rust/ja4/src/tcp.rs", 136, `"{}_{}_{}_{}"`},

	// R6 and R7 — part a, the window size.
	{53, "zeek/ja4t/main.zeek", 132, `rph$tcp$win`},
	{54, "wireshark/source/packet-ja4.c", 1257, `tcp.window_size_value`},
	{55, "rust/ja4/src/tcp.rs", 66, `tcp.window_size_value`},
	{58, "rust/ja4/src/tcp.rs", 65, `// Extract window size (raw, before scaling)`},
	// The page quotes `rph$tcp$win`, and line 132 above stores that value under this
	// name. Line 196 writes the stored value, and it applies no window scale.
	{59, "zeek/ja4t/main.zeek", 196, `c$fp$ja4t$syn_window_size`},

	// R8, R9 and R10 — part b, the option kinds.
	{65, "zeek/ja4t/main.zeek", 99, `opts$option_kinds += opt_kind;`},
	{66, "wireshark/source/packet-ja4.c", 1456, `tcp.option_kind`},
	{67, "rust/ja4/src/tcp.rs", 70, `tcp.option_kind`},
	{69, "zeek/ja4t/main.zeek", 199, `"-"`},
	{70, "wireshark/source/packet-ja4.c", 1458, `"%d-"`},
	{70, "rust/ja4/src/tcp.rs", 133, `.join("-")`},
	// The page names the break, and line 97 holds it. Line 96 opens the branch that the
	// same sentence names, so the citation reads at the head of a two-line construct.
	{73, "zeek/ja4t/main.zeek", 96, `if (opt_kind == 0) {`},
	{75, "wireshark/source/packet-ja4.c", 1456, `tcp.option_kind`},
	{76, "rust/ja4/src/tcp.rs", 70, `tcp.option_kind`},

	// R11 — part c, the maximum segment size.
	{85, "zeek/ja4t/main.zeek", 110, `opts$max_segment_size =`},
	{86, "wireshark/source/packet-ja4.c", 1461, `tcp.options.mss_val`},
	{87, "rust/ja4/src/tcp.rs", 77, `tcp.options.mss_val`},

	// R12 — part d, the window scale.
	{93, "zeek/ja4t/main.zeek", 113, `opts$window_scale =`},
	{94, "wireshark/source/packet-ja4.c", 1464, `tcp.options.wscale.shift`},
	{95, "rust/ja4/src/tcp.rs", 82, `tcp.options.wscale.shift`},

	// R16 and R17 — part e reaches JA4TS.
	{106, "zeek/ja4t/main.zeek", 231, `c$conn$ja4ts += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$synack_delays`},
	{107, "zeek/ja4t/main.zeek", 212, `@if(FINGERPRINT::JA4TS_enabled)`},
	{108, "wireshark/source/packet-ja4.c", 686, `for (int i = 1; i < conn->syn_ack_count; i++)`},
	{109, "wireshark/source/packet-ja4.c", 1595, `hf_ja4ts`},
	{112, "zeek/ja4t/main.zeek", 229, `|c$fp$ja4t$synack_delays| > 0`},
	{113, "wireshark/source/packet-ja4.c", 684, `conn->syn_ack_count > 1`},

	// R18 — the two delay counts.
	{116, "zeek/ja4t/main.zeek", 28, `synack_delays: vector of count &default=vector();`},
	{117, "zeek/ja4t/main.zeek", 180, `c$fp$ja4t$synack_delays +=`},
	{118, "zeek/ja4t/main.zeek", 185, `if (|c$fp$ja4t$synack_delays| == 10) {`},
	{121, "wireshark/source/packet-ja4.c", 234, `#define MAX_SYN_ACK_TIMES 10`},
	{122, "wireshark/source/packet-ja4.c", 1290, `conn->syn_ack_count < MAX_SYN_ACK_TIMES`},
	{124, "wireshark/source/packet-ja4.c", 686, `for (int i = 1; i < conn->syn_ack_count; i++)`},

	// R19, R20 and R21 — which packet each method reads.
	{159, "zeek/ja4t/main.zeek", 126, `rph$tcp$flags != TH_SYN`},
	{160, "wireshark/source/packet-ja4.c", 1266, `tcp_flags == 0x02`},
	{161, "rust/ja4/src/tcp.rs", 61, `is_initial_syn(flags)`},
	{163, "zeek/ja4t/main.zeek", 171, `rph$tcp$flags == (TH_SYN | TH_ACK)`},
	{164, "zeek/ja4t/main.zeek", 177, `c$fp$ja4t$synack_window_size = rph$tcp$win;`},
	{165, "wireshark/source/packet-ja4.c", 1279, `tcp_flags == 0x012`},
	{167, "rust/ja4/src/tcp.rs", 47, `/// Only the first SYN without ACK is processed.`},
	{167, "rust/ja4/src/tcp.rs", 136, `"{}_{}_{}_{}"`},

	// R22 and R23 — the two stops of the JA4TS measurement.
	{169, "zeek/ja4t/main.zeek", 162, `ts - c$fp$ja4t$last_ts > 120000000`},
	{172, "zeek/ja4t/main.zeek", 138, `ConnThreshold::set_packets_threshold`},
	{173, "zeek/ja4t/main.zeek", 146, `c$fp$ja4t$synack_done = T;`},

	// R24 and R25 — the rounding split.
	{180, "zeek/ja4t/main.zeek", 180, `c$fp$ja4t$synack_delays += double_to_count(ts - c$fp$ja4t$last_ts)/1000000;`},
	{180, "zeek/ja4t/main.zeek", 162, `120000000`},
	{183, "wireshark/source/packet-ja4.c", 277, `return (int64_t)(round(nstime_to_sec(&result)));`},
	{183, "wireshark/source/packet-ja4.c", 687, `timediff(`},
	{188, "zeek/ja4t/main.zeek", 233, `fmt("-R%d", double_to_count(c$fp$ja4t$rst_ts - c$fp$ja4t$last_ts)/1000000)`},
	{189, "wireshark/source/packet-ja4.c", 694, `timediff(`},

	// R26 — the empty option list.
	{191, "zeek/ja4t/main.zeek", 201, `"00"`},
	{192, "wireshark/source/packet-ja4.c", 671, `"00"`},
	{193, "rust/ja4/src/tcp.rs", 133, `.join("-")`},

	// R27 — a maximum segment size of zero.
	{197, "zeek/ja4t/main.zeek", 204, `fmt("%02d"`},
	{198, "wireshark/source/packet-ja4.c", 670, `%02d`},
	{199, "rust/ja4/src/tcp.rs", 139, `self.mss.unwrap_or(0)`},

	// R28 — a window scale of zero.
	{201, "zeek/ja4t/main.zeek", 207, `"00"`},
	{202, "wireshark/source/packet-ja4.c", 670, `%02d`},
	{203, "rust/ja4/src/tcp.rs", 140, `self.window_scale.unwrap_or(0)`},

	// R29 — the SYN that carries the ECN flags.
	{207, "rust/ja4/src/tcp.rs", 146, `(flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0`},
	{208, "rust/ja4/src/tcp.rs", 154, `assert!(is_initial_syn(0xC2));`},
	{209, "zeek/ja4t/main.zeek", 126, `rph$tcp$flags != TH_SYN`},
	{210, "wireshark/source/packet-ja4.c", 1266, `tcp_flags == 0x02`},

	// R30 — the reset packet.
	{213, "zeek/ja4t/main.zeek", 167, `rph$tcp$flags & TH_RST != 0`},
	{214, "wireshark/source/packet-ja4.c", 1296, `tcp_flags == 0x004`},
}

// ja4tPageCitation returns every substantive citation of the page, in page order.
//
// A span that carries no `:line` suffix names a whole file, and this guard reads a line.
// The page holds twelve such spans outside its preamble line, measured on 2026-08-15 UTC,
// and `foxioCitation.number` reads 0 for each one.
func ja4tPageCitation(t *testing.T) []foxioCitation {
	t.Helper()

	var page []foxioCitation

	for _, citation := range foxioReadCitation(t) {
		if citation.page != ja4tCitationPage || citation.line == ja4tCitationPreambleLine {
			continue
		}

		if citation.number == 0 {
			continue
		}

		page = append(page, citation)
	}

	if len(page) == 0 {
		t.Fatalf("%s holds no citation outside its preamble", ja4tCitationPage)
	}

	return page
}

// ja4tSourceLine returns the named line of the named file of the corpus. It returns an
// empty string when the file holds no such line.
func ja4tSourceLine(t *testing.T, path string, number int) string {
	t.Helper()

	file := filepath.Join(foxioCorpusReferenceDir, filepath.FromSlash(path))

	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("open %s: %v", file, err)
	}

	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if number < 1 || number > len(lines) {
		return ""
	}

	return lines[number-1]
}

// The table names one citation for each citation of the page, in page order. A count that
// disagrees means the page gained a citation, or it lost one, and the reader then has to
// learn which row the table lost.
func TestTheJA4TCitationTableHoldsEveryCitationOfThePage(t *testing.T) {
	page := ja4tPageCitation(t)

	if len(page) != len(ja4tCitationContent) {
		t.Fatalf("%s holds %d citation outside its preamble, and ja4tCitationContent holds %d row.\n"+
			"\tAdd a row for each new citation, and name the text the cited line holds.",
			ja4tCitationPage, len(page), len(ja4tCitationContent))
	}

	for index, want := range ja4tCitationContent {
		got := page[index]

		if got.line != want.pageLine || got.path != want.path || got.number != want.number {
			t.Errorf("row %d of ja4tCitationContent names %s:%d cites %s:%d, and the page holds %s:%d cites %s:%d",
				index, ja4tCitationPage, want.pageLine, want.path, want.number,
				ja4tCitationPage, got.line, got.path, got.number)
		}
	}
}

// FR-reference-18h asserts that a cited line is in range, and it asserts nothing about
// what that line holds. This test reads the line. #726 measured three citations of this
// page that name a line in range and hold no text of the claim.
func TestEveryCitationOfTheJA4TPageNamesALineThatHoldsItsClaim(t *testing.T) {
	if _, err := os.Stat(foxioCorpusReferenceDir); err != nil {
		t.Skip(ja4tCitationCorpusAbsentMessage)
	}

	page := ja4tPageCitation(t)

	// The test reads the line the page cites, and never the line the table names. A
	// citation that moves back therefore fails here, with the text of both lines.
	for index, got := range page {
		if index >= len(ja4tCitationContent) {
			break
		}

		want := ja4tCitationContent[index]
		line := ja4tSourceLine(t, got.path, got.number)

		if strings.Contains(line, want.want) {
			continue
		}

		t.Errorf("%s:%d cites %s:%d, and that line holds no text of its claim.\n"+
			"\twant text:  %s\n\tline %d:    %s\n"+
			"\tthe table names %s:%d, which holds: %s",
			ja4tCitationPage, got.line, got.path, got.number,
			want.want, got.number, line,
			want.path, want.number, ja4tSourceLine(t, want.path, want.number))
	}
}

// The table above excludes the preamble by line number, so a moved preamble would drop a
// real citation from the guard without a failure.
func TestThePreambleOfTheJA4TPageHoldsOneCitation(t *testing.T) {
	const rule = "Read `zeek/ja4t/main.zeek:180` as line 180 of"

	page := strings.Split(readRepoFile(t, ja4tCitationPage), "\n")

	if len(page) < ja4tCitationPreambleLine {
		t.Fatalf("%s holds %d lines, and the preamble sits at line %d",
			ja4tCitationPage, len(page), ja4tCitationPreambleLine)
	}

	line := page[ja4tCitationPreambleLine-1]

	if !strings.Contains(line, rule) {
		t.Errorf("%s:%d holds no preamble example, so ja4tCitationPreambleLine excludes a real citation.\n"+
			"\twant: %s\n\tline: %s",
			ja4tCitationPage, ja4tCitationPreambleLine, rule, line)
	}
}
