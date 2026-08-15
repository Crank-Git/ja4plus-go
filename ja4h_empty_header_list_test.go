package ja4plus

import (
	"go/ast"
	goparser "go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
)

// ja4hEmptyHeaderListHash is the first 12 characters of the SHA-256 hash of the empty
// string. The maintainer ruled on 2026-08-14 that JA4H part b writes this value for an
// empty header list, and R18 of `docs/specs/foxio/JA4H.md` is the deciding rule. The port
// half of the ruling lives in `Crank-Git/ja4plus#612`, and issue #527 is the reversal path.
const ja4hEmptyHeaderListHash = "e3b0c44298fc"

// ja4hZeroSentinel is the value that R27 of `docs/specs/foxio/JA4H.md` confines to part c
// and to part d.
const ja4hZeroSentinel = "000000000000"

// ja4hEmptyHeaderListRequest holds frame 4 of `testdata/foxio/pcap/gre-erspan-vxlan.pcap`.
// The request carries no header, and its path holds one unencoded space.
const ja4hEmptyHeaderListRequest = "GET /Hello Arkime HTTP/1.0\r\n\r\n"

// ja4hEmptyHeaderListVector is the FoxIO value for that frame.
// `testdata/foxio/wireshark/gre-erspan-vxlan.pcap.json` holds it.
const ja4hEmptyHeaderListVector = "ge10nn000000_e3b0c44298fc_000000000000_000000000000"

// TestJA4HPartBHashesAnEmptyHeaderList holds the ruling of 2026-08-14.
//
// R18 of `docs/specs/foxio/JA4H.md` states
// `Truncated SHA256 hash of Headers, in the order they appear`, and it names no sentinel.
// The Rust reference and the Zeek package write the sentinel, and the image outranks both.
func TestJA4HPartBHashesAnEmptyHeaderList(t *testing.T) {
	pkt := buildTCPPacketWithPayload(t, []byte("GET / HTTP/1.0\r\n\r\n"))

	fingerprint := ComputeJA4H(pkt)
	if fingerprint == "" {
		t.Fatal("ComputeJA4H produced no value for a request with no header")
	}

	parts := strings.Split(fingerprint, "_")
	if len(parts) != 4 {
		t.Fatalf("ComputeJA4H = %q, and the value holds %d parts rather than 4", fingerprint, len(parts))
	}
	if parts[1] != ja4hEmptyHeaderListHash {
		t.Errorf("part b = %q, want %q", parts[1], ja4hEmptyHeaderListHash)
	}
}

// TestJA4HKeepsTheZeroSentinelInPartCAndPartD holds R27 of `docs/specs/foxio/JA4H.md`.
//
// The ruling of 2026-08-14 moves part b alone. A change that moved part c or part d as
// well would disagree with every FoxIO implementation.
func TestJA4HKeepsTheZeroSentinelInPartCAndPartD(t *testing.T) {
	pkt := buildTCPPacketWithPayload(t, []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))

	fingerprint := ComputeJA4H(pkt)
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 4 {
		t.Fatalf("ComputeJA4H = %q, and the value holds %d parts rather than 4", fingerprint, len(parts))
	}
	if parts[2] != ja4hZeroSentinel {
		t.Errorf("part c = %q, want %q", parts[2], ja4hZeroSentinel)
	}
	if parts[3] != ja4hZeroSentinel {
		t.Errorf("part d = %q, want %q", parts[3], ja4hZeroSentinel)
	}
}

// TestJA4HReadsARequestPathThatHoldsASpace holds rule 5a of issue #527.
//
// `requestLineRe` in `internal/parser/http.go` read a path of non-space characters, so a
// path with one unencoded space reached no value. FoxIO holds a value for the same frame.
func TestJA4HReadsARequestPathThatHoldsASpace(t *testing.T) {
	request := parser.ParseHTTPRequest([]byte(ja4hEmptyHeaderListRequest))
	if request == nil {
		t.Fatal("ParseHTTPRequest read no request from a path that holds a space")
	}
	if want := "/Hello Arkime"; request.Path != want {
		t.Errorf("Path = %q, want %q", request.Path, want)
	}
	if want := "HTTP/1.0"; request.Version != want {
		t.Errorf("Version = %q, want %q", request.Version, want)
	}
}

// TestTheRequestLineReadsNoSecondLine holds the separator rule of `requestLineRe`.
//
// A separator of `\s` reads a line ending, so the match crossed into the second line and
// read a request line that no line of the payload holds. `ja4l.go` reads `IsHTTPRequest` to
// pick a measurement point, so such a match moves a JA4L value. #527 closed the defect on
// 2026-08-14, and the first payload below matched before that day.
func TestTheRequestLineReadsNoSecondLine(t *testing.T) {
	// A payload that starts with none of the nine method prefixes reaches the expression, so
	// both functions answer from it.
	unmatched := []string{
		"SSH-2.0-OpenSSH_9.6\r\n/a HTTP/1.1\r\n\r\n",
		"SSH-2.0-OpenSSH_9.6\r\nsome junk HTTP/1.1\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
	}

	for _, payload := range unmatched {
		if parser.IsHTTPRequest([]byte(payload)) {
			t.Errorf("IsHTTPRequest reads %q as a request", payload)
		}
		if request := parser.ParseHTTPRequest([]byte(payload)); request != nil {
			t.Errorf("ParseHTTPRequest reads %q as the request %+v", payload, request)
		}
	}

	// The path group reads no carriage return and no line feed. A group of any character
	// reads a bare carriage return, and the path then holds the smuggled text.
	//
	// `IsHTTPRequest` answers `true` for each payload below from its nine-prefix fast path,
	// which reads `GET ` and never the expression. #57 built that path, and #527 does not
	// move it. So this test reads `ParseHTTPRequest` alone here, and no fingerprint value
	// follows a payload that reaches no request.
	smuggled := []string{
		"GET /a\rFAKE HTTP/1.1\r\nReal: 1\r\n\r\n",
		"GET /a\r\nFAKE HTTP/1.1\r\n\r\n",
	}

	for _, payload := range smuggled {
		if request := parser.ParseHTTPRequest([]byte(payload)); request != nil {
			t.Errorf("ParseHTTPRequest reads %q as the request %+v", payload, request)
		}
	}
}

// TestTheRequestLineReadsASpaceAndATabAsASeparator holds the separator set of
// `requestLineRe`. RFC 9112 section 3 names one space, and a lenient parser reads a tab.
func TestTheRequestLineReadsASpaceAndATabAsASeparator(t *testing.T) {
	payloads := []string{
		"GET /a HTTP/1.1\r\n\r\n",
		"GET\t/a\tHTTP/1.1\r\n\r\n",
		"GET  /a  HTTP/1.1\r\n\r\n",
		"GET /a HTTP/1.1\n\n",
	}

	for _, payload := range payloads {
		request := parser.ParseHTTPRequest([]byte(payload))
		if request == nil {
			t.Fatalf("ParseHTTPRequest read no request from %q", payload)
		}
		if request.Path != "/a" {
			t.Errorf("Path of %q is %q, want %q", payload, request.Path, "/a")
		}
	}
}

// TestJA4HProducesTheFoxioValueOfTheSpacedPathFrame proves that the two rules of #527
// close one comparison of the corpus together.
func TestJA4HProducesTheFoxioValueOfTheSpacedPathFrame(t *testing.T) {
	pkt := buildTCPPacketWithPayload(t, []byte(ja4hEmptyHeaderListRequest))

	if got := ComputeJA4H(pkt); got != ja4hEmptyHeaderListVector {
		t.Errorf("ComputeJA4H = %q, want %q", got, ja4hEmptyHeaderListVector)
	}
}

// ja4hHashCallSite names one call of a truncated-hash function in the root package.
type ja4hHashCallSite struct {
	file     string
	function string
	callee   string
}

// ja4hHashCallSites names every call of a truncated-hash function in the root package.
//
// The ruling of 2026-08-14 reaches JA4H part b and each of the three JA4X parts, so four
// sites call `parser.TruncatedHashNoSentinel`. Each of the other seven keeps the zero
// sentinel for an empty list, and this table is the record of which seven. A new call site
// fails this test, so a later author must state which rule the new site follows.
//
// #527 built the JA4H half, and #582 built the JA4X half.
var ja4hHashCallSites = []ja4hHashCallSite{
	{"ja4.go", "ja4CipherHash", "TruncatedHash"},
	{"ja4.go", "ja4ExtensionHash", "TruncatedHash"},
	{"ja4.go", "computeJA4OriginalOrder", "TruncatedHash"},
	{"ja4.go", "computeJA4OriginalOrder", "TruncatedHash"},
	{"ja4h.go", "computeJA4HFromRequest", "TruncatedHashNoSentinel"},
	{"ja4h.go", "computeJA4HFromRequest", "TruncatedHash"},
	{"ja4h.go", "computeJA4HFromRequest", "TruncatedHash"},
	{"ja4s.go", "computeJA4SPair", "TruncatedHash"},
	{"ja4x.go", "computeJA4XWithRaw", "TruncatedHashNoSentinel"},
	{"ja4x.go", "computeJA4XWithRaw", "TruncatedHashNoSentinel"},
	{"ja4x.go", "computeJA4XWithRaw", "TruncatedHashNoSentinel"},
}

// TestEveryTruncatedHashCallSiteOfTheRootPackageIsNamed reads the source and compares it
// against `ja4hHashCallSites`.
//
// The test reads the syntax tree rather than a line number, because a later edit above a
// call moves the line and never the enclosing function.
func TestEveryTruncatedHashCallSiteOfTheRootPackageIsNamed(t *testing.T) {
	fileSet := token.NewFileSet()

	var found []ja4hHashCallSite

	for _, path := range productionGoFilesOf(t, ".") {
		file, err := goparser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(function, func(node ast.Node) bool {
				callee := parserHashCallee(node)
				if callee == "" {
					return true
				}
				found = append(found, ja4hHashCallSite{path, function.Name.Name, callee})
				return true
			})
		}
	}

	sortHashCallSites(found)
	want := append([]ja4hHashCallSite(nil), ja4hHashCallSites...)
	sortHashCallSites(want)

	if len(found) != len(want) {
		t.Fatalf("the root package holds %d truncated-hash call sites, and the table names %d:\n%v",
			len(found), len(want), found)
	}
	for i := range found {
		if found[i] != want[i] {
			t.Errorf("call site %d is %v, and the table names %v", i, found[i], want[i])
		}
	}
}

// parserHashCallee returns the name of the `parser` hash function that the node calls.
// It returns an empty string when the node calls no such function.
func parserHashCallee(node ast.Node) string {
	call, ok := node.(*ast.CallExpr)
	if !ok {
		return ""
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	packageName, ok := selector.X.(*ast.Ident)
	if !ok || packageName.Name != "parser" {
		return ""
	}
	switch selector.Sel.Name {
	case "TruncatedHash", "TruncatedHashNoSentinel":
		return selector.Sel.Name
	}
	return ""
}

func sortHashCallSites(sites []ja4hHashCallSite) {
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].file != sites[j].file {
			return sites[i].file < sites[j].file
		}
		if sites[i].function != sites[j].function {
			return sites[i].function < sites[j].function
		}
		return sites[i].callee < sites[j].callee
	})
}
