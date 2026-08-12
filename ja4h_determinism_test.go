package ja4plus

import (
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
)

// ja4hDeterminismRuns is the number of times the determinism test computes one value.
//
// Go randomizes the iteration order of a map on every range, so one range over a map of
// this many keys reaches a new order on nearly every run. 200 runs make a surviving
// order-dependence improbable. #303 records the measurement that this count holds.
const ja4hDeterminismRuns = 200

// ja4hDeterminismRequest is one HTTP request that carries 12 headers and 12 cookies.
//
// A map of one or two keys hides an order-dependence, because few orders exist. This
// request gives the map enough keys that a range reaches a different order on each run.
// The request ends with `\r\n\r\n`, because `ParseHTTPRequest` returns nil for a header
// block that has not ended.
const ja4hDeterminismRequest = "GET /search?q=one HTTP/1.1\r\n" +
	"Host: example.com\r\n" +
	"User-Agent: Mozilla/5.0\r\n" +
	"Accept: text/html\r\n" +
	"Accept-Language: en-US,en;q=0.9\r\n" +
	"Accept-Encoding: gzip, deflate\r\n" +
	"Referer: https://example.com/\r\n" +
	"Connection: keep-alive\r\n" +
	"Upgrade-Insecure-Requests: 1\r\n" +
	"Sec-Fetch-Dest: document\r\n" +
	"Sec-Fetch-Mode: navigate\r\n" +
	"Cache-Control: max-age=0\r\n" +
	"Cookie: zeta=26; alpha=1; mike=13; bravo=2; november=14; charlie=3; " +
	"oscar=15; delta=4; papa=16; echo=5; quebec=17; foxtrot=6\r\n" +
	"\r\n"

// TestJA4H_ComputesOneValueForOneRequestOnEveryRun holds the determinism of the three
// JA4H values.
//
// `ja4hSortedCookieStrings` ranges the `Cookies` map at `ja4h.go:315`, and the JA4H value
// is an ordered string. A range that reached the output without a sort would make the
// library answer differently for one input on two runs, and a fingerprint that is not
// stable compares against nothing. #303 records the reproduction attempt that found no
// such range on this tree, and this test holds the property that the attempt measured.
func TestJA4H_ComputesOneValueForOneRequestOnEveryRun(t *testing.T) {
	payload := []byte(ja4hDeterminismRequest)

	first := parser.ParseHTTPRequest(payload)
	if first == nil {
		t.Fatal("ParseHTTPRequest returned nil for the determinism request")
	}
	if len(first.Cookies) != 12 {
		t.Fatalf("the request parsed %d cookies, and the test needs 12", len(first.Cookies))
	}

	wantBase := computeJA4HFromRequest(first)
	wantRaw := computeJA4HRaw(first)
	wantRawOriginal := computeJA4HRawOriginalOrder(first)

	// A fresh parse on each run covers the parser as well as the fingerprinter, because
	// `ParseHTTPRequest` fills the two maps that the value reads.
	for run := 2; run <= ja4hDeterminismRuns; run++ {
		req := parser.ParseHTTPRequest(payload)
		if req == nil {
			t.Fatalf("run %d: ParseHTTPRequest returned nil", run)
		}
		if got := computeJA4HFromRequest(req); got != wantBase {
			t.Fatalf("run %d: the JA4H value moved\n run 1: %s\n run %d: %s", run, wantBase, run, got)
		}
		if got := computeJA4HRaw(req); got != wantRaw {
			t.Fatalf("run %d: the JA4H_r value moved\n run 1: %s\n run %d: %s", run, wantRaw, run, got)
		}
		if got := computeJA4HRawOriginalOrder(req); got != wantRawOriginal {
			t.Fatalf("run %d: the JA4H_ro value moved\n run 1: %s\n run %d: %s", run, wantRawOriginal, run, got)
		}
	}
}

// TestJA4H_SortsTheCookiePairListByTheCookieName holds the sort that makes the value
// stable.
//
// The determinism test above passes for a second reason: a sorted list and an unsorted
// list of one element are the same list. This test reads the pair order directly, so it
// fails when the sort goes away even though the cookie count stays at 12.
func TestJA4H_SortsTheCookiePairListByTheCookieName(t *testing.T) {
	req := parser.ParseHTTPRequest([]byte(ja4hDeterminismRequest))
	if req == nil {
		t.Fatal("ParseHTTPRequest returned nil for the determinism request")
	}

	names, pairs := ja4hSortedCookieStrings(req)

	wantNames := "alpha,bravo,charlie,delta,echo,foxtrot,mike,november,oscar,papa,quebec,zeta"
	if names != wantNames {
		t.Errorf("the cookie name list is not sorted\n want: %s\n got:  %s", wantNames, names)
	}

	wantPairs := "alpha=1,bravo=2,charlie=3,delta=4,echo=5,foxtrot=6,mike=13," +
		"november=14,oscar=15,papa=16,quebec=17,zeta=26"
	if pairs != wantPairs {
		t.Errorf("the cookie pair list is not sorted by the name\n want: %s\n got:  %s", wantPairs, pairs)
	}

	// The wire order differs from the sorted order, so a test that reads the sorted order
	// cannot pass by accident.
	if strings.Join(req.CookieNames, ",") == wantNames {
		t.Error("the request carries the cookies in sorted wire order, so the test proves nothing")
	}
}
