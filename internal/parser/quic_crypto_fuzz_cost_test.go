package parser

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime/metrics"
	"strconv"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/fuzzprop"
)

// Issue #568 asks which layer holds the cost of one fuzz execution of
// FuzzParseCryptoFramesReadsAnyPayload. The two benchmarks below read one corpus and
// report two times, so a reader separates the parser from the property harness.
//
// The seed corpus of a target lives at `testdata/fuzz/<TargetName>/`, and the fuzz engine
// writes an interesting input to the build cache instead. This file reads the seed corpus
// alone, because the build cache holds no file that this repository tracks.

// fuzzCryptoCorpusName names the seed corpus directory of
// FuzzParseCryptoFramesReadsAnyPayload.
const fuzzCryptoCorpusName = "FuzzParseCryptoFramesReadsAnyPayload"

// readFuzzCryptoCorpus returns every input that FuzzParseCryptoFramesReadsAnyPayload
// starts from.
//
// The first four inputs are the four that the target adds with `f.Add`, and the rest come
// from the seed corpus directory. It fails the benchmark when a corpus file states a value
// that no `[]byte` literal holds.
func readFuzzCryptoCorpus(tb testing.TB) [][]byte {
	tb.Helper()

	inputs := [][]byte{
		quicCryptoFrameAtOffset(0, quicClientHelloHandshakeMessage()),
		append([]byte{0x00}, quicCryptoFrameAtOffset(8, []byte{0xaa, 0xbb, 0xcc})...),
		{0x06, 0x00, 0x44, 0x00, 0x01, 0x02},
		{0x06, 0xc0},
	}

	dir := filepath.Join("testdata", "fuzz", fuzzCryptoCorpusName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		tb.Fatalf("the corpus directory %s did not open: %v", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			tb.Fatalf("the corpus file %s did not read: %v", entry.Name(), err)
		}

		inputs = append(inputs, decodeCorpusByteSlice(tb, entry.Name(), string(data)))
	}

	return inputs
}

// decodeCorpusByteSlice returns the byte slice that one corpus file states.
//
// A corpus file of one `[]byte` parameter holds a version line and one `[]byte("...")`
// line, and `strconv.Unquote` reads the Go string literal inside the parentheses. It fails
// the benchmark for a file of any other shape.
func decodeCorpusByteSlice(tb testing.TB, name, content string) []byte {
	tb.Helper()

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[]byte(") || !strings.HasSuffix(line, ")") {
			continue
		}

		literal := strings.TrimSuffix(strings.TrimPrefix(line, "[]byte("), ")")
		value, err := strconv.Unquote(literal)
		if err != nil {
			tb.Fatalf("the corpus file %s holds a literal that did not unquote: %v", name, err)
		}

		return []byte(value)
	}

	tb.Fatalf("the corpus file %s holds no []byte line", name)

	return nil
}

// BenchmarkParseCryptoFramesReadsTheFuzzCorpus measures ParseCryptoFrames alone.
//
// It calls the parser one time for each iteration, and it reads the corpus that
// FuzzParseCryptoFramesReadsAnyPayload starts from. Issue #568 compares this time with the
// time of BenchmarkParseCryptoFramesUnderTheFuzzPropertiesReadsTheFuzzCorpus below.
func BenchmarkParseCryptoFramesReadsTheFuzzCorpus(b *testing.B) {
	inputs := readFuzzCryptoCorpus(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseCryptoFrames(inputs[i%len(inputs)])
	}
}

// BenchmarkParseCryptoFramesUnderTheFuzzPropertiesReadsTheFuzzCorpus measures the work
// that one fuzz execution performs.
//
// `check` in `internal/fuzzprop/fuzzprop.go` is unexported and it takes a `*testing.T`, so
// this benchmark copies its shape rather than calls it. It reproduces the two
// `runtime/metrics` readings, the two parser calls and the `reflect.DeepEqual` comparison.
//
// It omits three things that `check` also does: the two `time.Now` and `time.Since` pairs,
// the FR-fuzz-16 duration comparison and the FR-fuzz-17 allocation comparison. So this
// benchmark states a lower bound of the harness cost, and never the whole cost.
//
// A change to that harness leaves this benchmark behind, and issue #568 records the reason
// this file copies the shape.
func BenchmarkParseCryptoFramesUnderTheFuzzPropertiesReadsTheFuzzCorpus(b *testing.B) {
	inputs := readFuzzCryptoCorpus(b)
	sample := []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := fuzzprop.ExactInput(inputs[i%len(inputs)])

		metrics.Read(sample)
		firstFragments, firstErr := ParseCryptoFrames(input)
		first := []any{firstFragments, firstErr}

		metrics.Read(sample)
		secondFragments, secondErr := ParseCryptoFrames(input)
		second := []any{secondFragments, secondErr}

		if !reflect.DeepEqual(first, second) {
			b.Fatalf("the two calls returned different results for input %d", i%len(inputs))
		}
	}
}
