package ja4plus_test

// This file holds FR-release-10, FR-release-13, FR-release-15 and FR-release-16 of #102.
// Each example below carries an `// Output:` block, so `go test` runs it and compares the
// printed text.
//
// `example_test.go` holds no output block, and it holds a different requirement.
// FR-documentation-28 mirrors each fenced Go block of `docs/` into that file, and
// `TestEveryGoSampleOfTheSiteIsATestableExample` in `docs_go_samples_test.go` maps the two
// one to one. That test reports an example of `example_test.go` that no page carries, so
// an output-checked example belongs here and not there.
//
// FR-release-14 asks for a runnable `SyncProcessor` example, and `ExampleSyncProcessor` in
// `concurrency_doc_test.go` already carries it with an output block. One name serves one
// example, so this file adds no second one.

import (
	"fmt"

	ja4plus "github.com/Crank-Git/ja4plus-go"
)

// Example reads one TCP SYN packet through a Processor and prints each fingerprint.
//
// `go doc` prints the package comment, and pkg.go.dev renders this example under it. So
// this function is the runnable example of the package documentation, which FR-release-10
// requires.
//
// The packet carries a window of 65535 and no TCP option. So the option list, the maximum
// segment size and the window scale of the JA4T value each read `00`.
func Example() {
	processor := ja4plus.NewProcessor()

	results, err := processor.ProcessPacket(concurrencySYNPacket(40000))
	if err != nil {
		fmt.Println("error:", err)

		return
	}

	for _, result := range results {
		fmt.Printf("%s %s\n", result.Type, result.Fingerprint)
	}

	// Output: ja4t 65535_00_00_00
}

// ExampleProcessor reads two connections through one Processor, and it then clears the
// state of the Processor.
//
// One Processor serves one goroutine, and this example uses one goroutine. A caller that
// wants more than one goroutine reads the `# Concurrency` section of the package
// documentation.
//
// A long-running monitor calls CleanupConnection when a connection ends, and it calls
// Reset when it starts a second packet source. State that neither call removes stays in
// the Processor for the life of the program.
func ExampleProcessor() {
	processor := ja4plus.NewProcessor()

	for _, srcPort := range []uint16{40000, 40001} {
		results, err := processor.ProcessPacket(concurrencySYNPacket(srcPort))
		if err != nil {
			fmt.Println("error:", err)

			return
		}

		for _, result := range results {
			fmt.Printf("%s from %s:%d to %s:%d\n",
				result.Type, result.SrcIP, result.SrcPort, result.DstIP, result.DstPort)
		}
	}

	processor.Reset()

	// Output:
	// ja4t from 192.168.1.1:40000 to 10.0.0.1:443
	// ja4t from 192.168.1.1:40001 to 10.0.0.1:443
}

// ExampleLookupFingerprint reads the local database for one fingerprint.
//
// The example prints the result of a value that no database holds, and it does so for a
// reason. Two databases answer this call: the embedded FoxIO mapping, and the cache file
// that `ja4plus db update` writes. A machine that holds a cache file answers a hit
// differently from a machine that holds none. An example compares its printed text
// exactly. A miss returns nil under every database, so this example states the one result
// that each machine reproduces.
//
// The lookup reaches no network. github.com/Crank-Git/ja4plus-go/ja4db holds the remote
// lookup.
func ExampleLookupFingerprint() {
	// Each part of this value is a placeholder, so no database record carries it.
	result := ja4plus.LookupFingerprint("t00i000000_000000000000_000000000000")

	fmt.Println(result == nil)

	// Output: true
}
