package ja4plus_test

import (
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	ja4plus "github.com/Crank-Git/ja4plus-go"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// These tests hold FR-concurrency-1 through FR-concurrency-6, which issue #27 carries.
// A documentation requirement is testable, so each requirement below reads the source
// file and asserts the statement that a user sees.
//
// The two example functions run each pattern under `go test`. `README.md` states the
// contract and links to `docs/concurrency.md`, and that page shows each pattern as a
// program. `docs_go_samples_test.go` in `internal/repocheck` compiles every Go block of
// that page through its mirrors, so a reader who copies the page gets code that builds.
//
// **The README showed both patterns as code until 2026-11-21 UTC.** On that date the
// maintainer moved them to `docs/concurrency.md`, so the pattern check below reads that page.

// concurrencyContractPhrase is the sentence that states the contract for one type.
// One phrase for every type keeps the statement identical across the package.
const concurrencyContractPhrase = "serves one goroutine"

// concurrencyFingerprinterTypes returns the file that declares each fingerprinter type, by
// type name. FR-concurrency-2 covers the ten fingerprinter types, and ten fingerprinters
// carry the eleven passive methods, because JA4LFingerprinter writes both JA4L and JA4LS.
//
// It reads the fields of Processor by reflection, so a new fingerprinter reaches this test
// with no edit here. Issue #148 records the fault a second list produces.
// The file name follows the type name, because JA4SSHFingerprinter declares itself in
// ja4ssh.go.
func concurrencyFingerprinterTypes() map[string]string {
	processor := reflect.TypeOf(ja4plus.Processor{})
	fingerprinter := reflect.TypeOf((*ja4plus.Fingerprinter)(nil)).Elem()

	types := map[string]string{}
	for index := 0; index < processor.NumField(); index++ {
		field := processor.Field(index)
		if !field.Type.Implements(fingerprinter) {
			continue
		}

		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}

		name := fieldType.Name()
		types[name] = strings.ToLower(strings.TrimSuffix(name, "Fingerprinter")) + ".go"
	}

	return types
}

func TestFingerprinterTypeCountIsTen(t *testing.T) {
	if got := len(concurrencyFingerprinterTypes()); got != 10 {
		t.Errorf("fingerprinter type count = %d, want 10", got)
	}
}

func TestProcessorDocCommentStatesTheConcurrencyContract(t *testing.T) {
	doc := docCommentOf(t, "processor.go", "type Processor struct")

	// FR-concurrency-1, FR-concurrency-3 and FR-concurrency-4 in one comment.
	for _, want := range []string{concurrencyContractPhrase, "GetShardKey", "SyncProcessor"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the Processor doc comment omits %q", want)
		}
	}
}

func TestEachFingerprinterDocCommentStatesTheConcurrencyContract(t *testing.T) {
	for typeName, file := range concurrencyFingerprinterTypes() {
		doc := docCommentOf(t, file, "type "+typeName+" struct")

		for _, want := range []string{concurrencyContractPhrase, "SyncProcessor"} {
			if !strings.Contains(doc, want) {
				t.Errorf("the %s doc comment omits %q", typeName, want)
			}
		}
	}
}

func TestPackageDocumentationHoldsTheConcurrencySection(t *testing.T) {
	text := readConcurrencyFile(t, "doc.go")

	// A godoc section heading starts with `#`, so a reader of `go doc` sees the heading.
	for _, want := range []string{
		"# Concurrency",
		concurrencyContractPhrase,
		"GetShardKey",
		"SyncProcessor",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("doc.go omits %q", want)
		}
	}
}

func TestReadmeHoldsTheConcurrencySection(t *testing.T) {
	text := readConcurrencyFile(t, "README.md")

	// The section heading is `### Concurrency`, and it holds the `## Concurrency` text.
	for _, want := range []string{
		"## Concurrency",
		concurrencyContractPhrase,
		"GetShardKey",
		"SyncProcessor",
		concurrencyPageLink,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README.md omits %q", want)
		}
	}
}

// concurrencyPageLink is the address of the published concurrency page. The README links
// to it, because that page shows the two patterns.
const concurrencyPageLink = "https://crank-git.github.io/ja4plus-go/concurrency/"

// TestTheConcurrencyPageShowsBothPatternsAsPrograms holds FR-concurrency-6 and
// FR-release-22.
//
// Each pattern needs one Go block of `docs/concurrency.md` that calls the function the
// pattern names. This test reads the page, and it compiles nothing.
// TestEveryGoSampleOfTheSiteIsARunnableProgram and
// TestEveryGoSampleOfTheSiteIsATestableExample hold each block equal to a program that the
// build compiles and to an example that `go test` runs.
func TestTheConcurrencyPageShowsBothPatternsAsPrograms(t *testing.T) {
	blocks := concurrencyGoBlocks(readConcurrencyFile(t, "docs/concurrency.md"))

	for pattern, call := range map[string]string{
		"sharded": "router.GetShardKey(",
		"shared":  "ja4plus.NewSyncProcessor()",
	} {
		shown := false
		for _, block := range blocks {
			if strings.Contains(block, "package main") && strings.Contains(block, call) {
				shown = true
			}
		}

		if !shown {
			t.Errorf("docs/concurrency.md holds no Go program that calls %s, so it does "+
				"not show the %s pattern", call, pattern)
		}
	}
}

// concurrencyGoBlocks returns the text of each fenced Go block of the page.
func concurrencyGoBlocks(page string) []string {
	var blocks []string

	rest := page
	for {
		_, after, found := strings.Cut(rest, "```go\n")
		if !found {
			return blocks
		}

		block, remainder, _ := strings.Cut(after, "\n```")
		blocks = append(blocks, block)
		rest = remainder
	}
}

// The method-count check of this file was removed on 2026-08-13, and
// `method_count_test.go` holds it now. The cross-member review of the Epic 12 batch found
// that the two checks enforced one rule with two meanings, which `.claude/rules/ste.md`
// rule 6 bars.
//
// The removed check read fourteen files, reported no line number, and exempted no
// quotation. `TestMethodCountAppliesElevenToMethodsAndTenToFingerprinters` reads every
// tracked document, names the file and the line, and exempts a phrase that a backtick or a
// double quotation mark delimits on both sides. So a page that quotes the forbidden form as
// the rule passed the new check and failed the old one.
//
// One thing the removed check read that the new one does not: the whole text of a Go file,
// including a string literal. The new check masks a Go file to its comments through
// `go/parser`, which is deliberate, because a literal that carries the phrase is output text
// rather than a statement about this project.

// docCommentOf returns the text of the file up to the declaration. The doc comment of the
// declaration is the last part of that text, so a search over it finds the statement.
func docCommentOf(t *testing.T, file, declaration string) string {
	t.Helper()

	doc, _, ok := strings.Cut(readConcurrencyFile(t, file), declaration)
	if !ok {
		t.Fatalf("%s declares no %q", file, declaration)
	}

	// Keep the comment block that touches the declaration, and drop the rest of the file.
	// A phrase in an unrelated comment must not satisfy the requirement.
	block := doc[strings.LastIndex(doc, "\n\n")+1:]

	return block
}

// readConcurrencyFile returns the content of the file at the repository root.
func readConcurrencyFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(content)
}

// processSharded runs one Processor for each shard and returns every result.
// Each goroutine owns its Processor, so no lock guards the per-packet path.
func processSharded(packets []gopacket.Packet, shards int) []ja4plus.FingerprintResult {
	inputs := make([]chan gopacket.Packet, shards)
	outputs := make(chan []ja4plus.FingerprintResult, shards)

	var wg sync.WaitGroup
	for i := range inputs {
		inputs[i] = make(chan gopacket.Packet, 16)

		wg.Add(1)
		go func(in <-chan gopacket.Packet) {
			defer wg.Done()

			proc := ja4plus.NewProcessor()

			var results []ja4plus.FingerprintResult
			for packet := range in {
				got, _ := proc.ProcessPacket(packet)
				results = append(results, got...)
			}

			outputs <- results
		}(inputs[i])
	}

	// GetShardKey holds no state, so the router calls it on its own Processor.
	router := ja4plus.NewProcessor()
	for _, packet := range packets {
		key := router.GetShardKey(packet)
		if key == "" {
			// The packet carries neither a TCP layer nor a UDP layer.
			continue
		}

		inputs[shardIndex(key, shards)] <- packet
	}

	for _, in := range inputs {
		close(in)
	}
	wg.Wait()
	close(outputs)

	var all []ja4plus.FingerprintResult
	for results := range outputs {
		all = append(all, results...)
	}

	return all
}

// shardIndex returns the shard that owns the key. The key holds the sorted five-tuple,
// so a packet and its reply reach one shard and one Processor.
func shardIndex(key string, shards int) int {
	digest := fnv.New32a()
	_, _ = digest.Write([]byte(key))

	return int(digest.Sum32() % uint32(shards))
}

// processShared shares one SyncProcessor between the workers and returns every result.
// The mutex serializes every call, so this pattern gives lower throughput than a shard
// for each goroutine.
func processShared(packets []gopacket.Packet, workers int) []ja4plus.FingerprintResult {
	proc := ja4plus.NewSyncProcessor()

	input := make(chan gopacket.Packet, 16)
	outputs := make(chan []ja4plus.FingerprintResult, workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var results []ja4plus.FingerprintResult
			for packet := range input {
				got, _ := proc.ProcessPacket(packet)
				results = append(results, got...)
			}

			outputs <- results
		}()
	}

	for _, packet := range packets {
		input <- packet
	}
	close(input)

	wg.Wait()
	close(outputs)

	var all []ja4plus.FingerprintResult
	for results := range outputs {
		all = append(all, results...)
	}

	return all
}

func ExampleProcessor_GetShardKey() {
	packets := concurrencySYNPackets(8)

	results := processSharded(packets, 4)

	fmt.Println(countJA4T(results))
	// Output: 8
}

func ExampleSyncProcessor() {
	packets := concurrencySYNPackets(8)

	results := processShared(packets, 4)

	fmt.Println(countJA4T(results))
	// Output: 8
}

// countJA4T returns the number of JA4T results. One TCP SYN packet produces one of them,
// so the count is stable whatever order the goroutines run in.
func countJA4T(results []ja4plus.FingerprintResult) int {
	count := 0
	for _, result := range results {
		if result.Type == "ja4t" {
			count++
		}
	}

	return count
}

// concurrencySYNPackets returns the requested number of TCP SYN packets. Each packet
// carries its own source port, so the packets reach more than one shard.
func concurrencySYNPackets(count int) []gopacket.Packet {
	packets := make([]gopacket.Packet, 0, count)
	for i := 0; i < count; i++ {
		packets = append(packets, concurrencySYNPacket(uint16(40000+i)))
	}

	return packets
}

// concurrencySYNPacket returns one TCP SYN packet from the source port.
func concurrencySYNPacket(srcPort uint16) gopacket.Packet {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("10.0.0.1"),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(443),
		SYN:     true,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, options, ip, tcp)

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()

	return packet
}
