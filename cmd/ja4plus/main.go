package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Crank-Git/ja4plus-go"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const ja4PlusMappingURL = "https://github.com/FoxIO-LLC/ja4/raw/main/ja4plus-mapping.csv"

// ja4PlusMappingMaxBytes bounds the mapping download.
// An unbounded copy writes whatever the server sends, and the mapping file is far below
// this size. `.claude/rules/external-apis.md` states the rule.
const ja4PlusMappingMaxBytes = 64 << 20

// ja4PlusDownloadTimeout bounds the whole mapping download.
// The default client of net/http carries no timeout, so this program never uses it.
const ja4PlusDownloadTimeout = 60 * time.Second

// Version is set via -ldflags at build time.
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "--version", "-v", "version":
		fmt.Printf("ja4plus %s\n", Version)
	case "--help", "-h", "help":
		printUsage()
	case "analyze":
		if err := runAnalyze(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "cert":
		if err := runCert(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "db":
		if err := runDB(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	// The usage names every token, because `--types` refuses a token that names no method
	// and the user needs the list before the refusal.
	fmt.Fprintf(os.Stderr, `ja4plus - JA4+ network fingerprinting tool

Usage:
  ja4plus analyze <pcap-file> [options]
  ja4plus cert <cert-file>
  ja4plus db update
  ja4plus db info
  ja4plus --version

Analyze options:
  --json          Output as JSON
  --csv           Output as CSV
  --types <list>  Comma-separated fingerprint types (e.g. ja4,ja4t)
                  Types: %s
                  ja4l prints the client value and the server value.
                  ja4ls prints the server value alone.
  --lookup        Include application lookup for each fingerprint

Database commands:
  db update       Download the latest ja4plus-mapping.csv from FoxIO
  db info         Print info about the active database (embedded vs cached)
`, strings.Join(methodTokens, ", "))
}

// packetReader abstracts over pcap and pcapng readers.
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

func runAnalyze(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing pcap file argument\nUsage: ja4plus analyze <pcap-file> [--json|--csv] [--types ja4,ja4t] [--lookup]")
	}

	pcapFile := args[0]
	var (
		outputJSON  bool
		outputCSV   bool
		typesFilter map[string]bool
		doLookup    bool
	)

	// Parse flags manually after the pcap file argument.
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--json":
			outputJSON = true
		case "--csv":
			outputCSV = true
		case "--types":
			i++
			if i >= len(args) {
				return fmt.Errorf("--types requires a comma-separated list")
			}
			filter, err := parseTypes(args[i])
			if err != nil {
				return err
			}
			typesFilter = filter
		case "--lookup":
			doLookup = true
		default:
			return fmt.Errorf("unknown option: %s", args[i])
		}
	}

	// Open and read the PCAP file.
	f, err := os.Open(pcapFile)
	if err != nil {
		return fmt.Errorf("cannot open file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var reader packetReader
	ext := strings.ToLower(filepath.Ext(pcapFile))
	if ext == ".pcapng" {
		r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return fmt.Errorf("failed to read pcapng: %w", err)
		}
		reader = r
	} else {
		r, err := pcapgo.NewReader(f)
		if err != nil {
			return fmt.Errorf("failed to read pcap: %w", err)
		}
		reader = r
	}

	proc := ja4plus.NewProcessor()

	var (
		results     []ja4plus.FingerprintResult
		packetFails int
	)

	for {
		data, ci, err := reader.ReadPacketData()

		// The reader reports the end of the capture with io.EOF. Every other error names a
		// truncated or corrupt file, and the program must not report success for it.
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("read %s: %w", pcapFile, err)
		}

		pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		pkt.Metadata().Timestamp = ci.Timestamp
		pkt.Metadata().CaptureLength = ci.CaptureLength
		pkt.Metadata().Length = ci.Length

		fpResults, errs := proc.ProcessPacket(pkt)
		packetFails += len(errs)

		for _, r := range fpResults {
			if !admitsResult(typesFilter, r) {
				continue
			}
			results = append(results, r)
		}
	}

	// The capture ends, so a connection whose last JA4SSH window never reached the threshold
	// holds that window open. FR-parity-32 emits it here, because no packet triggers it.
	for _, r := range proc.CloseOpenWindows() {
		if !admitsResult(typesFilter, r) {
			continue
		}

		results = append(results, r)
	}

	// A fingerprinter returns a non-fatal error for a record it cannot read. One line for
	// the whole capture reaches standard error, so standard output holds the results
	// alone. The exit code stays 0, because the capture itself is sound.
	if packetFails > 0 {
		fmt.Fprintf(os.Stderr, "note: %d packets carried a record that no fingerprinter read\n", packetFails)
	}

	// Output results.
	switch {
	case outputJSON:
		return writeJSON(results, doLookup)
	case outputCSV:
		return writeCSV(results, doLookup)
	default:
		return writeTable(results, doLookup)
	}
}

type jsonResult struct {
	Type        string `json:"type"`
	SrcIP       string `json:"src_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	Fingerprint string `json:"fingerprint"`
	Timestamp   string `json:"timestamp"`
	Application string `json:"application,omitempty"`
}

func writeJSON(results []ja4plus.FingerprintResult, doLookup bool) error {
	out := make([]jsonResult, 0, len(results))
	for _, r := range results {
		jr := jsonResult{
			Type:        r.Type,
			SrcIP:       r.SrcIP,
			SrcPort:     r.SrcPort,
			DstIP:       r.DstIP,
			DstPort:     r.DstPort,
			Fingerprint: r.Fingerprint,
			Timestamp:   r.Timestamp.Format(time.RFC3339),
		}
		if doLookup {
			if lr := ja4plus.LookupFingerprint(r.Fingerprint); lr != nil {
				jr.Application = lr.Application
			}
		}
		out = append(out, jr)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeCSV(results []ja4plus.FingerprintResult, doLookup bool) error {
	w := csv.NewWriter(os.Stdout)

	header := []string{"type", "src_ip", "src_port", "dst_ip", "dst_port", "fingerprint", "timestamp"}
	if doLookup {
		header = append(header, "application")
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		row := []string{
			r.Type,
			r.SrcIP,
			fmt.Sprintf("%d", r.SrcPort),
			r.DstIP,
			fmt.Sprintf("%d", r.DstPort),
			r.Fingerprint,
			r.Timestamp.Format(time.RFC3339),
		}
		if doLookup {
			app := ""
			if lr := ja4plus.LookupFingerprint(r.Fingerprint); lr != nil {
				app = lr.Application
			}
			row = append(row, app)
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	// Flush reports a write failure through Error. A discarded failure makes the program
	// exit 0 after standard output took no row.
	w.Flush()

	return w.Error()
}

func writeTable(results []ja4plus.FingerprintResult, doLookup bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	if doLookup {
		_, _ = fmt.Fprintln(w, "Type\tSource\tDestination\tFingerprint\tApplication")
	} else {
		_, _ = fmt.Fprintln(w, "Type\tSource\tDestination\tFingerprint")
	}

	for _, r := range results {
		src := fmt.Sprintf("%s:%d", r.SrcIP, r.SrcPort)
		dst := fmt.Sprintf("%s:%d", r.DstIP, r.DstPort)
		if doLookup {
			app := ""
			if lr := ja4plus.LookupFingerprint(r.Fingerprint); lr != nil {
				app = lr.Application
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Type, src, dst, r.Fingerprint, app)
		} else {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Type, src, dst, r.Fingerprint)
		}
	}
	return w.Flush()
}

func runCert(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing certificate file argument\nUsage: ja4plus cert <cert-file>")
	}

	certFile := args[0]
	data, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("cannot read file: %w", err)
	}

	var fingerprint string

	// Detect PEM vs DER: PEM files start with "-----BEGIN".
	if isPEM(data) {
		fingerprint = ja4plus.ComputeJA4XFromPEM(data)
	} else {
		fingerprint = ja4plus.ComputeJA4XFromDER(data)
	}

	if fingerprint == "" {
		return fmt.Errorf("could not compute JA4X fingerprint (invalid or unsupported certificate format)")
	}

	fmt.Println(fingerprint)
	return nil
}

func isPEM(data []byte) bool {
	// Check for PEM header or common PEM file marker.
	return len(data) > 10 && strings.HasPrefix(string(data), "-----BEGIN")
}

func runDB(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing subcommand\nUsage: ja4plus db {update|info}")
	}
	switch args[0] {
	case "update":
		return runDBUpdate()
	case "info":
		return runDBInfo()
	default:
		return fmt.Errorf("unknown db subcommand: %s\nUsage: ja4plus db {update|info}", args[0])
	}
}

func runDBUpdate() error {
	cachePath, err := ja4plus.CachedDatabasePath()
	if err != nil {
		return fmt.Errorf("resolve cache path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ja4PlusMappingURL, nil)
	if err != nil {
		return err
	}
	// The default client of net/http carries no timeout, so this program holds its own.
	client := &http.Client{Timeout: ja4PlusDownloadTimeout}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	tmp := cachePath + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	// The copy reads one byte more than the limit, so a body that reaches the limit is a
	// body the program declines rather than a file it truncates.
	n, err := io.Copy(out, io.LimitReader(resp.Body, ja4PlusMappingMaxBytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write: %w", err)
	}
	if n > ja4PlusMappingMaxBytes {
		_ = os.Remove(tmp)
		return fmt.Errorf("download: the body exceeds the limit of %d bytes", ja4PlusMappingMaxBytes)
	}
	if err := os.Rename(tmp, cachePath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install: %w", err)
	}

	fmt.Printf("downloaded %d bytes to %s\n", n, cachePath)
	// #74 made the library reload the table when the cache file changes, so a running
	// process needs no restart.
	fmt.Println("note: a running process reads the new database at its next lookup")
	return nil
}

func runDBInfo() error {
	info := ja4plus.GetDatabaseInfo()
	fmt.Printf("Source:  %s\n", info.Source)
	if info.Path != "" {
		fmt.Printf("Path:    %s\n", info.Path)
	}
	fmt.Printf("Entries: %d\n", info.Entries)
	if !info.ModTime.IsZero() {
		fmt.Printf("ModTime: %s\n", info.ModTime.Format(time.RFC3339))
	}
	cp, err := ja4plus.CachedDatabasePath()
	if err == nil && info.Source != "cache" {
		if _, statErr := os.Stat(cp); os.IsNotExist(statErr) {
			fmt.Printf("\nNo cache file at %s\n", cp)
			fmt.Println("Run `ja4plus db update` to download the latest from FoxIO.")
		}
	}
	return nil
}
