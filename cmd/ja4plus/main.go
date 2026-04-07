package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Crank-Git/ja4plus-go"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

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
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `ja4plus - JA4+ network fingerprinting tool

Usage:
  ja4plus analyze <pcap-file> [options]
  ja4plus cert <cert-file>
  ja4plus --version

Analyze options:
  --json          Output as JSON
  --csv           Output as CSV
  --types <list>  Comma-separated fingerprint types (e.g. ja4,ja4t)
  --lookup        Include application lookup for each fingerprint
`)
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
		outputJSON bool
		outputCSV  bool
		typesFilter map[string]bool
		doLookup   bool
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
			typesFilter = make(map[string]bool)
			for _, t := range strings.Split(args[i], ",") {
				t = strings.TrimSpace(strings.ToLower(t))
				if t != "" {
					typesFilter[t] = true
				}
			}
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
	defer f.Close()

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
	var results []ja4plus.FingerprintResult

	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		pkt.Metadata().Timestamp = ci.Timestamp
		pkt.Metadata().CaptureLength = ci.CaptureLength
		pkt.Metadata().Length = ci.Length

		fpResults, _ := proc.ProcessPacket(pkt)
		for _, r := range fpResults {
			if typesFilter != nil && !typesFilter[strings.ToLower(r.Type)] {
				continue
			}
			results = append(results, r)
		}
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
	defer w.Flush()

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
	return nil
}

func writeTable(results []ja4plus.FingerprintResult, doLookup bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	if doLookup {
		fmt.Fprintln(w, "Type\tSource\tDestination\tFingerprint\tApplication")
	} else {
		fmt.Fprintln(w, "Type\tSource\tDestination\tFingerprint")
	}

	for _, r := range results {
		src := fmt.Sprintf("%s:%d", r.SrcIP, r.SrcPort)
		dst := fmt.Sprintf("%s:%d", r.DstIP, r.DstPort)
		if doLookup {
			app := ""
			if lr := ja4plus.LookupFingerprint(r.Fingerprint); lr != nil {
				app = lr.Application
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Type, src, dst, r.Fingerprint, app)
		} else {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Type, src, dst, r.Fingerprint)
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

