package main

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// These tests hold the closures of issue #25 under FR-audit-24. The audit reads
// `cmd/ja4plus/main.go` for an unhandled error and for an exit code that does not match
// the outcome. `docs/audit/findings.md` records F-25-1, F-25-7, F-25-8 and F-25-9.
//
// Each test fails when the closure is reverted, so FR-audit-26 holds.

// auditWritePcap writes a libpcap file whose body is the bytes the caller names.
// It returns the path of the file.
func auditWritePcap(t *testing.T, body []byte) string {
	t.Helper()

	// The global header holds the magic number, the two version numbers, the time zone,
	// the accuracy, the snapshot length and the link type. Link type 1 is Ethernet.
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], 65535)
	binary.LittleEndian.PutUint32(header[20:24], 1)

	path := filepath.Join(t.TempDir(), "audit.pcap")

	if err := os.WriteFile(path, append(header, body...), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	return path
}

// auditPacketRecord returns one libpcap packet record that carries the frame.
func auditPacketRecord(frame []byte) []byte {
	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record[0:4], 1)
	binary.LittleEndian.PutUint32(record[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(record[12:16], uint32(len(frame)))

	return append(record, frame...)
}

// auditTCPFrame returns one Ethernet frame that carries the payload over IPv4 and TCP.
func auditTCPFrame(t *testing.T, srcPort uint16, dstPort uint16, payload []byte) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC:       []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    []byte{192, 0, 2, 1},
		DstIP:    []byte{192, 0, 2, 2},
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		PSH:     true,
		ACK:     true,
		Window:  65535,
	}

	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set the network layer of the TCP checksum: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializeLayers(buffer, options, ethernet, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize the frame: %v", err)
	}

	return buffer.Bytes()
}

// auditCaptureStandardError runs the call with a pipe on standard error and returns what
// the call wrote to it.
func auditCaptureStandardError(t *testing.T, call func()) string {
	t.Helper()

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("open the pipe: %v", err)
	}

	stderr := os.Stderr
	os.Stderr = write

	call()

	os.Stderr = stderr

	if err := write.Close(); err != nil {
		t.Fatalf("close the write end: %v", err)
	}

	written, err := io.ReadAll(read)
	if err != nil {
		t.Fatalf("read the pipe: %v", err)
	}

	return string(written)
}

func TestF25_1_RunAnalyzeReturnsAnErrorForATruncatedCapture(t *testing.T) {
	// F-25-1 is closed. The read loop answered every error with `break`, so a truncated
	// capture reached the output stage and the program exited 0. The loop now separates
	// io.EOF from every other error.
	//
	// The body below opens a packet record header and stops inside it, so the reader
	// reports an unexpected end of file rather than a clean one.
	truncated := []byte{0x00, 0x00, 0x00, 0x00, 0x00}

	err := runAnalyze([]string{auditWritePcap(t, truncated)})
	if err == nil {
		t.Fatal("runAnalyze reads a truncated capture and returns no error, so the program exits 0")
	}

	if !strings.Contains(err.Error(), "read ") {
		t.Errorf("runAnalyze returns the error %v, and the closure of F-25-1 names the read", err)
	}
}

func TestF25_1_RunAnalyzeReturnsNoErrorForACaptureThatHoldsNoPacket(t *testing.T) {
	// The clean end of a capture is io.EOF, and the closure must not read it as a failure.
	if err := runAnalyze([]string{auditWritePcap(t, nil)}); err != nil {
		t.Errorf("runAnalyze reads an empty capture and returns the error %v", err)
	}
}

func TestF25_7_RunAnalyzeReportsTheErrorsThatProcessPacketReturns(t *testing.T) {
	// F-25-7 is closed. The loop assigned the error slice of `Processor.ProcessPacket` to
	// `_`, so the program reported no parse failure at all. It now counts them and writes
	// one line to standard error.
	//
	// The payload below is a TLS record whose handshake length exceeds the record it sits
	// in, so `ParseClientHello` returns an error.
	payload := []byte{
		0x16, 0x03, 0x01, 0x00, 0x08,
		0x01, 0x00, 0xff, 0xf0, 0x03, 0x03, 0x00, 0x00,
	}

	body := auditPacketRecord(auditTCPFrame(t, 12345, 443, payload))
	path := auditWritePcap(t, body)

	written := auditCaptureStandardError(t, func() {
		if err := runAnalyze([]string{path}); err != nil {
			t.Errorf("runAnalyze returned the error %v", err)
		}
	})

	if !strings.Contains(written, "no fingerprinter read") {
		t.Errorf("standard error holds %q, and the closure of F-25-7 names the packet count", written)
	}
}

func TestF25_8_WriteCSVReturnsTheErrorOfTheFlush(t *testing.T) {
	// F-25-8 is closed. `writeCSV` held `defer w.Flush()`, and a deferred call discards
	// the write failure that Flush records. A standard output that takes no byte made the
	// program exit 0 after it wrote no row. The function now calls Flush and returns
	// `w.Error()`.
	//
	// The pipe below has a closed read end, so every write to it fails.
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("open the pipe: %v", err)
	}

	if err := read.Close(); err != nil {
		t.Fatalf("close the read end: %v", err)
	}

	results := []ja4plus.FingerprintResult{{
		Type:        "ja4",
		SrcIP:       "192.0.2.1",
		DstIP:       "192.0.2.2",
		Fingerprint: "t13d1516h2_8daaf6152771_b186095e22b6",
		Timestamp:   time.Unix(0, 0).UTC(),
	}}

	stdout := os.Stdout
	os.Stdout = write

	produced := writeCSV(results, false)

	os.Stdout = stdout

	if err := write.Close(); err != nil {
		t.Fatalf("close the write end: %v", err)
	}

	if produced == nil {
		t.Error("writeCSV wrote to a closed pipe and returned no error, so the program exits 0")
	}
}

func TestF25_9_TheMappingDownloadCarriesATimeoutAndBoundsTheResponseBody(t *testing.T) {
	// F-25-9 is closed. `runDBUpdate` used `http.DefaultClient`, which carries no timeout,
	// and it copied the whole response body with no bound.
	// `.claude/rules/external-apis.md` states both rules.
	if ja4PlusDownloadTimeout <= 0 {
		t.Error("the download timeout is not above 0, and http.DefaultClient carries none")
	}

	if ja4PlusMappingMaxBytes <= 0 {
		t.Error("the response body limit is not above 0, so the copy is unbounded")
	}

	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	if strings.Contains(string(source), "http.DefaultClient") {
		t.Error("cmd/ja4plus/main.go reads http.DefaultClient, which carries no timeout")
	}

	if !strings.Contains(string(source), "io.LimitReader(resp.Body") {
		t.Error("cmd/ja4plus/main.go copies the response body with no limit")
	}
}
