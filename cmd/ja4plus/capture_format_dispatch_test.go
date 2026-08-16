package main

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// These tests hold the closure of issue #727.
// The analyze command dispatched on the file extension, so it refused a classic pcap named
// `.pcapng`. A capture file names its own format in its first four bytes.
// A file extension is a convention that a writer may not follow.
// The FoxIO corpus ships one such file, and `loadPCAP` in `integration_test.go` reads the
// magic number for that reason.
//
// Each test fails when the extension reaches the dispatch again.

// dispatchWriteCapture writes the bytes under the name the caller states, in a directory
// that the test owns. It returns the path of the file.
func dispatchWriteCapture(t *testing.T, name string, content []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	return path
}

// dispatchClassicPcap returns a libpcap file that carries the frames.
// The global header holds the magic number, the two version numbers, the time zone, the
// accuracy, the snapshot length and the link type. Link type 1 is Ethernet.
func dispatchClassicPcap(frames [][]byte) []byte {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], 65535)
	binary.LittleEndian.PutUint32(header[20:24], 1)

	out := header
	for _, frame := range frames {
		out = append(out, auditPacketRecord(frame)...)
	}

	return out
}

// dispatchPcapng returns a pcapng file that carries the frames.
// It writes through the writer of the packet library, so the bytes hold whatever Section
// Header Block that library produces today.
func dispatchPcapng(t *testing.T, frames [][]byte) []byte {
	t.Helper()

	path := filepath.Join(t.TempDir(), "source.bytes")

	file, err := os.Create(path) //nolint:gosec // The path names a directory that the test owns.
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}

	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("open the pcapng writer: %v", err)
	}

	for _, frame := range frames {
		info := gopacket.CaptureInfo{CaptureLength: len(frame), Length: len(frame)}
		if err := writer.WritePacket(info, frame); err != nil {
			t.Fatalf("write the frame: %v", err)
		}
	}

	if err := writer.Flush(); err != nil {
		t.Fatalf("flush the pcapng writer: %v", err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}

	content, err := os.ReadFile(path) //nolint:gosec // The path names a directory that the test owns.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return content
}

// dispatchSYNFrame returns one Ethernet frame that carries a TCP SYN over IPv4.
// The JA4T fingerprinter reads a SYN, so the analyze command prints a value for it.
func dispatchSYNFrame(t *testing.T) []byte {
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
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(443),
		SYN:     true,
		Window:  65535,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{0x08}},
		},
	}

	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set the network layer of the TCP checksum: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializeLayers(buffer, options, ethernet, ip, tcp); err != nil {
		t.Fatalf("serialize the frame: %v", err)
	}

	return buffer.Bytes()
}

// dispatchCaptureStandardOutput runs the call with a pipe on standard output and returns
// what the call wrote to it.
func dispatchCaptureStandardOutput(t *testing.T, call func()) string {
	t.Helper()

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("open the pipe: %v", err)
	}

	// The read end holds a file descriptor for the whole test binary, so the helper closes
	// it. Five cases call this helper, and each one leaks a descriptor without the close.
	defer func() { _ = read.Close() }()

	stdout := os.Stdout
	os.Stdout = write

	call()

	os.Stdout = stdout

	if err := write.Close(); err != nil {
		t.Fatalf("close the write end: %v", err)
	}

	written, err := io.ReadAll(read)
	if err != nil {
		t.Fatalf("read the pipe: %v", err)
	}

	return string(written)
}

// dispatchAnalyzeReadsThePackets runs the analyze command over the path, and it fails when
// the command returns an error or prints no fingerprint.
//
// A reader that starts at the fourth byte rejects a valid file, so the assertion on the
// printed value proves that the whole file reached the reader.
func dispatchAnalyzeReadsThePackets(t *testing.T, path string) {
	t.Helper()

	var err error

	written := dispatchCaptureStandardOutput(t, func() {
		err = runAnalyze([]string{path})
	})

	if err != nil {
		t.Fatalf("runAnalyze returns the error %v for %s", err, path)
	}

	if !strings.Contains(written, "ja4t") {
		t.Errorf("runAnalyze prints %q for %s, and it reads no packet of the file", written, path)
	}
}

func TestRunAnalyzeReadsAClassicPcapUnderTheNamePcap(t *testing.T) {
	content := dispatchClassicPcap([][]byte{dispatchSYNFrame(t)})
	dispatchAnalyzeReadsThePackets(t, dispatchWriteCapture(t, "capture.pcap", content))
}

func TestRunAnalyzeReadsAClassicPcapUnderTheNamePcapng(t *testing.T) {
	// This case is the refusal of issue #727. The FoxIO corpus ships `http1.pcapng`, whose
	// magic number reads `a1b2c3d4`, and the extension dispatch answered it with
	// `failed to read pcapng: Unknown magic a1b2c3d4`.
	content := dispatchClassicPcap([][]byte{dispatchSYNFrame(t)})
	dispatchAnalyzeReadsThePackets(t, dispatchWriteCapture(t, "capture.pcapng", content))
}

func TestRunAnalyzeReadsAPcapngUnderTheNamePcapng(t *testing.T) {
	content := dispatchPcapng(t, [][]byte{dispatchSYNFrame(t)})
	dispatchAnalyzeReadsThePackets(t, dispatchWriteCapture(t, "capture.pcapng", content))
}

func TestRunAnalyzeReadsAPcapngUnderTheNamePcap(t *testing.T) {
	content := dispatchPcapng(t, [][]byte{dispatchSYNFrame(t)})
	dispatchAnalyzeReadsThePackets(t, dispatchWriteCapture(t, "capture.pcap", content))
}

func TestRunAnalyzeReadsACaptureThatCarriesNoExtension(t *testing.T) {
	// The magic number decides the format, so a file with no extension still reads.
	content := dispatchPcapng(t, [][]byte{dispatchSYNFrame(t)})
	dispatchAnalyzeReadsThePackets(t, dispatchWriteCapture(t, "capture", content))
}

func TestRunAnalyzeReturnsAnErrorForAFileShorterThanFourBytes(t *testing.T) {
	// The sniff reads four bytes, and a shorter file gives it fewer. The command reports
	// the error, and it never panics.
	for _, content := range [][]byte{nil, {0x0a}, {0x0a, 0x0d}, {0x0a, 0x0d, 0x0d}} {
		path := dispatchWriteCapture(t, "short.pcap", content)

		if err := runAnalyze([]string{path}); err == nil {
			t.Errorf("runAnalyze reads a file of %d bytes and returns no error", len(content))
		}
	}
}

func TestRunAnalyzeReportsThePcapngFormatWhenAPcapngFileFails(t *testing.T) {
	// A file whose magic number reads `0a0d0d0a` is a pcapng file, and a failure on it must
	// still name that format. A truncated Section Header Block reaches the pcapng reader.
	content := []byte{0x0a, 0x0d, 0x0d, 0x0a, 0x00, 0x00}
	path := dispatchWriteCapture(t, "truncated.pcapng", content)

	err := runAnalyze([]string{path})
	if err == nil {
		t.Fatal("runAnalyze reads a truncated pcapng file and returns no error")
	}

	if !strings.Contains(err.Error(), "pcapng") {
		t.Errorf("runAnalyze returns the error %v, and it names no pcapng format", err)
	}
}
