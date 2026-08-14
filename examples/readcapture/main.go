// Command readcapture reads a capture file and prints one line for each fingerprint.
//
// This program mirrors the fenced Go block of `docs/usage.md`, and
// `TestEveryGoSampleOfTheSiteIsARunnableProgram` holds the two equal. Edit the page and
// this file together.
//
// It reads `capture.pcap` from the working directory, and it reaches no network.
package main

import (
	"fmt"
	"os"

	ja4plus "github.com/Crank-Git/ja4plus-go"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

func main() {
	f, _ := os.Open("capture.pcap")
	defer f.Close()

	reader, _ := pcapgo.NewReader(f)
	proc := ja4plus.NewProcessor()

	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		pkt.Metadata().Timestamp = ci.Timestamp

		results, _ := proc.ProcessPacket(pkt)
		for _, r := range results {
			fmt.Printf("[%s] %s:%d -> %s:%d  %s\n",
				r.Type, r.SrcIP, r.SrcPort, r.DstIP, r.DstPort, r.Fingerprint)
		}
	}
}
