package ja4plus

import (
	"testing"
)

// The header block of a request that declares a body of 8 bytes. The gate of #455 reads the
// `Content-Length` value, so the test states one.
const ja4hDeclaredBodyRequest = "POST /upload HTTP/1.1\r\n" +
	"Host: 192.168.235.136:8089\r\n" +
	"Content-Type: text/plain\r\n" +
	"Content-Length: 8\r\n" +
	"\r\n"

// The body that completes the request above. It holds the 8 bytes the header declares.
const ja4hDeclaredBody = "12345678"

// TestJA4H_ProducesNoValueForARequestWhoseBodyNeverCompletes holds the ruling of #455.
//
// The maintainer ruled on 2026-08-13 that the library holds the value until the payload after
// the header block reaches the byte count that `Content-Length` names. No capture of the
// corpus separates the candidate answers, so this test builds the separating packet.
// `.claude/rules/rulings.md` `## Where a ruling is recorded` states that rule, and the port's
// issue Crank-Git/ja4plus#607 carries the other half.
//
// The test fails when a reader removes the gate, because the library then produces a value
// for a request that no sender completed.
func TestJA4H_ProducesNoValueForARequestWhoseBodyNeverCompletes(t *testing.T) {
	fingerprinter := NewJA4H()

	packet := ja4hSegmentAt(t, 1000, 0, ja4hDeclaredBodyRequest)
	results, err := fingerprinter.ProcessPacket(packet)
	if err != nil {
		t.Fatalf("the header block returned an error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("the request produced %d values before its body, and the ruling states 0: %q",
			len(results), results[0].Fingerprint)
	}

	// One rule governs every path that produces a JA4H value, so the one-shot function
	// declines the same request.
	if value := ComputeJA4H(packet); value != "" {
		t.Fatalf("ComputeJA4H produced %q for a request before its body, and the ruling states \"\"",
			value)
	}
}

// TestJA4H_ProducesTheValueAtThePacketThatCompletesTheBody holds the emission frame of #455.
//
// The library produced the value at the packet that ends the header block, and the reference
// produces it later. `docs/audit/ja4h-deviation-cluster.md`
// `## Cause 2 — the library emits at the frame that ends the header block` measures the
// difference on `http1.pcapng`.
//
// The test fails when the emission frame moves back, because the first segment then carries
// the value.
func TestJA4H_ProducesTheValueAtThePacketThatCompletesTheBody(t *testing.T) {
	fingerprinter := NewJA4H()

	head := ja4hDeclaredBodyRequest + ja4hDeclaredBody[:4]
	tail := ja4hDeclaredBody[4:]

	first, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, head))
	if err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}
	if len(first) != 0 {
		t.Fatalf("the first segment produced %d values, and the emission frame states 0: %q",
			len(first), first[0].Fingerprint)
	}

	second, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, uint32(1000+len(head)), 1, tail))
	if err != nil {
		t.Fatalf("the second segment returned an error: %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("the segment that completes the body produced %d values, and the emission frame states 1",
			len(second))
	}
}

// TestJA4H_ProducesTheValueForARequestThatDeclaresNoBody holds the limit of the gate of #455.
//
// A request that names no `Content-Length` names no byte count, so the header block completes
// it. The test fails when the gate holds such a request, because the library then produces no
// value for a request that every FoxIO implementation answers.
func TestJA4H_ProducesTheValueForARequestThatDeclaresNoBody(t *testing.T) {
	fingerprinter := NewJA4H()

	results, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, ja4hRepeatedRequest))
	if err != nil {
		t.Fatalf("the request returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the request produced %d values, and the reference holds 1", len(results))
	}
}

// TestJA4H_ProducesTheValueForARequestWhoseContentLengthIsNoByteCount holds the second limit
// of the gate of #455.
//
// A `Content-Length` value that is not a byte count names no count, so the header block
// completes the request. That reading keeps a malformed header from holding a value for the
// life of the stream.
func TestJA4H_ProducesTheValueForARequestWhoseContentLengthIsNoByteCount(t *testing.T) {
	fingerprinter := NewJA4H()

	request := "POST /upload HTTP/1.1\r\n" +
		"Host: 192.168.235.136:8089\r\n" +
		"Content-Length: eight\r\n" +
		"\r\n"

	results, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, request))
	if err != nil {
		t.Fatalf("the request returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the request produced %d values, and the reading states 1", len(results))
	}
}
