package parser

import (
	"bytes"
	"testing"
)

func TestTCPStreamReassembler_Basic(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.AddSegment("flow1", 100, []byte("Hello"))
	r.AddSegment("flow1", 105, []byte("World"))

	got := r.GetStream("flow1")
	want := []byte("HelloWorld")
	if !bytes.Equal(got, want) {
		t.Errorf("GetStream = %q, want %q", got, want)
	}
}

func TestTCPStreamReassembler_OutOfOrder(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	// Add second segment first
	r.AddSegment("flow1", 105, []byte("World"))
	r.AddSegment("flow1", 100, []byte("Hello"))

	got := r.GetStream("flow1")
	want := []byte("HelloWorld")
	if !bytes.Equal(got, want) {
		t.Errorf("GetStream = %q, want %q", got, want)
	}
}

func TestTCPStreamReassembler_Duplicate(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.AddSegment("flow1", 100, []byte("Hello"))
	r.AddSegment("flow1", 100, []byte("Hello")) // duplicate
	r.AddSegment("flow1", 105, []byte("World"))

	got := r.GetStream("flow1")
	want := []byte("HelloWorld")
	if !bytes.Equal(got, want) {
		t.Errorf("GetStream = %q, want %q", got, want)
	}
}

func TestTCPStreamReassembler_Overlap(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.AddSegment("flow1", 100, []byte("HelloWo"))
	r.AddSegment("flow1", 105, []byte("World"))

	got := r.GetStream("flow1")
	want := []byte("HelloWorld")
	if !bytes.Equal(got, want) {
		t.Errorf("GetStream = %q, want %q", got, want)
	}
}

func TestTCPStreamReassembler_Eviction(t *testing.T) {
	r := NewTCPStreamReassembler(2, 4096)
	r.AddSegment("flow1", 0, []byte("aaa"))
	r.AddSegment("flow2", 0, []byte("bbb"))
	// Adding flow3 should evict flow1 (oldest)
	r.AddSegment("flow3", 0, []byte("ccc"))

	if got := r.GetStream("flow1"); got != nil {
		t.Errorf("expected flow1 to be evicted, got %q", got)
	}
	if got := r.GetStream("flow2"); !bytes.Equal(got, []byte("bbb")) {
		t.Errorf("flow2 = %q, want %q", got, "bbb")
	}
	if got := r.GetStream("flow3"); !bytes.Equal(got, []byte("ccc")) {
		t.Errorf("flow3 = %q, want %q", got, "ccc")
	}
}

func TestTCPStreamReassembler_MaxBytes(t *testing.T) {
	r := NewTCPStreamReassembler(10, 10)
	r.AddSegment("flow1", 0, []byte("12345678901234567890"))

	got := r.GetStream("flow1")
	if len(got) > 10 {
		t.Errorf("expected at most 10 bytes, got %d", len(got))
	}
}

func TestTCPStreamReassembler_RemoveStream(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.AddSegment("flow1", 0, []byte("data"))
	r.RemoveStream("flow1")

	if got := r.GetStream("flow1"); got != nil {
		t.Errorf("expected nil after RemoveStream, got %q", got)
	}
}

func TestTCPStreamReassembler_EmptyData(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.AddSegment("flow1", 0, []byte{})
	r.AddSegment("flow1", 0, nil)

	if got := r.GetStream("flow1"); got != nil {
		t.Errorf("expected nil for empty data, got %q", got)
	}
}
