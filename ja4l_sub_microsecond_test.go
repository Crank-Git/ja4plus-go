package ja4plus

import (
	"net"
	"testing"
	"time"
)

// The tests of this file hold part a of a JA4L value for an interval below 2 microseconds.
// Issue #809 removed a floor of 1 that no FoxIO source states.
//
// Each FoxIO implementation at commit `16b96d95c220762cf658f67d678cda2aac95c81e` writes 0 for
// an interval of 1 microsecond.
//
//   - `python/common.py:184` returns `(dt2 - dt1) // timedelta(microseconds=2)`.
//   - `rust/ja4/src/time/tcp.rs:179` divides the interval by 2, and `:180` holds the comment
//     `// 0 if the difference == 1`.
//   - `wireshark/source/packet-ja4.c:1354` writes `latency.nsecs / 2 / 1000`.
//   - `zeek/scripts/fingerprints/ja4l/main.zeek:113` writes `double_to_count(dt)` of the
//     halved interval.
//
// The port writes `int((end - start) / LATENCY_DIVISOR)` at
// `ja4plus/fingerprinters/ja4l.py:422` of tag `v1.3.0`, with no floor.

// The two hosts and the two initial sequence numbers serve every connection of this file.
var (
	ja4lSubMicrosecondClient = net.IP{192, 168, 1, 1}
	ja4lSubMicrosecondServer = net.IP{10, 0, 0, 1}
)

const (
	ja4lSubMicrosecondClientISN uint32 = 1000
	ja4lSubMicrosecondServerISN uint32 = 2000
)

// ja4lHandshake sends the SYN, the SYN-ACK and the bare ACK of one connection at the three
// offsets from one base time. It returns the results of the SYN-ACK and of the bare ACK.
func ja4lHandshake(t *testing.T, syn, synAck, ack time.Duration) (server, client []FingerprintResult) {
	t.Helper()

	fp := NewJA4L()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	synPkt := buildTCPStreamPacket(t, ja4lSubMicrosecondClient, ja4lSubMicrosecondServer, 64, 12345, 443,
		true, false, ja4lSubMicrosecondClientISN, 0, nil)
	synPkt.Metadata().Timestamp = base.Add(syn)
	if _, err := fp.ProcessPacket(synPkt); err != nil {
		t.Fatalf("SYN: unexpected error: %v", err)
	}

	synAckPkt := buildTCPStreamPacket(t, ja4lSubMicrosecondServer, ja4lSubMicrosecondClient, 58, 443, 12345,
		true, true, ja4lSubMicrosecondServerISN, ja4lSubMicrosecondClientISN+1, nil)
	synAckPkt.Metadata().Timestamp = base.Add(synAck)
	server, err := fp.ProcessPacket(synAckPkt)
	if err != nil {
		t.Fatalf("SYN-ACK: unexpected error: %v", err)
	}

	ackPkt := buildTCPStreamPacket(t, ja4lSubMicrosecondClient, ja4lSubMicrosecondServer, 64, 12345, 443,
		false, true, ja4lSubMicrosecondClientISN+1, ja4lSubMicrosecondServerISN+1, nil)
	ackPkt.Metadata().Timestamp = base.Add(ack)
	client, err = fp.ProcessPacket(ackPkt)
	if err != nil {
		t.Fatalf("bare ACK: unexpected error: %v", err)
	}

	return server, client
}

func TestJA4LWritesZeroForAServerIntervalOfOneMicrosecond(t *testing.T) {
	server, _ := ja4lHandshake(t, 0, time.Microsecond, 100*time.Microsecond)

	if got, want := ja4lLastFingerprint(t, server), "JA4L-S=0_58"; got != want {
		t.Errorf("SYN-ACK: Fingerprint = %q, want %q", got, want)
	}
}

func TestJA4LWritesZeroForAClientIntervalOfOneMicrosecond(t *testing.T) {
	_, client := ja4lHandshake(t, 0, 100*time.Microsecond, 101*time.Microsecond)

	if got, want := ja4lLastFingerprint(t, client), "JA4L-C=0_64"; got != want {
		t.Errorf("bare ACK: Fingerprint = %q, want %q", got, want)
	}
}

// TestJA4LWritesOneForANegativeInterval holds the present value of an interval below zero.
//
// This test asserts the present behavior, and it states no rule. Issue #253 records that the
// FoxIO implementations disagree on an interval below zero. Issue #809 removed the floor for an interval of 0 or 1 microsecond, and it kept
// this value. A change to it waits for a ruling.
func TestJA4LWritesOneForANegativeInterval(t *testing.T) {
	cases := []struct {
		name                   string
		syn, synAck, ack       time.Duration
		wantServer, wantClient string
	}{
		{
			name:       "the SYN-ACK carries a timestamp before the SYN",
			syn:        50 * time.Microsecond,
			synAck:     0,
			ack:        100 * time.Microsecond,
			wantServer: "JA4L-S=1_58",
			wantClient: "JA4L-C=50_64",
		},
		{
			name:       "the bare ACK carries a timestamp before the SYN-ACK",
			syn:        0,
			synAck:     100 * time.Microsecond,
			ack:        50 * time.Microsecond,
			wantServer: "JA4L-S=50_58",
			wantClient: "JA4L-C=1_64",
		},
		{
			name:       "the bare ACK carries a timestamp 1 microsecond before the SYN-ACK",
			syn:        0,
			synAck:     100 * time.Microsecond,
			ack:        99 * time.Microsecond,
			wantServer: "JA4L-S=50_58",
			wantClient: "JA4L-C=1_64",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := ja4lHandshake(t, tc.syn, tc.synAck, tc.ack)

			if got := ja4lLastFingerprint(t, server); got != tc.wantServer {
				t.Errorf("SYN-ACK: Fingerprint = %q, want %q", got, tc.wantServer)
			}
			if got := ja4lLastFingerprint(t, client); got != tc.wantClient {
				t.Errorf("bare ACK: Fingerprint = %q, want %q", got, tc.wantClient)
			}
		})
	}
}
