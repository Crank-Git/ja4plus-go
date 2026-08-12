package parser

import (
	"bytes"
	"encoding/binary"
)

// The bounds of the SSH message walk. Every packet is untrusted input, so the walk reads a
// length field only inside these bounds and it holds a bounded buffer.
const (
	// sshLengthFieldBytes is the width of the SSH packet length field. RFC 4253 section 6
	// states it, and the length excludes the field.
	sshLengthFieldBytes = 4

	// minSSHMessageLength and maxSSHMessageLength bound the length field this walk follows.
	// A length outside them belongs to no SSH message.
	minSSHMessageLength = 2
	maxSSHMessageLength = 65536

	// sshMsgNewKeys is the message code of SSH_MSG_NEWKEYS. RFC 4253 section 7.3 states it.
	// The direction encrypts every later message, so no reader follows the length after it.
	sshMsgNewKeys = 21

	// sshMessageCodeOffset is the offset of the message code inside the message body. The
	// padding length takes the first byte, and RFC 4253 section 6 puts the code in the second.
	sshMessageCodeOffset = 1

	// maxSSHBannerBytes is the longest version line this walk reads. RFC 4253 section 4.2
	// limits the line to 255 bytes, and a longer line belongs to no SSH connection.
	maxSSHBannerBytes = 255

	// maxPendingSegments and maxPendingBytes bound the buffer that holds a segment which
	// arrives before its predecessor. A direction that loses a segment never fills the gap,
	// so the buffer needs a bound.
	maxPendingSegments = 32
	maxPendingBytes    = 65536
)

// sshTrackerState names the phase of one direction.
type sshTrackerState int

const (
	// sshTrackerBanner waits for the version line. It is the zero value, so a zero-value
	// tracker stands before the version line.
	sshTrackerBanner sshTrackerState = iota

	// sshTrackerMessages reads the length field of each message.
	sshTrackerMessages

	// sshTrackerOpaque holds a direction whose lengths no reader follows.
	sshTrackerOpaque
)

// sshBannerPrefix opens the SSH version line. RFC 4253 section 4.2 states it.
var sshBannerPrefix = []byte("SSH-")

// SSHMessageTracker reports which TCP segment of one direction completes an SSH message.
//
// The FoxIO reference counts the packets `tshark` labels `ssh`. `tshark` reassembles an SSH
// message that spans two TCP segments, and it labels only the segment that completes the
// message. `wireshark/source/packet-ja4.c:1469` counts one packet for each `ssh.direction`
// field, and `python/ja4ssh.py:94` counts the packet whose protocol list holds `ssh`. This
// type reproduces that boundary, so the JA4SSH packet count reads the SSH message and not
// the TCP segment.
//
// The tracker reads the length field only while the direction sends plaintext. Before the
// version line, and after SSH_MSG_NEWKEYS, it reports every segment as one SSH packet,
// because neither phase carries a length a reader trusts.
//
// One tracker follows one direction of one connection. The zero value is ready to read the
// first segment of a direction. One tracker serves one goroutine, and no lock guards it.
type SSHMessageTracker struct {
	state        sshTrackerState
	banner       []byte
	lengthField  []byte
	remaining    int
	bodyPosition int
	// messageCode holds the code of the message the walk reads, and -1 names a message
	// whose code no segment has delivered yet.
	messageCode int
	nextSeq     uint32
	// hasNextSeq reports whether the tracker has read a first segment. The first sequence
	// number of a direction is any 32-bit value, so a zero nextSeq names no position.
	hasNextSeq   bool
	pending      map[uint32][]byte
	pendingBytes int
}

// NewSSHMessageTracker returns a tracker that stands before the version line of one
// direction. The zero value of SSHMessageTracker reads the same way, so a caller that
// embeds the type needs no call.
func NewSSHMessageTracker() *SSHMessageTracker {
	return &SSHMessageTracker{}
}

// sshSeqOffset returns the signed distance from the base sequence number to the sequence
// number.
//
// A sequence number wraps at 2**32, so a plain comparison reads a wrapped number as a
// number far behind the base. RFC 793 section 3.3 states the wrap. The conversion to int32
// reads the distance in the shorter direction around the sequence space, and the result is
// positive when the sequence number follows the base.
func sshSeqOffset(seq, base uint32) int32 {
	return int32(seq - base)
}

// AddSegment returns the length of each segment that completes an SSH message.
//
// The tracker reads the payload of the direction in sequence order. It drops a segment the
// direction already sent, and it holds a segment that arrives before its predecessor until
// the predecessor arrives.
//
// The returned slice holds one entry for each segment the FoxIO reference counts as one SSH
// packet, in sequence order. It is empty for an empty payload, for a duplicate segment, and
// for a segment that holds part of a message and no message end.
func (t *SSHMessageTracker) AddSegment(payload []byte, seq uint32) []int {
	if len(payload) == 0 {
		return nil
	}

	if !t.hasNextSeq {
		t.nextSeq = seq
		t.hasNextSeq = true
	}

	if t.state == sshTrackerOpaque {
		// An opaque direction follows no message boundary, so the order of the segments
		// changes nothing. Every segment is one SSH packet.
		return []int{len(payload)}
	}

	if sshSeqOffset(seq, t.nextSeq) > 0 {
		return t.hold(payload, seq)
	}

	counted := t.readSegment(payload, seq)

	for t.state != sshTrackerOpaque {
		ready, readySeq, held := t.takeReady()
		if !held {
			break
		}

		counted = append(counted, t.readSegment(ready, readySeq)...)
	}

	if t.state == sshTrackerOpaque {
		t.release()
	}

	return counted
}

// readSegment returns the length of the segment when the segment completes an SSH message.
// It returns an empty slice when the direction already sent every byte of the segment.
func (t *SSHMessageTracker) readSegment(payload []byte, seq uint32) []int {
	// A retransmission repeats the bytes the tracker already read, so the tracker reads only
	// the part of the segment that follows them. The distance reads as int64, because the
	// negation of the smallest int32 overflows int32 and would index the payload out of
	// bounds.
	overlap := -int64(sshSeqOffset(seq, t.nextSeq))
	if overlap >= int64(len(payload)) {
		return nil
	}

	completed := t.CompletesMessage(payload[overlap:])
	t.nextSeq = seq + uint32(len(payload))

	if completed {
		return []int{len(payload)}
	}

	return nil
}

// hold buffers a segment that arrives before its predecessor.
//
// It returns the segment length when the buffer reaches a bound. A gap that never fills
// turns the tracker opaque, and an opaque tracker counts every segment.
func (t *SSHMessageTracker) hold(payload []byte, seq uint32) []int {
	if held, exists := t.pending[seq]; exists {
		if len(held) >= len(payload) {
			return nil
		}

		t.pendingBytes -= len(held)
	}

	if t.pending == nil {
		t.pending = make(map[uint32][]byte)
	}

	t.pending[seq] = payload
	t.pendingBytes += len(payload)

	if len(t.pending) > maxPendingSegments || t.pendingBytes > maxPendingBytes {
		t.state = sshTrackerOpaque
		t.release()

		return []int{len(payload)}
	}

	return nil
}

// takeReady returns the held segment that starts at or before the next sequence number.
// It reports false when the buffer holds no such segment.
//
// This method reads the nearest held segment from one pass, and `ja4plus/utils/ssh_utils.py:196`
// reaches the same order by a sort. **`pending` is keyed by the sequence number**, and one
// sequence number maps to one distance, so no two entries reach the same distance. `hold`
// replaces the entry of a repeated sequence number and adds no second one. A reader who
// changes the key type of `pending` breaks that invariant, and this pass then needs the sort.
// The comparison also names the smaller sequence number on a tie, because a range over a Go
// map orders nothing and a tie would otherwise pick a segment at random.
func (t *SSHMessageTracker) takeReady() ([]byte, uint32, bool) {
	var (
		bestSeq    uint32
		bestOffset int32
		found      bool
	)

	for seq := range t.pending {
		offset := sshSeqOffset(seq, t.nextSeq)
		if !found || offset < bestOffset || (offset == bestOffset && seq < bestSeq) {
			bestSeq, bestOffset, found = seq, offset, true
		}
	}

	if !found || bestOffset > 0 {
		return nil, 0, false
	}

	payload := t.pending[bestSeq]
	delete(t.pending, bestSeq)
	t.pendingBytes -= len(payload)

	return payload, bestSeq, true
}

// release drops every held segment.
func (t *SSHMessageTracker) release() {
	t.pending = nil
	t.pendingBytes = 0
}

// CompletesMessage reports whether at least one SSH message ends in this segment.
//
// It reports false for an empty segment, and false for a segment that holds part of a
// message and no message end. A caller that holds no sequence number calls this method, and
// it reads the segments in the order they arrive.
func (t *SSHMessageTracker) CompletesMessage(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}

	switch t.state {
	case sshTrackerOpaque:
		return true
	case sshTrackerBanner:
		return t.readBanner(payload)
	default:
		return t.readMessages(payload)
	}
}

// readBanner reports whether the version line ends in this segment.
//
// A capture that starts after the version line holds no message boundary, so the tracker
// turns opaque and reports true. A line above maxSSHBannerBytes does the same.
func (t *SSHMessageTracker) readBanner(payload []byte) bool {
	// The version line spans two segments on a small maximum transmission unit, so the
	// tracker matches the prefix of the line it holds so far.
	t.banner = append(t.banner, payload...)

	prefix := sshBannerPrefix
	if len(t.banner) < len(prefix) {
		prefix = prefix[:len(t.banner)]
	}

	if !bytes.HasPrefix(t.banner, prefix) {
		t.banner = nil
		t.state = sshTrackerOpaque

		return true
	}

	end := bytes.IndexByte(t.banner, '\n')
	if end < 0 {
		if len(t.banner) > maxSSHBannerBytes {
			t.banner = nil
			t.state = sshTrackerOpaque

			return true
		}

		return false
	}

	rest := append([]byte(nil), t.banner[end+1:]...)
	t.banner = nil
	t.state = sshTrackerMessages

	if len(rest) > 0 {
		t.readMessages(rest)
	}

	return true
}

// readMessages reports whether at least one message ends in this segment.
// A length field this walk denies turns the tracker opaque and reports true.
func (t *SSHMessageTracker) readMessages(payload []byte) bool {
	completed := false
	position := 0

	for position < len(payload) {
		if t.remaining > 0 {
			taken := t.remaining
			if available := len(payload) - position; taken > available {
				taken = available
			}

			// A body that spans two segments delivers the message code late, so the walk
			// reads the code at the body offset and not at the segment offset.
			codeIndex := sshMessageCodeOffset - t.bodyPosition
			if t.messageCode < 0 && codeIndex >= 0 && codeIndex < taken {
				t.messageCode = int(payload[position+codeIndex])
			}

			t.bodyPosition += taken
			t.remaining -= taken
			position += taken

			if t.remaining == 0 {
				completed = true

				if t.messageCode == sshMsgNewKeys {
					t.state = sshTrackerOpaque

					return true
				}
			}

			continue
		}

		needed := sshLengthFieldBytes - len(t.lengthField)
		if len(payload)-position < needed {
			// The length field spans two segments. Keep the bytes that arrived.
			t.lengthField = append(t.lengthField, payload[position:]...)

			return completed
		}

		t.lengthField = append(t.lengthField, payload[position:position+needed]...)
		position += needed

		messageLength := binary.BigEndian.Uint32(t.lengthField)
		t.lengthField = nil

		if messageLength < minSSHMessageLength || messageLength > maxSSHMessageLength {
			// A length this walk denies ends the walk, and the tracker counts every later
			// segment.
			t.state = sshTrackerOpaque

			return true
		}

		t.remaining = int(messageLength)
		t.bodyPosition = 0
		t.messageCode = -1
	}

	return completed
}
