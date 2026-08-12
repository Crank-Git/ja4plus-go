package parser

import (
	"encoding/binary"
	"testing"
)

// sshMessage returns one whole SSH binary packet whose body holds the message code.
// The length field states the byte count that follows it, which RFC 4253 section 6 states.
func sshMessage(bodyLength int, code byte) []byte {
	message := make([]byte, sshLengthFieldBytes+bodyLength)
	binary.BigEndian.PutUint32(message, uint32(bodyLength))
	// The padding length takes the first body byte, and the message code takes the second.
	message[4] = 4

	if bodyLength > 1 {
		message[5] = code
	}

	return message
}

// sshBanner holds one version line that RFC 4253 section 4.2 admits.
var sshBanner = []byte("SSH-2.0-OpenSSH_8.9\r\n")

func TestSSHMessageTrackerCountsTheSegmentThatEndsTheVersionLine(t *testing.T) {
	var tracker SSHMessageTracker

	counted := tracker.AddSegment(sshBanner, 1)
	if len(counted) != 1 || counted[0] != len(sshBanner) {
		t.Fatalf("the tracker counted %v, and the segment holds the whole version line", counted)
	}
}

func TestSSHMessageTrackerCountsNoSegmentThatHoldsPartOfTheVersionLine(t *testing.T) {
	var tracker SSHMessageTracker

	if counted := tracker.AddSegment(sshBanner[:8], 1); len(counted) != 0 {
		t.Errorf("the tracker counted %v, and the segment holds no line end", counted)
	}

	counted := tracker.AddSegment(sshBanner[8:], uint32(1+8))
	if len(counted) != 1 || counted[0] != len(sshBanner)-8 {
		t.Errorf("the tracker counted %v, and the second segment ends the version line", counted)
	}
}

func TestSSHMessageTrackerCountsNoSegmentThatHoldsPartOfAMessage(t *testing.T) {
	var tracker SSHMessageTracker

	tracker.AddSegment(sshBanner, 1)

	message := sshMessage(60, 94)
	seq := uint32(1 + len(sshBanner))

	if counted := tracker.AddSegment(message[:20], seq); len(counted) != 0 {
		t.Errorf("the tracker counted %v, and the segment holds no message end", counted)
	}

	counted := tracker.AddSegment(message[20:], seq+20)
	if len(counted) != 1 || counted[0] != len(message)-20 {
		t.Errorf("the tracker counted %v, and the second segment ends the message", counted)
	}
}

func TestSSHMessageTrackerCountsOneSegmentThatEndsTwoMessages(t *testing.T) {
	var tracker SSHMessageTracker

	tracker.AddSegment(sshBanner, 1)

	// FoxIO counts the packets `tshark` labels `ssh`, and one frame carries one label. A
	// segment that ends two messages is one SSH packet.
	pair := append(sshMessage(20, 94), sshMessage(20, 94)...)

	counted := tracker.AddSegment(pair, uint32(1+len(sshBanner)))
	if len(counted) != 1 || counted[0] != len(pair) {
		t.Errorf("the tracker counted %v, and one segment is one SSH packet", counted)
	}
}

func TestSSHMessageTrackerCountsEverySegmentAfterNewKeys(t *testing.T) {
	var tracker SSHMessageTracker

	tracker.AddSegment(sshBanner, 1)

	newKeys := sshMessage(20, sshMsgNewKeys)
	seq := uint32(1 + len(sshBanner))

	if counted := tracker.AddSegment(newKeys, seq); len(counted) != 1 {
		t.Fatalf("the tracker counted %v, and the segment ends SSH_MSG_NEWKEYS", counted)
	}

	// A cipher hides the length field of every later record, so the tracker follows no
	// message boundary and counts every segment.
	seq += uint32(len(newKeys))

	for count := 0; count < 3; count++ {
		record := make([]byte, 36)
		counted := tracker.AddSegment(record, seq)

		if len(counted) != 1 || counted[0] != len(record) {
			t.Errorf("the tracker counted %v for encrypted record %d, and it counts every one",
				counted, count+1)
		}

		seq += uint32(len(record))
	}
}

func TestSSHMessageTrackerCountsARetransmissionOnce(t *testing.T) {
	var tracker SSHMessageTracker

	if counted := tracker.AddSegment(sshBanner, 1); len(counted) != 1 {
		t.Fatalf("the tracker counted %v for the first segment", counted)
	}

	if counted := tracker.AddSegment(sshBanner, 1); len(counted) != 0 {
		t.Errorf("the tracker counted %v for a retransmission, and it counts one segment once", counted)
	}
}

func TestSSHMessageTrackerHoldsASegmentThatArrivesBeforeItsPredecessor(t *testing.T) {
	var tracker SSHMessageTracker

	tracker.AddSegment(sshBanner, 1)

	message := sshMessage(60, 94)
	seq := uint32(1 + len(sshBanner))

	// The second half arrives first, so the tracker holds it until the first half arrives.
	if counted := tracker.AddSegment(message[20:], seq+20); len(counted) != 0 {
		t.Errorf("the tracker counted %v, and the segment follows a gap", counted)
	}

	counted := tracker.AddSegment(message[:20], seq)
	if len(counted) != 1 || counted[0] != len(message)-20 {
		t.Errorf("the tracker counted %v, and the held segment ends the message", counted)
	}
}

func TestSSHMessageTrackerCountsEverySegmentWhenAGapNeverFills(t *testing.T) {
	var tracker SSHMessageTracker

	tracker.AddSegment(sshBanner, 1)

	// A direction that loses a segment never fills the gap, so the buffer holds a bound and
	// the tracker turns opaque at it.
	seq := uint32(1 + len(sshBanner))
	var counted []int

	for count := 0; count <= maxPendingSegments; count++ {
		counted = tracker.AddSegment(make([]byte, 40), seq+100+uint32(count*40))
	}

	if len(counted) != 1 {
		t.Errorf("the tracker counted %v at the buffer bound, and it counts every later segment", counted)
	}
}

func TestSSHMessageTrackerCountsEverySegmentOfALengthItDenies(t *testing.T) {
	var tracker SSHMessageTracker

	tracker.AddSegment(sshBanner, 1)

	// Every packet is untrusted input. A length field above maxSSHMessageLength belongs to no
	// SSH message, so the walk ends and the tracker counts every later segment.
	denied := make([]byte, 40)
	binary.BigEndian.PutUint32(denied, maxSSHMessageLength+1)

	counted := tracker.AddSegment(denied, uint32(1+len(sshBanner)))
	if len(counted) != 1 {
		t.Errorf("the tracker counted %v, and it denies the length field", counted)
	}
}

func TestSSHMessageTrackerCountsEverySegmentOfACaptureThatMissesTheVersionLine(t *testing.T) {
	var tracker SSHMessageTracker

	// A capture that starts after the version line holds no message boundary the tracker can
	// find, so it counts every segment.
	counted := tracker.AddSegment([]byte("not a version line"), 1)
	if len(counted) != 1 {
		t.Errorf("the tracker counted %v, and the first segment opens with no version line", counted)
	}
}

func TestSSHMessageTrackerCountsEverySegmentOfAVersionLineAboveTheLimit(t *testing.T) {
	var tracker SSHMessageTracker

	// RFC 4253 section 4.2 limits the version line to 255 bytes, and a longer line belongs to
	// no SSH connection.
	line := make([]byte, maxSSHBannerBytes+1)
	copy(line, "SSH-")

	counted := tracker.AddSegment(line, 1)
	if len(counted) != 1 {
		t.Errorf("the tracker counted %v, and the line passes the limit of RFC 4253", counted)
	}
}

func TestSSHMessageTrackerCountsNoEmptySegment(t *testing.T) {
	var tracker SSHMessageTracker

	if counted := tracker.AddSegment(nil, 1); len(counted) != 0 {
		t.Errorf("the tracker counted %v for an empty payload", counted)
	}

	if tracker.CompletesMessage(nil) {
		t.Error("the tracker reports that an empty segment ends a message")
	}
}

func TestSSHMessageTrackerReadsAWrappedSequenceNumber(t *testing.T) {
	var tracker SSHMessageTracker

	// RFC 793 section 3.3 wraps a sequence number at 2**32. The first segment ends past the
	// wrap, so a plain comparison would read the second segment as a segment far behind.
	base := ^uint32(0) - 3
	tracker.AddSegment(sshBanner[:8], base)

	counted := tracker.AddSegment(sshBanner[8:], base+8)
	if len(counted) != 1 {
		t.Errorf("the tracker counted %v across the sequence wrap, and the segment ends the line",
			counted)
	}
}

func TestNewSSHMessageTrackerReadsTheSameWayAsTheZeroValue(t *testing.T) {
	tracker := NewSSHMessageTracker()

	counted := tracker.AddSegment(sshBanner, 1)
	if len(counted) != 1 {
		t.Errorf("the tracker counted %v, and the segment holds the whole version line", counted)
	}
}
