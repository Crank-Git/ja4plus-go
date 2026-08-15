package capture

import (
	"errors"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// testReadDeadline bounds one read of these tests. It is shorter than `readDeadline`,
// because a test that waits for the production deadline pays that wait at every run.
const testReadDeadline = 20 * time.Millisecond

// stubPacketSource holds each read until the test delivers one answer.
//
// The source needs no interface and no privilege, so a test of every platform drives
// `deadlineReader` with it. The type carries no build constraint for the same reason, and
// `dropAccumulator` of `capture.go` states the same reading.
type stubPacketSource struct {
	// answers carries one answer for each read. The test writes it.
	answers chan packetRead
	// reads carries one signal for each read the source begins. A test counts the signals,
	// so it proves that the read goroutine ended.
	reads chan struct{}
}

// newStubPacketSource returns a source that holds each read until the test answers it.
func newStubPacketSource() *stubPacketSource {
	return &stubPacketSource{
		answers: make(chan packetRead),
		reads:   make(chan struct{}, 8),
	}
}

// ReadPacketData returns the answer that the test delivers, and it blocks until then.
func (s *stubPacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	s.reads <- struct{}{}

	answer := <-s.answers

	return answer.data, answer.info, answer.err
}

func TestTheReadDeadlineIsPositiveForEveryBackend(t *testing.T) {
	// Each backend reads `readDeadline`. The libpcap backend passes it to `pcap.OpenLive`,
	// and `pcap.BlockForever` is negative: that value makes each read block until the
	// interface delivers a packet. Issue #610 measured the cost of a read that blocks
	// forever, so this test fails when a later change restores a value of zero or below.
	//
	// This test carries no build constraint, because one constant serves the two backends
	// and the default build of macOS selects neither one.
	if readDeadline <= 0 {
		t.Fatalf("the read deadline is %v, and each read then blocks until a packet arrives", readDeadline)
	}
}

func TestTheReadDeadlineReportsATimeoutWhenTheSourceDeliversNoPacket(t *testing.T) {
	// Issue #610 records the cost of a read that blocks forever: one `SIGINT` did not stop
	// the monitor on an interface that carries no traffic.
	source := newStubPacketSource()
	reader := newDeadlineReader(source, testReadDeadline)

	data, _, err := reader.read()

	if !errors.Is(err, ErrReadTimeout) {
		t.Fatalf("the reader returns the error %v, and it reports no read deadline", err)
	}
	if data != nil {
		t.Errorf("the reader returns %d bytes beside the read deadline", len(data))
	}

	releaseStubPacketSource(t, source, reader)
}

func TestTheReadDeadlineReturnsThePacketThatTheSourceDelivers(t *testing.T) {
	source := newStubPacketSource()
	reader := newDeadlineReader(source, time.Minute)

	packet := []byte{1, 2, 3, 4}
	go func() {
		source.answers <- packetRead{
			data: packet,
			info: gopacket.CaptureInfo{CaptureLength: len(packet), Length: len(packet)},
		}
	}()

	data, info, err := reader.read()

	if err != nil {
		t.Fatalf("the reader returns the error %v for a packet", err)
	}
	if len(data) != len(packet) {
		t.Errorf("the reader returns %d bytes, and the source delivered %d", len(data), len(packet))
	}
	if info.CaptureLength != len(packet) {
		t.Errorf("the reader returns the capture length %d, and the source delivered %d", info.CaptureLength, len(packet))
	}

	releaseStubPacketSource(t, source, reader)
}

func TestTheReadDeadlineDeliversThePacketThatFollowsATimeout(t *testing.T) {
	// A read that reaches the deadline loses no packet. The read goroutine holds the packet
	// until the caller reads again, because the channel holds no buffer.
	source := newStubPacketSource()
	reader := newDeadlineReader(source, testReadDeadline)

	if _, _, err := reader.read(); !errors.Is(err, ErrReadTimeout) {
		t.Fatalf("the first read returns the error %v, and it reports no read deadline", err)
	}

	packet := []byte{9, 9, 9}
	go func() {
		source.answers <- packetRead{data: packet, info: gopacket.CaptureInfo{CaptureLength: len(packet)}}
	}()

	data, _, err := reader.read()

	if err != nil {
		t.Fatalf("the second read returns the error %v for a packet", err)
	}
	if len(data) != len(packet) {
		t.Errorf("the second read returns %d bytes, and the source delivered %d", len(data), len(packet))
	}

	releaseStubPacketSource(t, source, reader)
}

func TestTheReadDeadlineReportsTheFailureOfTheSourceToEveryLaterRead(t *testing.T) {
	// The read goroutine ends at the first failure. A later read reports that failure, and
	// it reports no read deadline, so `readPackets` of `cmd/ja4plus` reads one failure and
	// never a deadline that follows it.
	source := newStubPacketSource()
	reader := newDeadlineReader(source, testReadDeadline)

	failure := errors.New("the interface is removed")
	go func() { source.answers <- packetRead{err: failure} }()

	if _, _, err := reader.read(); !errors.Is(err, failure) {
		t.Fatalf("the first read returns the error %v, and the source delivered %v", err, failure)
	}

	if _, _, err := reader.read(); !errors.Is(err, failure) {
		t.Fatalf("the second read returns the error %v, and the source delivered %v", err, failure)
	}

	reader.stop()
}

func TestTheReadDeadlineStopsItsReadGoroutine(t *testing.T) {
	// `Close` of the backend stops the reader and then closes the socket, so the read
	// goroutine ends. #612 records the cost of a goroutine that outlives its owner.
	source := newStubPacketSource()
	reader := newDeadlineReader(source, testReadDeadline)

	<-source.reads

	reader.stop()

	// The close of the socket ends the read that the goroutine holds, and this answer
	// stands for that close.
	source.answers <- packetRead{err: errors.New("use of closed file")}

	select {
	case <-source.reads:
		t.Fatal("the read goroutine read the source after the stop")
	case <-time.After(4 * testReadDeadline):
	}
}

// releaseStubPacketSource ends the read goroutine of the reader, so no goroutine of a test
// outlives that test.
func releaseStubPacketSource(t *testing.T, source *stubPacketSource, reader *deadlineReader) {
	t.Helper()

	reader.stop()

	select {
	case source.answers <- packetRead{err: errors.New("use of closed file")}:
	case <-time.After(time.Second):
	}
}
