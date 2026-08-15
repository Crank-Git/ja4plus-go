package capture

import (
	"sync"
	"time"

	"github.com/gopacket/gopacket"
)

// packetSource returns one packet, and it blocks until the interface delivers one.
//
// `pcapgo.EthernetHandle` satisfies it. The interface exists so that a test of every
// platform drives `deadlineReader` with a source that needs no interface and no privilege.
type packetSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// packetRead holds one answer of a packet source.
type packetRead struct {
	// data holds the bytes of one packet.
	data []byte
	// info holds the capture information of that packet.
	info gopacket.CaptureInfo
	// err holds the failure that ended the source, and it is nil for a packet.
	err error
}

// deadlineReader gives a packet source that blocks one read deadline.
//
// **`pcapgo.EthernetHandle` takes no read deadline**, measured on 2026-08-14 at gopacket
// v1.6.1 and at v1.7.1. It reads the packet socket through an `os.File` that it holds in an
// unexported field, so no caller reaches that socket to set a deadline on it. #77 recorded
// the same absence, and `statistics.go` of `cmd/ja4plus` states it.
//
// So this type reads the source on one goroutine, and `read` returns `ErrReadTimeout` when
// that goroutine delivers no answer before the deadline. Issue #610 is the reversal path: a
// release of the capture library that takes a deadline removes this type.
//
// **One goroutine calls `read` and `stop`.** That goroutine is the goroutine that owns the
// `Handle`, and the doc comment of `Handle` states the ownership.
type deadlineReader struct {
	// reads carries one answer of the source. It holds no buffer, so the read goroutine
	// holds each packet until the caller takes it and a deadline loses no packet.
	reads chan packetRead
	// done ends the read goroutine, and `stop` closes it.
	done chan struct{}
	// stopOnce closes `done` one time, so a second call of `stop` panics never.
	stopOnce sync.Once
	// deadline bounds one call of `read`.
	deadline time.Duration
	// failed holds the failure that ended the source. The goroutine that calls `read` owns
	// this field, so the field needs no lock.
	failed error
}

// newDeadlineReader returns a reader that reads the source, and it starts the read
// goroutine of that reader.
//
// The caller calls `stop` and then closes the source. A source that blocks in a read
// returns at that close, and the read goroutine then ends.
func newDeadlineReader(source packetSource, deadline time.Duration) *deadlineReader {
	reader := &deadlineReader{
		reads:    make(chan packetRead),
		done:     make(chan struct{}),
		deadline: deadline,
	}

	go reader.readSource(source)

	return reader
}

// readSource reads the source until the source fails, and until `stop` ends the reader.
//
// It ends at the first failure, because a capture handle that failed returns no packet
// again. `read` holds that failure and it reports the failure to every later call.
func (r *deadlineReader) readSource(source packetSource) {
	for {
		data, info, err := source.ReadPacketData()

		select {
		case r.reads <- packetRead{data: data, info: info, err: err}:
		case <-r.done:
			return
		}

		if err != nil {
			return
		}
	}
}

// read returns the bytes of the next packet, and the capture information of that packet.
// It returns `ErrReadTimeout` when the source delivers no answer before the deadline.
// It returns the failure of the source, and it returns that failure to every later call.
func (r *deadlineReader) read() ([]byte, gopacket.CaptureInfo, error) {
	if r.failed != nil {
		return nil, gopacket.CaptureInfo{}, r.failed
	}

	timer := time.NewTimer(r.deadline)
	defer timer.Stop()

	select {
	case answer := <-r.reads:
		if answer.err != nil {
			r.failed = answer.err
		}

		return answer.data, answer.info, answer.err
	case <-timer.C:
		return nil, gopacket.CaptureInfo{}, ErrReadTimeout
	}
}

// stop ends the read goroutine.
//
// The read goroutine ends after the read that it holds returns, so the caller closes the
// source after this call. A second call of this method ends nothing again.
func (r *deadlineReader) stop() {
	r.stopOnce.Do(func() { close(r.done) })
}
