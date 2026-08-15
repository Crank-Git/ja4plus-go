package capture

import "testing"

// The drop count of issue #81. FR-capture-31 reports the count, and FR-capture-34 states
// that the pure-Go backend reads it from the packet socket.
//
// No test of this file opens a packet socket, because a packet socket needs a privilege
// that no test holds, and it reaches Linux alone. The accumulator carries no build
// constraint, so every platform runs the test below.

// TestTheDropAccumulatorReturnsTheTotalSinceTheHandleOpened reads FR-capture-31. The
// packet socket of Linux resets its counter at each read, so the backend accumulates each
// delta.
func TestTheDropAccumulatorReturnsTheTotalSinceTheHandleOpened(t *testing.T) {
	var accumulator dropAccumulator

	cases := []struct {
		delta uint32
		total uint64
	}{
		{delta: 0, total: 0},
		{delta: 12, total: 12},
		{delta: 0, total: 12},
		{delta: 5, total: 17},
	}

	for _, one := range cases {
		if total := accumulator.add(one.delta); total != one.total {
			t.Errorf("the accumulator returns %d for the delta %d, and the total is %d",
				total, one.delta, one.total)
		}
	}
}

// TestTheDropAccumulatorHoldsATotalAboveTheWidthOfOneDelta reads FR-capture-31. The kernel
// reports a delta of 32 bits, and a monitor that runs for weeks passes that width.
func TestTheDropAccumulatorHoldsATotalAboveTheWidthOfOneDelta(t *testing.T) {
	var accumulator dropAccumulator

	accumulator.add(^uint32(0))

	total := accumulator.add(1)
	if total != uint64(^uint32(0))+1 {
		t.Errorf("the accumulator returns %d, and the total passes the width of one delta", total)
	}
}
