//go:build linux || libpcap

package capture

import "time"

// linkReadDeadline bounds one read of a Link.
//
// The scanner of package `scan` sends each SYN at a rate, and it reads responses between
// two sends. A read of the monitor waits `readDeadline`, and a wait that long on an idle
// interface would hold the next SYN back past its send time. So a Link waits a shorter
// time, and the default rate of 10 SYN packets each second keeps its interval of 100 ms.
const linkReadDeadline = 10 * time.Millisecond
