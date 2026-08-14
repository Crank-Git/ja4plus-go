//go:build !linux && !darwin

package capture

// captureRefusal returns nil on a platform that holds neither a packet socket nor a BPF
// device.
//
// Linux holds the packet socket, and `permission_linux.go` probes it. macOS holds the BPF
// device, and `permission_darwin.go` probes it. The release workflow builds five
// platforms, and Windows is the one that reaches this file. `unsupportedMessage` of
// `unsupported.go` states that the monitor reads no interface there, so no run of Windows
// reaches a capture handle and no probe answers a question.
func captureRefusal() error {
	return nil
}
