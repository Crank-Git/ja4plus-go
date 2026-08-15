package ja4plus

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ---------------------------------------------------------------------------
// Issue #155 — every exported entry point fills the state it reads
// ---------------------------------------------------------------------------

// zeroValueSweepTypes names the type of every fingerprinter that the package exports.
// CLAUDE.md states the count: ten fingerprinters carry eleven methods.
var zeroValueSweepTypes = []reflect.Type{
	reflect.TypeOf(JA4Fingerprinter{}),
	reflect.TypeOf(JA4DFingerprinter{}),
	reflect.TypeOf(JA4D6Fingerprinter{}),
	reflect.TypeOf(JA4HFingerprinter{}),
	reflect.TypeOf(JA4LFingerprinter{}),
	reflect.TypeOf(JA4SFingerprinter{}),
	reflect.TypeOf(JA4SSHFingerprinter{}),
	reflect.TypeOf(JA4TFingerprinter{}),
	reflect.TypeOf(JA4TSFingerprinter{}),
	reflect.TypeOf(JA4XFingerprinter{}),
}

// zeroValueSweepPacketType is the interface that a packet parameter takes.
var zeroValueSweepPacketType = reflect.TypeOf((*gopacket.Packet)(nil)).Elem()

// zeroValueSweepInput is one packet of the sweep, with the protocol name that the
// connection parameters carry.
type zeroValueSweepInput struct {
	// name states the shape of the packet.
	name string
	// proto is `tcp` or `udp`, and it fills the protocol parameter of a method.
	proto string
	// packet is the one packet that a packet parameter takes.
	packet gopacket.Packet
}

// zeroValueSweepInputs builds one well formed packet for each transport protocol.
//
// The sweep states a property of the zero value and not of the parser, so two packets
// reach every entry point. The payload of each one is valid, because a rejected payload
// returns before the method reads its state.
func zeroValueSweepInputs(t *testing.T) []zeroValueSweepInput {
	t.Helper()

	web := gopacket.NewPacket(
		panicAuditFrame(t, "tcp", 12345, 80, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")),
		layers.LayerTypeEthernet, gopacket.Default)

	// A QUIC long header that carries version 1 and an 8-byte connection identifier.
	quic := gopacket.NewPacket(
		panicAuditFrame(t, "udp", 12345, 443, []byte{
			0xc0, 0x00, 0x00, 0x00, 0x01, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00,
		}),
		layers.LayerTypeEthernet, gopacket.Default)

	return []zeroValueSweepInput{
		{"tcp", "tcp", web},
		{"udp", "udp", quic},
	}
}

// zeroValueSweepArguments returns one argument for each parameter of the method.
//
// A string parameter takes an address, an address, then the protocol name, because every
// connection parameter list of this package runs in that order. The test fails on a
// parameter type that the table does not hold, so a new signature reaches a person.
func zeroValueSweepArguments(t *testing.T, method reflect.Type, input zeroValueSweepInput) []reflect.Value {
	t.Helper()

	if method.IsVariadic() {
		t.Fatalf("the sweep fills no variadic parameter list, and one method now takes %v", method)
	}

	addresses := []string{"192.0.2.1", "192.0.2.2"}
	ports := []uint16{12345, 443}

	addressIndex := 0
	portIndex := 0

	arguments := make([]reflect.Value, 0, method.NumIn())

	for index := 0; index < method.NumIn(); index++ {
		parameter := method.In(index)

		switch {
		case parameter == zeroValueSweepPacketType:
			arguments = append(arguments, reflect.ValueOf(input.packet))
		case parameter.Kind() == reflect.String:
			value := input.proto
			if addressIndex < len(addresses) {
				value = addresses[addressIndex]
			}

			addressIndex++

			arguments = append(arguments, reflect.ValueOf(value).Convert(parameter))
		case parameter.Kind() == reflect.Uint16:
			value := ports[portIndex%len(ports)]
			portIndex++

			arguments = append(arguments, reflect.ValueOf(value).Convert(parameter))
		default:
			t.Fatalf("the sweep fills no parameter of type %v", parameter)
		}
	}

	return arguments
}

func TestAZeroValueFingerprinterSurvivesEveryExportedMethod(t *testing.T) {
	// Issue #155 records that `ensure` gated `ProcessPacket` alone, and that
	// `JA4HFingerprinter.CleanupConnection` panicked on a zero value. This test states the
	// property of the package rather than the three sites that the issue names, so a later
	// entry point that reads unfilled state fails here.
	calls := 0

	for _, input := range zeroValueSweepInputs(t) {
		for _, fingerprinter := range zeroValueSweepTypes {
			pointer := reflect.PointerTo(fingerprinter)

			for index := 0; index < pointer.NumMethod(); index++ {
				method := pointer.Method(index)
				name := fingerprinter.Name() + "." + method.Name

				t.Run(input.name+"/"+name, func(t *testing.T) {
					// Each subtest builds a new zero value, so the call under test is the
					// first call that the value ever receives.
					value := reflect.New(fingerprinter)
					bound := value.Method(index)
					arguments := zeroValueSweepArguments(t, bound.Type(), input)

					recovered, stack := auditRecoverPanicAt(func() {
						bound.Call(arguments)
					})

					if recovered != nil {
						t.Fatalf("%s panics on a zero value with %v, and every exported method fills the state it reads\n%s",
							name, recovered, stack)
					}
				})

				calls++
			}
		}
	}

	if calls < len(zeroValueSweepTypes)*3 {
		t.Errorf("the sweep made %d calls, and each of the %d fingerprinters exports at least ProcessPacket, Reset and CleanupConnection",
			calls, len(zeroValueSweepTypes))
	}
}

// zeroValueSweepLibraryFiles returns the path of every shipped file of the root package.
func zeroValueSweepLibraryFiles(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read .: %v", err)
	}

	paths := make([]string, 0, len(entries))

	for _, entry := range entries {
		name := entry.Name()

		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		paths = append(paths, name)
	}

	return paths
}

// zeroValueSweepReceiver matches the receiver of a method of a fingerprinter type.
var zeroValueSweepReceiver = regexp.MustCompile(`^func \([a-z]+ \*([A-Za-z0-9]+Fingerprinter)\) `)

func TestTheZeroValueSweepCoversEveryFingerprinterOfTheSource(t *testing.T) {
	// A new fingerprinter that the sweep table does not name is a fingerprinter the sweep
	// never reaches. This test reads the shipped source, so the table cannot fall behind.
	covered := make(map[string]struct{}, len(zeroValueSweepTypes))
	for _, fingerprinter := range zeroValueSweepTypes {
		covered[fingerprinter.Name()] = struct{}{}
	}

	missing := make(map[string]struct{})

	for _, path := range zeroValueSweepLibraryFiles(t) {
		for _, line := range strings.Split(panicAuditReadSource(t, path), "\n") {
			match := zeroValueSweepReceiver.FindStringSubmatch(line)
			if match == nil {
				continue
			}

			if _, held := covered[match[1]]; !held {
				missing[match[1]] = struct{}{}
			}
		}
	}

	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for name := range missing {
			names = append(names, name)
		}

		sort.Strings(names)
		t.Errorf("the sweep table names no %s, and the root package holds a method of that type",
			strings.Join(names, ", "))
	}
}
