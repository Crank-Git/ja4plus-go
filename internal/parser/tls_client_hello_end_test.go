package parser

import "testing"

// The cases below port `TestClientHelloEnd` of `tests/test_ja4_tcp_client_hello_reassembly.py`
// of the port at tag `v1.3.0`. Crank-Git/ja4plus#772 records the defect, and
// Crank-Git/ja4plus#784 holds the repair.

// clientHelloEndHello returns one ClientHello record of 2000 bytes or more, so a cut at
// 1400 bytes leaves the hello incomplete.
func clientHelloEndHello() []byte {
	return BuildClientHello(0x0303, []uint16{0x1301, 0x1302}, []TLSExtension{
		MakeSNIExtension("example.com"),
		{Typ: 0x0015, Data: make([]byte, 1900)},
	})
}

func TestClientHelloEndNamesTheEndOfTheHelloInTheFirstSegment(t *testing.T) {
	hello := clientHelloEndHello()

	end, held := ClientHelloEnd(hello[:1400])
	if !held || end != len(hello) {
		t.Errorf("ClientHelloEnd = (%d, %t), want (%d, true)", end, held, len(hello))
	}
}

func TestClientHelloEndNamesTheEndOfAWholeHello(t *testing.T) {
	hello := clientHelloEndHello()

	end, held := ClientHelloEnd(hello)
	if !held || end != len(hello) {
		t.Errorf("ClientHelloEnd = (%d, %t), want (%d, true)", end, held, len(hello))
	}
}

// Seven bytes hold the record header and two of the four handshake header bytes. The
// header states the length, so the least end is the end of that header.
func TestClientHelloEndNamesTheLeastEndThatACutHandshakeHeaderAllows(t *testing.T) {
	end, held := ClientHelloEnd(clientHelloEndHello()[:7])
	if !held || end != 9 {
		t.Errorf("ClientHelloEnd = (%d, %t), want (9, true)", end, held)
	}
}

func TestClientHelloEndNamesTheEndOfARecordHeaderAlone(t *testing.T) {
	end, held := ClientHelloEnd(clientHelloEndHello()[:5])
	if !held || end != 9 {
		t.Errorf("ClientHelloEnd = (%d, %t), want (9, true)", end, held)
	}
}

func TestClientHelloEndCountsAChangeCipherSpecRecordBeforeTheHello(t *testing.T) {
	hello := clientHelloEndHello()
	changeCipherSpec := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	data := append(append([]byte{}, changeCipherSpec...), hello[:1400]...)

	end, held := ClientHelloEnd(data)
	if !held || end != len(changeCipherSpec)+len(hello) {
		t.Errorf("ClientHelloEnd = (%d, %t), want (%d, true)", end, held, len(changeCipherSpec)+len(hello))
	}
}

func TestClientHelloEndNamesNoEndForBytesThatOpenNoClientHello(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"no byte", []byte{}},
		{"a record header that the bytes cut", []byte{0x16, 0x03, 0x01, 0x07}},
		{"an HTTP request line", []byte("GET / HTTP/1.1\r\n")},
		{"a record version byte that is not 3", []byte{0x16, 0x02, 0x01, 0x07, 0xf2, 0x01, 0x00, 0x07, 0xee}},
		{"a ServerHello", []byte{0x16, 0x03, 0x03, 0x04, 0xba, 0x02, 0x00, 0x04, 0xb6}},
		{"a ChangeCipherSpec record that the bytes cut", []byte{0x14, 0x03, 0x03, 0x00, 0x01}},
		{"an application data record", append([]byte{0x17, 0x03, 0x03, 0x00, 0x20}, make([]byte, 32)...)},
		{"a record type that TLS does not define", []byte{0x18, 0x03, 0x03, 0x00, 0x01, 0x01}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if end, held := ClientHelloEnd(testCase.data); held {
				t.Errorf("ClientHelloEnd = (%d, true), want no end", end)
			}
		})
	}
}

// A record length field of 0xffff passes the end of the bytes. The walk steps past it and
// reads no byte outside the slice.
func TestClientHelloEndReadsNoByteBeyondARecordLengthThatPassesTheBytes(t *testing.T) {
	data := []byte{0x14, 0x03, 0x03, 0xff, 0xff, 0x01}

	if end, held := ClientHelloEnd(data); held {
		t.Errorf("ClientHelloEnd = (%d, true), want no end", end)
	}
}
