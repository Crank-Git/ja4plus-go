package ja4plus

import "testing"

func TestIsGreaseValue(t *testing.T) {
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
		0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	for _, v := range greaseValues {
		if !IsGreaseValue(v) {
			t.Errorf("IsGreaseValue(0x%04x) = false, want true", v)
		}
	}

	nonGrease := []uint16{
		0x0000, 0x0001, 0x00ff, 0x0100, 0x0303,
		0x0304, 0x0a0b, 0x1a2a, 0xffff, 0x5600,
	}
	for _, v := range nonGrease {
		if IsGreaseValue(v) {
			t.Errorf("IsGreaseValue(0x%04x) = true, want false", v)
		}
	}
}

func TestFilterGreaseValues(t *testing.T) {
	input := []uint16{0x0a0a, 0x0035, 0x1a1a, 0x009c, 0xfafa, 0x00ff}
	want := []uint16{0x0035, 0x009c, 0x00ff}
	got := FilterGreaseValues(input)
	if len(got) != len(want) {
		t.Fatalf("FilterGreaseValues: got %d values, want %d", len(got), len(want))
	}
	for i, v := range got {
		if v != want[i] {
			t.Errorf("FilterGreaseValues[%d] = 0x%04x, want 0x%04x", i, v, want[i])
		}
	}
}
