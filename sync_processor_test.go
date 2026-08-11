package ja4plus

import (
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// syncProcessorMethodNames holds the exported method set that FR-concurrency-9 through
// FR-concurrency-12 fix. A method outside this set reaches the unguarded Processor.
var syncProcessorMethodNames = []string{
	"CleanupConnection",
	"GetShardKey",
	"ProcessPacket",
	"Reset",
}

func TestNewSyncProcessor_ReturnsAUsableProcessor(t *testing.T) {
	sp := NewSyncProcessor()
	if sp == nil {
		t.Fatal("NewSyncProcessor returned nil")
	}

	pkt := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)
	results, errs := sp.ProcessPacket(pkt)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}

	found := false
	for _, r := range results {
		if r.Type == "ja4t" {
			found = true
		}
	}
	if !found {
		t.Error("expected JA4T result from SYN packet")
	}
}

func TestSyncProcessor_ExportsOnlyTheFourWrapperMethods(t *testing.T) {
	spType := reflect.TypeOf(&SyncProcessor{})

	var got []string
	for i := 0; i < spType.NumMethod(); i++ {
		got = append(got, spType.Method(i).Name)
	}

	if !reflect.DeepEqual(got, syncProcessorMethodNames) {
		t.Errorf("exported methods = %v, want %v", got, syncProcessorMethodNames)
	}
}

func TestSyncProcessor_MatchesTheProcessorSignatures(t *testing.T) {
	spType := reflect.TypeOf(&SyncProcessor{})
	procType := reflect.TypeOf(&Processor{})

	for _, name := range syncProcessorMethodNames {
		spMethod, ok := spType.MethodByName(name)
		if !ok {
			t.Fatalf("SyncProcessor has no method %s", name)
		}
		procMethod, ok := procType.MethodByName(name)
		if !ok {
			t.Fatalf("Processor has no method %s", name)
		}
		// The receiver is parameter 0 and differs by design, so compare the rest.
		if !reflect.DeepEqual(methodShape(spMethod), methodShape(procMethod)) {
			t.Errorf("%s signature = %v, want %v", name,
				methodShape(spMethod), methodShape(procMethod))
		}
	}
}

// methodShape returns the parameter types and the result types of the method, without
// the receiver. Two methods with an equal shape have an equal signature.
func methodShape(m reflect.Method) []reflect.Type {
	var shape []reflect.Type
	for i := 1; i < m.Type.NumIn(); i++ {
		shape = append(shape, m.Type.In(i))
	}
	for i := 0; i < m.Type.NumOut(); i++ {
		shape = append(shape, m.Type.Out(i))
	}
	return shape
}

func TestSyncProcessor_HoldsNoExportedField(t *testing.T) {
	spType := reflect.TypeOf(SyncProcessor{})
	for i := 0; i < spType.NumField(); i++ {
		if spType.Field(i).IsExported() {
			t.Errorf("field %s is exported; a caller must not reach the inner Processor",
				spType.Field(i).Name)
		}
	}
}

func TestSyncProcessor_HoldsOneMutex(t *testing.T) {
	spType := reflect.TypeOf(SyncProcessor{})

	count := 0
	for i := 0; i < spType.NumField(); i++ {
		if spType.Field(i).Type == reflect.TypeOf(sync.Mutex{}) {
			count++
		}
	}
	if count != 1 {
		t.Errorf("sync.Mutex field count = %d, want 1", count)
	}
}

func TestSyncProcessor_DocumentsTheContract(t *testing.T) {
	source, err := os.ReadFile("sync_processor.go")
	if err != nil {
		t.Fatalf("read sync_processor.go: %v", err)
	}

	doc, _, ok := strings.Cut(string(source), "type SyncProcessor struct")
	if !ok {
		t.Fatal("sync_processor.go declares no SyncProcessor type")
	}

	for _, want := range []string{"serializes every call", "throughput"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the SyncProcessor doc comment omits %q", want)
		}
	}
}

func TestSyncProcessor_ProcessesPacketsFromEightGoroutines(t *testing.T) {
	const goroutines = 8
	const packets = 50

	sp := NewSyncProcessor()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < packets; i++ {
				pkt := buildSYNPacket("192.168.1.1", "10.0.0.1",
					uint16(40000+g), uint16(443+i))
				if _, errs := sp.ProcessPacket(pkt); len(errs) > 0 {
					t.Errorf("unexpected errors: %v", errs)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestSyncProcessor_SerializesResetAgainstProcessPacket(t *testing.T) {
	const goroutines = 8
	const packets = 50

	sp := NewSyncProcessor()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < packets; i++ {
				pkt := buildSYNPacket("192.168.1.1", "10.0.0.1",
					uint16(40000+g), uint16(443+i))
				_, _ = sp.ProcessPacket(pkt)
			}
		}(g)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < packets; i++ {
			sp.Reset()
		}
	}()

	wg.Wait()
}

func TestSyncProcessor_SerializesCleanupConnectionAgainstProcessPacket(t *testing.T) {
	const goroutines = 8
	const packets = 50

	sp := NewSyncProcessor()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < packets; i++ {
				pkt := buildSYNPacket("192.168.1.1", "10.0.0.1",
					uint16(40000+g), uint16(443+i))
				_, _ = sp.ProcessPacket(pkt)
			}
		}(g)
	}

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < packets; i++ {
				sp.CleanupConnection("192.168.1.1", uint16(40000+g),
					"10.0.0.1", uint16(443+i), "tcp")
			}
		}(g)
	}

	wg.Wait()
}

func TestSyncProcessor_ReturnsOneShardKeyForAPacketAndItsReply(t *testing.T) {
	sp := NewSyncProcessor()

	request := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)
	reply := buildSYNPacket("10.0.0.1", "192.168.1.1", 443, 54321)

	got := sp.GetShardKey(request)
	if got == "" {
		t.Fatal("GetShardKey returned an empty key for a TCP packet")
	}
	if want := sp.GetShardKey(reply); got != want {
		t.Errorf("GetShardKey(request) = %q, GetShardKey(reply) = %q", got, want)
	}
}

func TestSyncProcessor_ReturnsTheSameShardKeyAsProcessor(t *testing.T) {
	sp := NewSyncProcessor()
	proc := NewProcessor()

	pkt := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)

	if got, want := sp.GetShardKey(pkt), proc.GetShardKey(pkt); got != want {
		t.Errorf("SyncProcessor.GetShardKey = %q, Processor.GetShardKey = %q", got, want)
	}
}

func TestSyncProcessor_ReadsShardKeysFromEightGoroutines(t *testing.T) {
	const goroutines = 8
	const packets = 50

	sp := NewSyncProcessor()
	want := sp.GetShardKey(buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443))

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < packets; i++ {
				pkt := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)
				if got := sp.GetShardKey(pkt); got != want {
					t.Errorf("GetShardKey = %q, want %q", got, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}
