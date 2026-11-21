package ja4plus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// syncProcessorMethodNames holds the exported method set that FR-concurrency-9 through
// FR-concurrency-12 fix. A method outside this set reaches the unguarded Processor.
var syncProcessorMethodNames = []string{
	"CleanupConnection",
	// Issue #216 adds CloseConnectionWindow, which emits the open window of one connection.
	"CloseConnectionWindow",
	"CloseOpenWindows",
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

func TestSyncProcessor_ExportsOnlyTheNamedWrapperMethods(t *testing.T) {
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

// TestSyncProcessor_SerializesCloseConnectionWindowAgainstProcessPacket holds the rule of
// `.claude/rules/concurrency.md`: a new exported Processor method carries a race test.
// The method returns a result, so the mutex must cover the whole call. A result that escapes
// while another goroutine changes the fingerprinter state would race. Issue #216 adds the
// method.
func TestSyncProcessor_SerializesCloseConnectionWindowAgainstProcessPacket(t *testing.T) {
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
				for _, result := range sp.CloseConnectionWindow("192.168.1.1", uint16(40000+g),
					"10.0.0.1", uint16(443+i), "tcp") {
					// The read reaches the result outside the lock, which is the race a
					// wrapper that returns state under the lock would produce.
					_ = result.Fingerprint
				}
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

// `.claude/rules/concurrency.md` states the rule these two tests hold: a change that adds
// an exported method to Processor adds the matching method to SyncProcessor.
//
// sync_processor_test.go holds the reverse direction, because it compares the method set
// of SyncProcessor against a fixed list. That direction leaves a new Processor method
// unwrapped and reports nothing, which issue #148 records.
//
// A wrapper that forgets the mutex is worse than a missing wrapper, because the caller
// then reads a data race from a type whose name states the opposite. The second test
// therefore reads the source of each wrapper.

// A caller who shares one SyncProcessor reaches every exported Processor method through
// it. The shared pattern cannot call a method that the wrapper omits.
func TestSyncProcessorWrapsEveryExportedProcessorMethod(t *testing.T) {
	procType := reflect.TypeOf(&Processor{})
	syncType := reflect.TypeOf(&SyncProcessor{})

	if procType.NumMethod() == 0 {
		t.Fatal("Processor exports no method, so this test proves nothing")
	}

	for index := 0; index < procType.NumMethod(); index++ {
		procMethod := procType.Method(index)

		syncMethod, ok := syncType.MethodByName(procMethod.Name)
		if !ok {
			t.Errorf("Processor exports %s and SyncProcessor wraps it with no method",
				procMethod.Name)

			continue
		}

		// The receiver is parameter 0 and differs by design, so compare the rest.
		if !reflect.DeepEqual(methodShape(syncMethod), methodShape(procMethod)) {
			t.Errorf("%s signature = %v, want %v", procMethod.Name,
				methodShape(syncMethod), methodShape(procMethod))
		}
	}
}

// FR-concurrency-13 states that the mutex covers the whole call.
// The lock is the first statement, so no result escapes before the wrapper holds it.
// The unlock is deferred, so a panic in the inner call releases the mutex.
func TestEverySyncProcessorMethodTakesTheMutexFirst(t *testing.T) {
	methods := syncProcessorMethodDeclarations(t)

	if len(methods) == 0 {
		t.Fatal("sync_processor.go declares no exported method, so this test proves nothing")
	}

	for name, body := range methods {
		if len(body.List) == 0 {
			t.Errorf("%s holds an empty body and acquires no mutex", name)

			continue
		}

		if !isMutexCall(body.List[0], "Lock") {
			t.Errorf("the first statement of %s is not a mutex Lock call", name)
		}

		if !holdsDeferredUnlock(body) {
			t.Errorf("%s defers no mutex Unlock call", name)
		}
	}
}

// syncProcessorMethodDeclarations returns the body of every exported method of
// SyncProcessor, by method name.
// It reads the source, because the mutex rule states the shape of the body. Reflection
// reports no statement of a body.
// It reads every source file of the package. A wrapper that Go declares outside
// sync_processor.go takes the mutex too, and a search of one file would miss it.
func syncProcessorMethodDeclarations(t *testing.T) map[string]*ast.BlockStmt {
	t.Helper()

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list the source files: %v", err)
	}

	bodies := map[string]*ast.BlockStmt{}

	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}

		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}

		for _, decl := range parsed.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || function.Recv == nil || function.Body == nil {
				continue
			}

			if !ast.IsExported(function.Name.Name) {
				continue
			}

			if receiverTypeName(function.Recv) != "SyncProcessor" {
				continue
			}

			bodies[function.Name.Name] = function.Body
		}
	}

	return bodies
}

// receiverTypeName returns the type name of the receiver, without the pointer.
func receiverTypeName(receiver *ast.FieldList) string {
	if len(receiver.List) == 0 {
		return ""
	}

	expr := receiver.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}

	name, ok := expr.(*ast.Ident)
	if !ok {
		return ""
	}

	return name.Name
}

// isMutexCall reports whether the statement calls the named method on the mu field.
func isMutexCall(statement ast.Stmt, method string) bool {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok {
		return false
	}

	return isMutexCallExpression(expression.X, method)
}

// isMutexCallExpression reports whether the expression calls the named method on the mu
// field of the receiver.
func isMutexCallExpression(expr ast.Expr, method string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}

	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != method {
		return false
	}

	field, ok := selector.X.(*ast.SelectorExpr)

	return ok && field.Sel.Name == "mu"
}

// holdsDeferredUnlock reports whether the body defers an Unlock call on the mu field.
func holdsDeferredUnlock(body *ast.BlockStmt) bool {
	for _, statement := range body.List {
		deferred, ok := statement.(*ast.DeferStmt)
		if ok && isMutexCallExpression(deferred.Call, "Unlock") {
			return true
		}
	}

	return false
}
