package ja4plus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

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
