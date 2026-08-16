package repocheck

import (
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/deviations"
	"github.com/Crank-Git/ja4plus-go/internal/repofile"
)

// readDeviationRegister returns the parsed register.
// It fails the test when the file is absent or when it does not parse.
//
// `internal/deviations` holds the reader, and this wrapper reports its error to the test.
// Package `ja4plus` holds the same wrapper. A test helper lives in a `_test.go` file, and
// no package imports another package's test files.
func readDeviationRegister(t *testing.T) []deviations.Entry {
	t.Helper()

	entries, err := deviations.Load()
	if err != nil {
		t.Fatalf("%v", err)
	}

	return entries
}

// productionGoFilesOf returns every Go file of one directory that the build compiles into
// the package. `internal/repofile` holds the walk, and this wrapper reports its error to
// the test.
func productionGoFilesOf(t *testing.T, dir string) []string {
	t.Helper()

	paths, err := repofile.ProductionGoFiles(dir)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return paths
}
