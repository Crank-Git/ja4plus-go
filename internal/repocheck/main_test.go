// Package repocheck holds the tests that read this repository rather than this
// library. Each one opens a tracked file and states a fact about it. None of
// them references a symbol of package `ja4plus`.
package repocheck

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain moves the working directory to the repository root before any test
// runs. Every path in this package is written relative to that root.
func TestMain(m *testing.M) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		panic("repocheck: cannot resolve the repository root: " + err.Error())
	}
	if err := os.Chdir(root); err != nil {
		panic("repocheck: cannot enter the repository root: " + err.Error())
	}
	os.Exit(m.Run())
}
