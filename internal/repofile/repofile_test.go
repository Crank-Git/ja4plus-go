package repofile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadReturnsTheTextOfAFile holds the reader that every repository test calls.
func TestReadReturnsTheTextOfAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "page.md")
	if err := os.WriteFile(path, []byte("one line\n"), 0o600); err != nil {
		t.Fatalf("write the fixture: %v", err)
	}

	text, err := Read(path)
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}

	if text != "one line\n" {
		t.Errorf("Read returns %q, and the file holds %q", text, "one line\n")
	}
}

// TestReadReportsAnAbsentFile holds the error path. A test that reads a path the tree no
// longer holds must fail with the path in the message.
func TestReadReportsAnAbsentFile(t *testing.T) {
	_, err := Read(filepath.Join(t.TempDir(), "absent.md"))
	if err == nil {
		t.Fatal("Read returns no error for an absent file")
	}

	if !strings.Contains(err.Error(), "absent.md") {
		t.Errorf("the error is %q, and it names no path", err)
	}
}

// TestProductionGoFilesSkipsATestFileAndASubdirectory holds the walk that the package
// documentation guard reads. A test file and a subdirectory are not the compiled surface.
func TestProductionGoFilesSkipsATestFileAndASubdirectory(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{"beta.go", "alpha.go", "alpha_test.go", "notes.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("package p\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o750); err != nil {
		t.Fatalf("create the subdirectory: %v", err)
	}

	paths, err := ProductionGoFiles(dir)
	if err != nil {
		t.Fatalf("walk the fixture: %v", err)
	}

	want := []string{filepath.Join(dir, "alpha.go"), filepath.Join(dir, "beta.go")}
	if len(paths) != len(want) {
		t.Fatalf("the walk returns %v, and the directory holds two production files", paths)
	}

	// The walk sorts, so a caller reads one order on every run.
	for index, path := range paths {
		if path != want[index] {
			t.Errorf("the walk returns %q at %d, and the sorted order names %q", path, index, want[index])
		}
	}
}

// TestProductionGoFilesReportsAnAbsentDirectory holds the error path.
func TestProductionGoFilesReportsAnAbsentDirectory(t *testing.T) {
	if _, err := ProductionGoFiles(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("the walk returns no error for an absent directory")
	}
}

// TestIsExcludedDocumentationDirReadsTheList binds the predicate to the list beside it.
func TestIsExcludedDocumentationDirReadsTheList(t *testing.T) {
	for _, excluded := range ExcludedDocumentationDirs {
		if !IsExcludedDocumentationDir(excluded) {
			t.Errorf("the list names %s, and the predicate reports that the site publishes it", excluded)
		}
	}

	if IsExcludedDocumentationDir("reference") {
		t.Error("the predicate excludes `reference`, and the site publishes that directory")
	}
}
