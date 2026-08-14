package dbcache_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/dbcache"
)

// The tests below hold FR-lookup-23 through FR-lookup-26 of
// `docs/specs/features/09-database-lookup.md`. Issue #75 builds the validation and the
// atomic write.

// databaseOne holds one fingerprint, and it carries one column of each family.
const databaseOne = "ja4,Application,Notes\n" +
	"t13d000000_000000000000_000000000001,Update One,the first database\n"

// databaseTwo holds a second fingerprint.
const databaseTwo = "ja4,Application,Notes\n" +
	"t13d000000_000000000000_000000000002,Update Two,the second database\n"

// cacheFileName names the file that the tests install.
const cacheFileName = "ja4plus-mapping.csv"

// oversizeDatabase returns a database that holds one byte more than the bound.
// The header and the record keep the content valid, so the size is the one reason the
// validation rejects it.
func oversizeDatabase() []byte {
	head := "ja4,Application,Notes\nt13d000000_000000000000_000000000001,Update One,"
	notes := strings.Repeat("x", dbcache.MaxBytes+1-len(head)-1)

	return []byte(head + notes + "\n")
}

func TestValidate_RejectsADatabaseLargerThanTheBound(t *testing.T) {
	err := dbcache.Validate(oversizeDatabase())
	if err == nil {
		t.Fatal("Validate accepted a database above the bound, and FR-lookup-25 rejects it")
	}

	if !strings.Contains(err.Error(), "16777216") {
		t.Errorf("Validate returned %q, want an error that names the bound of 16777216 bytes", err)
	}
}

func TestValidate_AcceptsADatabaseOfExactlyTheBound(t *testing.T) {
	database := oversizeDatabase()[:dbcache.MaxBytes]

	if err := dbcache.Validate(database); err != nil {
		t.Errorf("Validate(%d bytes) = %v, want no error at the bound", len(database), err)
	}
}

func TestValidate_RejectsAFileThatHoldsNoFingerprintColumn(t *testing.T) {
	if err := dbcache.Validate([]byte("Application,Notes\nUpdate One,no fingerprint\n")); err == nil {
		t.Error("Validate accepted a file that holds no fingerprint column")
	}
}

func TestValidate_RejectsAFileThatHoldsNoIdentityColumn(t *testing.T) {
	if err := dbcache.Validate([]byte("ja4,Notes\nt13d000000_000000000000_000000000001,no identity\n")); err == nil {
		t.Error("Validate accepted a file that holds no identity column")
	}
}

func TestValidate_RejectsAFileThatHoldsNoRecord(t *testing.T) {
	if err := dbcache.Validate([]byte("ja4,Application,Notes\n")); err == nil {
		t.Error("Validate accepted a file that holds a header row and no record")
	}
}

func TestValidate_RejectsAFileThatTheCSVReaderRejects(t *testing.T) {
	if err := dbcache.Validate([]byte("ja4,\"Application\n")); err == nil {
		t.Error("Validate accepted a file that the CSV reader rejects at the header row")
	}
}

// TestValidate_RejectsAFileWhoseFingerprintRecordsCarryNoIdentity holds FR-lookup-23.
// `parseMapping` in `lookup.go` skips a record that carries no identity value, so such a
// file parses and yields no entry. A write of it reports a success and leaves the library
// on the previous database.
func TestValidate_RejectsAFileWhoseFingerprintRecordsCarryNoIdentity(t *testing.T) {
	database := "Application,ja4,Notes\n,t13d000000_000000000000_000000000099,no identity\n"

	if err := dbcache.Validate([]byte(database)); err == nil {
		t.Error("Validate accepted a file whose one fingerprint record carries no identity value")
	}
}

func TestValidate_RejectsAnEmptyFile(t *testing.T) {
	if err := dbcache.Validate(nil); err == nil {
		t.Error("Validate accepted an empty file")
	}
}

func TestValidate_AcceptsTheEmbeddedMapping(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "data", "ja4plus-mapping.csv"))
	if err != nil {
		t.Fatalf("read the embedded mapping: %v", err)
	}

	if err := dbcache.Validate(data); err != nil {
		t.Errorf("Validate(the embedded mapping) = %v, want no error", err)
	}
}

func TestWrite_InstallsTheDatabaseAtThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), cacheFileName)

	if err := dbcache.Write(path, []byte(databaseOne)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	if string(content) != databaseOne {
		t.Errorf("the cache file holds %q, want %q", content, databaseOne)
	}
}

// TestWrite_LeavesThePreviousCacheFileUnchangedWhenValidationFails holds the acceptance
// criterion `A failed update leaves the previous cache file unchanged.`
func TestWrite_LeavesThePreviousCacheFileUnchangedWhenValidationFails(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, cacheFileName)

	if err := dbcache.Write(path, []byte(databaseOne)); err != nil {
		t.Fatalf("install the first database: %v", err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	if err := dbcache.Write(path, oversizeDatabase()); err == nil {
		t.Fatal("Write accepted a database above the bound, and the cache file is now the new one")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	if string(content) != databaseOne {
		t.Errorf("the cache file holds %q, want the previous database %q", content, databaseOne)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("the file time moved from %s to %s, and a failed write leaves the file alone",
			before.ModTime(), after.ModTime())
	}

	assertDirectoryHoldsOnly(t, directory, cacheFileName)
}

// TestWrite_LeavesNoTemporaryFileWhenTheDatabaseFailsValidation reads the directory,
// because a temporary file that survives a failure fills the cache directory.
func TestWrite_LeavesNoTemporaryFileWhenTheDatabaseFailsValidation(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, cacheFileName)

	if err := dbcache.Write(path, []byte("ja4,\"Application\n")); err == nil {
		t.Fatal("Write accepted a file that the CSV reader rejects")
	}

	assertDirectoryHoldsOnly(t, directory)
}

// TestWrite_LeavesNoTemporaryFileWhenTheInstallSucceeds holds the same property for the
// successful path.
func TestWrite_LeavesNoTemporaryFileWhenTheInstallSucceeds(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, cacheFileName)

	if err := dbcache.Write(path, []byte(databaseTwo)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	assertDirectoryHoldsOnly(t, directory, cacheFileName)
}

// TestWrite_NamesTheDirectoryWhenItCannotWriteThere holds the edge case
// `The cache directory is not writable.`
func TestWrite_NamesTheDirectoryWhenItCannotWriteThere(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the root account writes a directory of mode 0500, so the case does not arise")
	}

	directory := t.TempDir()
	path := filepath.Join(directory, cacheFileName)

	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatalf("set the mode of %s: %v", directory, err)
	}

	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })

	err := dbcache.Write(path, []byte(databaseOne))
	if err == nil {
		t.Fatal("Write reported no error for a directory it cannot write")
	}

	if !strings.Contains(err.Error(), directory) {
		t.Errorf("Write returned %q, want an error that names %s", err, directory)
	}

	// A rename across two filesystems is not atomic, so the temporary file sits in the
	// directory of the target. The failure of the create call proves that directory.
	if !strings.Contains(err.Error(), "create a temporary file in") {
		t.Errorf("Write returned %q, want the failure of the create call in the target directory", err)
	}
}

// assertDirectoryHoldsOnly reports every entry of the directory that the want list does
// not name.
func assertDirectoryHoldsOnly(t *testing.T, directory string, want ...string) {
	t.Helper()

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read %s: %v", directory, err)
	}

	expected := map[string]bool{}
	for _, name := range want {
		expected[name] = true
	}

	for _, entry := range entries {
		if !expected[entry.Name()] {
			t.Errorf("%s holds %s, and a write leaves no other file", directory, entry.Name())
		}
	}

	if len(entries) != len(want) {
		t.Errorf("%s holds %d entries, want %d", directory, len(entries), len(want))
	}
}
