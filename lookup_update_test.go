package ja4plus

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/dbcache"
)

// The tests below hold FR-lookup-23 through FR-lookup-27 of
// `docs/specs/features/09-database-lookup.md`. Issue #75 builds the update path.
//
// `lookup_reload_test.go` holds `useTemporaryCacheDir`, `writeCacheFile`,
// `reloadCacheOne`, `reloadFingerprintOne` and `reloadFingerprintTwo`.

// updateDatabaseTwo holds one fingerprint that the embedded copy does not hold.
const updateDatabaseTwo = "ja4,Application,Notes\n" +
	"t13d000000_000000000000_000000000002,Update Two,the database the update installs\n"

// TestUpdateCache_MakesALookupReadTheNewDatabaseInOneProcess holds the acceptance
// criterion that names an update and a lookup in one process.
func TestUpdateCache_MakesALookupReadTheNewDatabaseInOneProcess(t *testing.T) {
	path := useTemporaryCacheDir(t)

	writeCacheFile(t, path, reloadCacheOne, time.Now().Truncate(time.Second))

	if result := LookupFingerprint(reloadFingerprintOne); result == nil {
		t.Fatalf("LookupFingerprint(%q) = nil, want the record of the first cache file", reloadFingerprintOne)
	}

	if err := updateCache([]byte(updateDatabaseTwo)); err != nil {
		t.Fatalf("updateCache: %v", err)
	}

	result := LookupFingerprint(reloadFingerprintTwo)
	if result == nil {
		t.Fatalf("LookupFingerprint(%q) = nil, want the record of the database the update installs", reloadFingerprintTwo)
	}

	if result.Application != "Update Two" {
		t.Errorf("Application = %q, want %q", result.Application, "Update Two")
	}
}

// TestUpdateCache_LeavesThePreviousCacheFileUnchangedWhenTheDatabaseFailsValidation holds
// the acceptance criterion `A failed update leaves the previous cache file unchanged.`
func TestUpdateCache_LeavesThePreviousCacheFileUnchangedWhenTheDatabaseFailsValidation(t *testing.T) {
	path := useTemporaryCacheDir(t)

	writeCacheFile(t, path, reloadCacheOne, time.Now().Truncate(time.Second))

	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	if err := updateCache([]byte("ja4,\"Application\n")); err == nil {
		t.Fatal("updateCache accepted a file that the CSV reader rejects")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	if string(content) != reloadCacheOne {
		t.Errorf("the cache file holds %q, want the previous database %q", content, reloadCacheOne)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("the file time moved from %s to %s, and a failed update leaves the file alone",
			before.ModTime(), after.ModTime())
	}

	result := LookupFingerprint(reloadFingerprintOne)
	if result == nil {
		t.Fatalf("LookupFingerprint(%q) = nil, want the previous table after a failed update", reloadFingerprintOne)
	}
}

// TestUpdateCache_RejectsADatabaseLargerThanTheBound holds the acceptance criterion
// `A downloaded file larger than 16 MB is rejected before it reaches the cache.`
func TestUpdateCache_RejectsADatabaseLargerThanTheBound(t *testing.T) {
	path := useTemporaryCacheDir(t)

	head := "ja4,Application,Notes\nt13d000000_000000000000_000000000002,Update Two,"
	database := head + strings.Repeat("x", dbcache.MaxBytes+1-len(head)-1) + "\n"

	err := updateCache([]byte(database))
	if err == nil {
		t.Fatal("updateCache accepted a database above the bound")
	}

	if !strings.Contains(err.Error(), "16777216") {
		t.Errorf("updateCache returned %q, want an error that names the bound of 16777216 bytes", err)
	}

	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("stat %s reported %v, want no cache file after a rejected update", path, statErr)
	}
}

// TestTheLookupTable_DeclinesACacheFileLargerThanTheBound holds FR-lookup-25 on the read
// path. A cache file that another program wrote is untrusted input.
func TestTheLookupTable_DeclinesACacheFileLargerThanTheBound(t *testing.T) {
	path := useTemporaryCacheDir(t)

	writeCacheFile(t, path, reloadCacheOne, time.Now().Truncate(time.Second))

	// A truncation reports the size without a write of the whole file.
	if err := os.Truncate(path, dbcache.MaxBytes+1); err != nil {
		t.Fatalf("truncate %s: %v", path, err)
	}

	info := GetDatabaseInfo()
	if info.Source != "embedded" {
		t.Errorf("Source = %q, want embedded for a cache file above the bound", info.Source)
	}
}

// TestGetDatabaseInfo_ReportsTheSourceThePathAndTheRecordCount holds FR-lookup-27.
func TestGetDatabaseInfo_ReportsTheSourceThePathAndTheRecordCount(t *testing.T) {
	path := useTemporaryCacheDir(t)

	if err := updateCache([]byte(updateDatabaseTwo)); err != nil {
		t.Fatalf("updateCache: %v", err)
	}

	info := GetDatabaseInfo()

	if info.Source != "cache" {
		t.Errorf("Source = %q, want cache", info.Source)
	}

	if info.Path != path {
		t.Errorf("Path = %q, want %q", info.Path, path)
	}

	if info.Entries != 1 {
		t.Errorf("Entries = %d, want 1 for a database that holds one fingerprint", info.Entries)
	}

	if info.ModTime.IsZero() {
		t.Error("ModTime is the zero time, and the cache file carries a file time")
	}
}
