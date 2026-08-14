package ja4plus

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The tests below hold FR-lookup-18 through FR-lookup-22 of
// `docs/specs/features/09-database-lookup.md`. Issue #74 builds the reload.

// A cache file that holds one fingerprint the embedded copy does not hold.
const reloadCacheOne = "ja4,Application,Notes\n" +
	"t13d000000_000000000000_000000000001,Reload One,the first cache file\n"

// A second cache file that holds a different fingerprint.
const reloadCacheTwo = "ja4,Application,Notes\n" +
	"t13d000000_000000000000_000000000002,Reload Two,the second cache file\n"

// A cache file that the CSV reader rejects at the header.
const reloadCacheCorrupt = "ja4,\"Application\n"

const reloadFingerprintOne = "t13d000000_000000000000_000000000001"

const reloadFingerprintTwo = "t13d000000_000000000000_000000000002"

// useTemporaryCacheDir points the user cache directory at a temporary directory and
// returns the cache path. The library holds one table for the whole process, so the
// helper discards that table before the test and after it.
func useTemporaryCacheDir(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))

	// macOS resolves the user cache directory under $HOME/Library/Caches, and
	// os.UserCacheDir fails when that directory is absent.
	if err := os.MkdirAll(filepath.Join(home, "Library", "Caches"), 0o755); err != nil {
		t.Fatalf("create the macOS cache directory: %v", err)
	}

	invalidateLookupTable()
	t.Cleanup(invalidateLookupTable)

	path, err := CachedDatabasePath()
	if err != nil {
		t.Fatalf("CachedDatabasePath: %v", err)
	}

	return path
}

// replaceCacheFile installs the content at the cache path and sets the file time. The
// library reads the file time, so a test that controls it controls the reload.
// A goroutine other than the test goroutine calls this function, so it reports an error
// rather than a fatal result.
func replaceCacheFile(path, content string, modTime time.Time) error {
	temporary := path + ".test-tmp"
	if err := os.WriteFile(temporary, []byte(content), 0o600); err != nil {
		return err
	}

	// The rename is atomic, so a reader never sees a partial file.
	if err := os.Rename(temporary, path); err != nil {
		return err
	}

	return os.Chtimes(path, modTime, modTime)
}

// writeCacheFile installs the content at the cache path from the test goroutine.
func writeCacheFile(t *testing.T, path, content string, modTime time.Time) {
	t.Helper()

	if err := replaceCacheFile(path, content, modTime); err != nil {
		t.Fatalf("install the cache file at %s: %v", path, err)
	}
}

// TestTheLookupTable_ReloadsWhenTheCacheFileChanges holds FR-lookup-18. It holds the
// acceptance criterion that names an update and a lookup in one process.
func TestTheLookupTable_ReloadsWhenTheCacheFileChanges(t *testing.T) {
	path := useTemporaryCacheDir(t)
	base := time.Now().Truncate(time.Second)

	writeCacheFile(t, path, reloadCacheOne, base.Add(-2*time.Second))

	if result := LookupFingerprint(reloadFingerprintOne); result == nil {
		t.Fatalf("LookupFingerprint(%q) = nil, want the record of the first cache file", reloadFingerprintOne)
	}

	writeCacheFile(t, path, reloadCacheTwo, base)

	result := LookupFingerprint(reloadFingerprintTwo)
	if result == nil {
		t.Fatalf("LookupFingerprint(%q) = nil, want the record of the second cache file", reloadFingerprintTwo)
	}

	if result.Application != "Reload Two" {
		t.Errorf("Application = %q, want %q", result.Application, "Reload Two")
	}

	if stale := LookupFingerprint(reloadFingerprintOne); stale != nil {
		t.Errorf("LookupFingerprint(%q) = %+v, want nil after the reload", reloadFingerprintOne, stale)
	}
}

// TestTheLookupTable_KeepsThePreviousTableWhenAReloadFails holds FR-lookup-22.
func TestTheLookupTable_KeepsThePreviousTableWhenAReloadFails(t *testing.T) {
	path := useTemporaryCacheDir(t)
	base := time.Now().Truncate(time.Second)

	writeCacheFile(t, path, reloadCacheOne, base.Add(-2*time.Second))

	if result := LookupFingerprint(reloadFingerprintOne); result == nil {
		t.Fatalf("LookupFingerprint(%q) = nil, want the record of the first cache file", reloadFingerprintOne)
	}

	writeCacheFile(t, path, reloadCacheCorrupt, base)

	result := LookupFingerprint(reloadFingerprintOne)
	if result == nil {
		t.Fatalf("LookupFingerprint(%q) = nil, want the previous table after a failed reload", reloadFingerprintOne)
	}

	if result.Application != "Reload One" {
		t.Errorf("Application = %q, want %q", result.Application, "Reload One")
	}

	info := GetDatabaseInfo()
	if info.Source != "cache" {
		t.Errorf("Source = %q, want cache after a failed reload", info.Source)
	}

	if info.Path != path {
		t.Errorf("Path = %q, want %q", info.Path, path)
	}
}

// TestTheLookupTable_FallsBackToTheEmbeddedCopyWhenTheCacheIsCorrupt holds the
// acceptance criterion that names a corrupt cache file. The library holds no previous
// table here, so the embedded copy is the last resort.
func TestTheLookupTable_FallsBackToTheEmbeddedCopyWhenTheCacheIsCorrupt(t *testing.T) {
	path := useTemporaryCacheDir(t)

	writeCacheFile(t, path, reloadCacheCorrupt, time.Now().Truncate(time.Second))

	info := GetDatabaseInfo()
	if info.Source != "embedded" {
		t.Errorf("Source = %q, want embedded", info.Source)
	}

	if info.Entries == 0 {
		t.Error("Entries = 0, want the record count of the embedded copy")
	}

	if info.Path != "" {
		t.Errorf("Path = %q, want the empty string for the embedded copy", info.Path)
	}
}

// TestTheLookupTable_ReportsNoRaceWhenAnUpdateRunsBesideALookup holds FR-lookup-20 and
// FR-lookup-21. It reports a race only under `go test -race`.
func TestTheLookupTable_ReportsNoRaceWhenAnUpdateRunsBesideALookup(t *testing.T) {
	path := useTemporaryCacheDir(t)
	base := time.Now().Truncate(time.Second)

	writeCacheFile(t, path, reloadCacheOne, base)

	const readers = 8

	const rounds = 40

	var group sync.WaitGroup

	sources := make([]string, readers)

	for index := 0; index < readers; index++ {
		group.Add(1)

		go func(slot int) {
			defer group.Done()

			for round := 0; round < rounds; round++ {
				_ = LookupFingerprint(reloadFingerprintOne)
				_ = LookupFingerprint(reloadFingerprintTwo)
				sources[slot] = GetDatabaseInfo().Source
			}
		}(index)
	}

	group.Add(1)

	var updateErr error

	go func() {
		defer group.Done()

		for round := 0; round < rounds; round++ {
			content := reloadCacheOne
			if round%2 == 1 {
				content = reloadCacheTwo
			}

			if err := replaceCacheFile(path, content, base.Add(time.Duration(round)*time.Second)); err != nil {
				updateErr = err
				return
			}
		}
	}()

	group.Wait()

	if updateErr != nil {
		t.Fatalf("install the cache file at %s: %v", path, updateErr)
	}

	for _, source := range sources {
		if source != "embedded" && source != "cache" {
			t.Errorf("GetDatabaseInfo reported the source %q, want embedded or cache", source)
		}
	}
}

// BenchmarkLookupFingerprint measures the read path. The reload check adds one os.Stat
// call to each lookup, and this benchmark reports what that call costs.
func BenchmarkLookupFingerprint(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = LookupFingerprint("t13d1516h2_8daaf6152771_02713d6af862")
	}
}

// TestTheLookupSource_HoldsNoSyncOnce holds FR-lookup-19. The reload needs a mechanism
// that runs more than once, and `sync.Once` runs exactly once.
func TestTheLookupSource_HoldsNoSyncOnce(t *testing.T) {
	source := readRepoFile(t, "lookup.go")

	if strings.Contains(source, "sync.Once") {
		t.Error("lookup.go holds sync.Once, and FR-lookup-19 replaces it with a mechanism that supports a reload")
	}

	if !strings.Contains(source, "atomic.Pointer[lookupTable]") {
		t.Error("lookup.go holds no atomic.Pointer[lookupTable], and the reload publishes the table through one")
	}
}
