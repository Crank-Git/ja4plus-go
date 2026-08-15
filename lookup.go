package ja4plus

import (
	_ "embed"
	"encoding/csv"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/dbcache"
)

//go:embed data/ja4plus-mapping.csv
var mappingCSV []byte

// LookupResult holds the result of a fingerprint database lookup.
type LookupResult struct {
	// Application names the program that produces the fingerprint.
	Application string
	// Type names the class of the program.
	Type string
	// Notes holds the free text of the record.
	Notes string
}

// cacheStamp identifies one state of the cache file. The library rebuilds the table
// when the stamp of the file differs from the stamp the loaded table carries.
//
// A stamp holds the file time and the size, so it separates no two files that carry both.
// A writer inside this package calls invalidateLookupTable, which reaches that case.
type cacheStamp struct {
	exists  bool
	modTime time.Time
	size    int64
}

// same reports whether two stamps describe one state of the cache file.
// time.Time carries a location pointer, so a field comparison is safer than ==.
func (s cacheStamp) same(other cacheStamp) bool {
	if s.exists != other.exists {
		return false
	}

	if !s.exists {
		return true
	}

	return s.size == other.size && s.modTime.Equal(other.modTime)
}

// lookupTable holds one snapshot of the fingerprint table. No field changes after the
// build, so a reader that loads the pointer needs no lock.
type lookupTable struct {
	// entries maps a fingerprint to its record.
	entries map[string]*LookupResult
	// source is "embedded" or "cache".
	source string
	// path is the cache path when source is "cache", and the empty string otherwise.
	path string
	// modTime is the file time of the cache file that produced this table. A table that
	// declines a later cache file keeps the file time of the file it reads.
	modTime time.Time
	// cachePath is the resolved cache path, whichever source the table reads.
	// activeTable reads it, so a lookup never calls CachedDatabasePath again.
	cachePath string
	// stamp is the state of the cache file that this table answers for. A table that
	// declines a corrupt cache file still carries the stamp of that file, so the
	// library rebuilds once for each state of the file.
	stamp cacheStamp
}

// loadedTable publishes the active table. A reader loads the pointer, so the read path
// takes no lock and `.claude/rules/concurrency.md` `## The contract` holds.
var loadedTable atomic.Pointer[lookupTable]

// buildMutex serializes a build. A reader never takes it, and it stops two goroutines
// from parsing the same file at the same time.
var buildMutex sync.Mutex

// errEmptyTable reports a source that parses and holds no fingerprint. The library
// declines such a source, because it answers every lookup with nil.
var errEmptyTable = errors.New("the mapping source holds no fingerprint")

// invalidateLookupTable discards the loaded table, so the next lookup builds a new one.
// A caller that writes the cache file calls it to publish the new file at once.
func invalidateLookupTable() {
	loadedTable.Store(nil)
}

// updateCache validates the database and replaces the cache file with it.
//
// It publishes the new table at once, so a lookup of this process reads the new database
// without a stat of the cache file.
//
// It returns an error and leaves the previous cache file unchanged when the database fails
// validation, and when the write fails. `internal/dbcache` states each rule.
//
// No package outside this one reaches this function, because #100 freezes the exported
// surface. `ja4plus db update` runs in another process, and it writes the cache file
// through `internal/dbcache`. A running process then reads the new file at its next
// lookup, because `activeTable` stats the cache file.
func updateCache(data []byte) error {
	path, err := CachedDatabasePath()
	if err != nil {
		return err
	}

	if err := dbcache.Write(path, data); err != nil {
		return err
	}

	invalidateLookupTable()

	return nil
}

// statCache returns the state of the cache file. It reports no error, because an
// unreadable file and an absent file reach the same result: the embedded copy.
func statCache(path string) cacheStamp {
	if path == "" {
		return cacheStamp{}
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return cacheStamp{}
	}

	return cacheStamp{exists: true, modTime: info.ModTime(), size: info.Size()}
}

// parseMapping returns the fingerprint table that the CSV content holds.
// It returns an error when the content holds no header row and when it holds no
// fingerprint. A caller that receives an error keeps the table it already has.
func parseMapping(data []byte) (map[string]*LookupResult, error) {
	r := csv.NewReader(strings.NewReader(string(data)))

	header, err := r.Read()
	if err != nil {
		return nil, err
	}

	// Build column index
	colIdx := make(map[string]int)
	for i, h := range header {
		colIdx[strings.TrimSpace(h)] = i
	}

	// The validation of a downloaded database reads the same two column sets, so one
	// package states each one. FR-lookup-24 names the expected columns.
	fpTypes := dbcache.FingerprintColumns()

	identity := dbcache.IdentityColumns()

	entries := make(map[string]*LookupResult)

	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// Build identification string from available fields
		var identParts []string
		for _, field := range identity {
			idx, ok := colIdx[field]
			if !ok || idx >= len(row) {
				continue
			}
			val := strings.TrimSpace(row[idx])
			if val != "" {
				identParts = append(identParts, val)
			}
		}
		if len(identParts) == 0 {
			continue
		}

		ident := strings.Join(identParts, " / ")
		notes := ""
		if idx, ok := colIdx["Notes"]; ok && idx < len(row) {
			notes = strings.TrimSpace(row[idx])
		}

		// Index by each fingerprint type present
		for _, fpType := range fpTypes {
			idx, ok := colIdx[fpType]
			if !ok || idx >= len(row) {
				continue
			}
			fpVal := strings.TrimSpace(row[idx])
			if fpVal != "" {
				entries[fpVal] = &LookupResult{
					Application: ident,
					Type:        fpType,
					Notes:       notes,
				}
			}
		}
	}

	if len(entries) == 0 {
		return nil, errEmptyTable
	}

	return entries, nil
}

// loadDB returns the active table. It rebuilds the table when the cache file changed
// since the last build, so a database update takes effect in the same process.
func loadDB() map[string]*LookupResult {
	return activeTable().entries
}

// rebuildTable builds a new table and publishes it. It returns the previous table when
// the cache file fails to parse, so FR-lookup-22 holds.
//
// A cache file that the program deleted is not a failed parse. The library then reads the
// embedded copy, because the embedded copy is the last resort of this package.
func rebuildTable() *lookupTable {
	buildMutex.Lock()
	defer buildMutex.Unlock()

	// Another goroutine can publish a fresh table while this one waits for the mutex.
	if current := loadedTable.Load(); current != nil && statCache(current.cachePath).same(current.stamp) {
		return current
	}

	previous := loadedTable.Load()

	cachePath, err := CachedDatabasePath()
	if err != nil {
		// The path is deterministic, and CachedDatabasePath fails on the directory it
		// creates. A previous table therefore names the file this build still reads.
		cachePath = ""
		if previous != nil {
			cachePath = previous.cachePath
		}
	}

	stamp := statCache(cachePath)

	if stamp.exists {
		// Another program writes the cache file, so the file is untrusted input. The bound
		// of FR-lookup-25 therefore holds for a read as well as for a write.
		if stamp.size <= dbcache.MaxBytes {
			if data, rerr := os.ReadFile(cachePath); rerr == nil && len(data) > 0 {
				if entries, perr := parseMapping(data); perr == nil {
					return publish(&lookupTable{
						entries:   entries,
						source:    "cache",
						path:      cachePath,
						modTime:   stamp.modTime,
						cachePath: cachePath,
						stamp:     stamp,
					})
				}
			}
		}

		// The cache file failed. A previous table answers every lookup it answered
		// before, and the new stamp stops a rebuild for each later lookup.
		if previous != nil {
			carried := *previous
			carried.cachePath = cachePath
			carried.stamp = stamp

			return publish(&carried)
		}
	}

	entries, perr := parseMapping(mappingCSV)
	if perr != nil {
		// The embedded copy is the last resort, so a failure here leaves an empty
		// table rather than a nil map.
		entries = make(map[string]*LookupResult)
	}

	return publish(&lookupTable{
		entries:   entries,
		source:    "embedded",
		cachePath: cachePath,
		stamp:     stamp,
	})
}

// publish stores the table and returns it.
func publish(table *lookupTable) *lookupTable {
	loadedTable.Store(table)

	return table
}

// activeTable returns the active table, and it rebuilds the table when the file time or
// the size of the cache file changed. GetDatabaseInfo reads the whole snapshot, so it
// reads one consistent state.
//
// The check costs one os.Stat call for each lookup. A lookup measured 6.6 ns before #74
// and 614 ns after it, on macOS 25.6.0 on 2026-08-14. The library holds no exported name
// that a writer in another package calls, so a stat is the one way to see an update that
// another program made. A writer inside this package calls invalidateLookupTable instead,
// and it pays nothing.
func activeTable() *lookupTable {
	table := loadedTable.Load()
	if table != nil && statCache(table.cachePath).same(table.stamp) {
		return table
	}

	return rebuildTable()
}

// LookupFingerprint looks up a JA4+ fingerprint in the local FoxIO database.
// If a cached database file is present at the user-cache path
// (see CachedDatabasePath), it is used; otherwise the embedded database is
// used. Returns nil if the fingerprint is not found. This function never
// makes network calls.
//
// The library reads the file time and the size of the cache file at each call, and it
// rebuilds the table when one of the two changes. A program that updates the database
// therefore reads the new table at its next lookup, and it needs no restart. A rebuild
// that cannot parse the cache file leaves the previous table in place. A cache file that
// the program deleted makes the library read the embedded copy.
//
// This function is safe for concurrent use.
//
// The remote lookup lives in the package
// github.com/Crank-Git/ja4plus-go/ja4db, which this package does not import.
func LookupFingerprint(fingerprint string) *LookupResult {
	db := loadDB()
	return db[fingerprint]
}

// CachedDatabasePath returns the path where a cached ja4plus-mapping.csv
// downloaded by `ja4plus db update` is stored. The directory is created if
// it does not already exist.
func CachedDatabasePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(dir, "ja4plus")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, "ja4plus-mapping.csv"), nil
}

// DatabaseInfo describes the active lookup database.
type DatabaseInfo struct {
	// Source is "embedded" or "cache".
	Source string
	// Path is the cache path when Source == "cache", empty otherwise.
	Path string
	// Entries is the number of fingerprints loaded.
	Entries int
	// ModTime is the modification time of the cache file (zero for embedded).
	ModTime time.Time
}

// GetDatabaseInfo returns metadata about the currently-active database.
// It reads one snapshot of the table, so the source, the path and the record count
// describe one state.
func GetDatabaseInfo() DatabaseInfo {
	table := activeTable()
	info := DatabaseInfo{Source: table.source, Entries: len(table.entries)}

	if table.source == "cache" {
		info.Path = table.path
		info.ModTime = table.modTime
	}

	return info
}
