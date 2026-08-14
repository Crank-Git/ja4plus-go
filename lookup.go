package ja4plus

import (
	_ "embed"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed data/ja4plus-mapping.csv
var mappingCSV []byte

// LookupResult holds the result of a fingerprint database lookup.
type LookupResult struct {
	Application string
	Type        string
	Notes       string
}

var (
	lookupDB    map[string]*LookupResult
	lookupOnce  sync.Once
	dbSource    = "embedded" // "embedded" or "cache"
	dbCachePath string
)

func loadDB() map[string]*LookupResult {
	lookupOnce.Do(func() {
		lookupDB = make(map[string]*LookupResult)

		// Prefer the cache file if it exists and is non-empty.
		data := mappingCSV
		if cp, err := CachedDatabasePath(); err == nil {
			if b, rerr := os.ReadFile(cp); rerr == nil && len(b) > 0 {
				data = b
				dbSource = "cache"
				dbCachePath = cp
			}
		}

		r := csv.NewReader(strings.NewReader(string(data)))

		// Read header
		header, err := r.Read()
		if err != nil {
			return
		}

		// Build column index
		colIdx := make(map[string]int)
		for i, h := range header {
			colIdx[strings.TrimSpace(h)] = i
		}

		fpTypes := []string{"ja4", "ja4s", "ja4h", "ja4x", "ja4t", "ja4tscan"}

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
			for _, field := range []string{"Application", "Library", "Device", "OS"} {
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
					lookupDB[fpVal] = &LookupResult{
						Application: ident,
						Type:        fpType,
						Notes:       notes,
					}
				}
			}
		}
	})
	return lookupDB
}

// LookupFingerprint looks up a JA4+ fingerprint in the local FoxIO database.
// If a cached database file is present at the user-cache path
// (see CachedDatabasePath), it is used; otherwise the embedded database is
// used. Returns nil if the fingerprint is not found. This function never
// makes network calls.
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
func GetDatabaseInfo() DatabaseInfo {
	db := loadDB()
	info := DatabaseInfo{Source: dbSource, Entries: len(db)}
	if dbSource == "cache" {
		info.Path = dbCachePath
		if st, err := os.Stat(dbCachePath); err == nil {
			info.ModTime = st.ModTime()
		}
	}
	return info
}
