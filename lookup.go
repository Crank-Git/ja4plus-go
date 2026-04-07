package ja4plus

import (
	"encoding/csv"
	_ "embed"
	"io"
	"strings"
	"sync"
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
	lookupDB   map[string]*LookupResult
	lookupOnce sync.Once
)

func loadDB() map[string]*LookupResult {
	lookupOnce.Do(func() {
		lookupDB = make(map[string]*LookupResult)
		r := csv.NewReader(strings.NewReader(string(mappingCSV)))

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

// LookupFingerprint looks up a JA4+ fingerprint in the embedded FoxIO database.
// Returns nil if the fingerprint is not found.
func LookupFingerprint(fingerprint string) *LookupResult {
	db := loadDB()
	return db[fingerprint]
}
