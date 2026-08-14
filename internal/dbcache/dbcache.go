// Package dbcache validates a JA4+ fingerprint database and installs it in the cache file.
//
// A downloaded database is untrusted input, and this package is the validation boundary of
// the library. No caller writes the cache file by another path.
//
// The package holds one bound and one CSV column set for the whole repository. The library
// and the command-line program each read them here, so the two never state two values.
//
// The CSV column set and the ja4db.com JSON field set are two keyspaces, and this package
// holds the CSV one alone. `ja4db/lookup.go` names `application`, `library`, `device` and
// `os` as JSON field names of the remote response, and that literal is no second copy of
// this column set. The names read alike because ja4db.com publishes one record shape in two
// encodings.
//
// `docs/specs/features/09-database-lookup.md` states FR-lookup-23 through FR-lookup-26.
package dbcache

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MaxBytes bounds a database that replaces the cache file. FR-lookup-25 states 16 MB.
//
// The mapping file that FoxIO publishes holds 4740 bytes, measured on 2026-08-14, so the
// bound leaves the file room to grow by a factor of about 3500.
const MaxBytes = 16 << 20

// cacheFileMode names the mode of the cache file. os.CreateTemp creates a file that the
// owner alone reads, and every process that reads the database reads the cache file.
const cacheFileMode = 0o644

// FingerprintColumns returns the name of each column that holds a fingerprint value.
// `parseMapping` in `lookup.go` indexes a record by each one of them.
//
// The function returns a new slice at each call, because a package-level slice is state
// that a caller changes.
func FingerprintColumns() []string {
	return []string{"ja4", "ja4s", "ja4h", "ja4x", "ja4t", "ja4tscan"}
}

// IdentityColumns returns the name of each column that identifies the application of a
// record. `parseMapping` in `lookup.go` joins the non-empty ones into the application name.
func IdentityColumns() []string {
	return []string{"Application", "Library", "Device", "OS"}
}

// Validate reports whether the database is one the library loads.
//
// It returns an error in each of these cases.
//
//   - The database is above MaxBytes.
//   - The CSV reader rejects the header row.
//   - The header holds no fingerprint column.
//   - The header holds no identity column.
//   - No record carries both a fingerprint value and an identity value.
//
// The last case matters, because a database that yields no entry answers every lookup with
// nil. `rebuildTable` in `lookup.go` then keeps the previous table, and the caller reads a
// successful update that changed nothing.
//
// A record that the CSV reader rejects is not a reason to reject the file, because
// `parseMapping` in `lookup.go` skips such a record.
func Validate(data []byte) error {
	if len(data) > MaxBytes {
		return fmt.Errorf("the database holds %d bytes, and the bound is %d bytes", len(data), MaxBytes)
	}

	reader := csv.NewReader(bytes.NewReader(data))

	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("read the header row: %w", err)
	}

	column := map[string]int{}
	for index, name := range header {
		column[strings.TrimSpace(name)] = index
	}

	fingerprintIndex := presentColumns(column, FingerprintColumns())
	if len(fingerprintIndex) == 0 {
		return fmt.Errorf("the header holds no fingerprint column, and one of %s is needed",
			strings.Join(FingerprintColumns(), ", "))
	}

	identityIndex := presentColumns(column, IdentityColumns())
	if len(identityIndex) == 0 {
		return fmt.Errorf("the header holds no identity column, and one of %s is needed",
			strings.Join(IdentityColumns(), ", "))
	}

	for {
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}

		if readErr != nil {
			continue
		}

		// `parseMapping` skips a record that carries no identity value, so a record needs
		// both halves to reach the table.
		if holdsValue(record, fingerprintIndex) && holdsValue(record, identityIndex) {
			return nil
		}
	}

	return errors.New("the database holds no record that carries a fingerprint value and an identity value")
}

// Write validates the database and replaces the cache file at the path.
//
// It writes a temporary file in the directory of the path and renames it, so a reader
// reads the previous database or the new one and never a partial file. It removes the
// temporary file on each failure path.
//
// A failure leaves the previous cache file unchanged.
//
// The function syncs the temporary file and it syncs no directory, so a power loss between
// the rename and the next directory write can leave the previous name. The cache file holds
// a copy of a file the program downloads again, so the library declines that cost.
func Write(path string, data []byte) error {
	if err := Validate(data); err != nil {
		return err
	}

	directory := filepath.Dir(path)

	// A rename across two filesystems is not atomic, so the temporary file sits beside the
	// target.
	temporary, err := os.CreateTemp(directory, ".ja4plus-mapping-*.csv")
	if err != nil {
		return fmt.Errorf("create a temporary file in %s: %w", directory, err)
	}

	name := temporary.Name()

	// A successful rename removes the name, so this call then reports a file it does not
	// find. Every failure path below leaves the name, and this call removes it.
	defer func() { _ = os.Remove(name) }()

	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()

		return fmt.Errorf("write %s: %w", name, err)
	}

	// The rename publishes the file, so the content reaches the disk first.
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()

		return fmt.Errorf("write %s to the disk: %w", name, err)
	}

	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}

	if err := os.Chmod(name, cacheFileMode); err != nil {
		return fmt.Errorf("set the mode of %s: %w", name, err)
	}

	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}

	return nil
}

// presentColumns returns the index of each name that the header holds.
func presentColumns(column map[string]int, names []string) []int {
	var index []int

	for _, name := range names {
		if position, ok := column[name]; ok {
			index = append(index, position)
		}
	}

	return index
}

// holdsValue reports whether the record carries a non-empty value in one of the columns.
func holdsValue(record []string, index []int) bool {
	for _, position := range index {
		if position < len(record) && strings.TrimSpace(record[position]) != "" {
			return true
		}
	}

	return false
}
