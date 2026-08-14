// Package dbcache validates a JA4+ fingerprint database and installs it in the cache file.
//
// A downloaded database is untrusted input, and this package is the validation boundary of
// the library. No caller writes the cache file by another path.
//
// The package holds one bound and one column set for the whole repository. The library and
// the command-line program each read them here, so the two never state two values.
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
// It returns an error when the database is above MaxBytes, when the CSV reader rejects the
// header row, when the header holds no fingerprint column, when the header holds no
// identity column, and when no record carries a fingerprint value.
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

	if len(presentColumns(column, IdentityColumns())) == 0 {
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

		if holdsFingerprint(record, fingerprintIndex) {
			return nil
		}
	}

	return errors.New("the database holds no record that carries a fingerprint value")
}

// Write validates the database and replaces the cache file at the path.
//
// It writes a temporary file in the directory of the path and renames it, so a reader
// reads the previous database or the new one and never a partial file. It removes the
// temporary file on each failure path.
//
// A failure leaves the previous cache file unchanged.
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

// holdsFingerprint reports whether the record carries a non-empty value in one of the
// fingerprint columns.
func holdsFingerprint(record []string, fingerprintIndex []int) bool {
	for _, position := range fingerprintIndex {
		if position < len(record) && strings.TrimSpace(record[position]) != "" {
			return true
		}
	}

	return false
}
