package ja4plus

import (
	"strings"
	"testing"
)

// LICENSE covers the original Go code alone. FoxIO License 1.1 covers the JA4+ methods,
// and NOTICE carries those terms. These tests hold FR-licensing-1 and FR-licensing-2, so
// that a later edit cannot reword the license text without a failure.

// theCopyrightLine is the line the maintainer named for issue #10.
const theCopyrightLine = "Copyright (c) 2026 Crank-Git"

// bsdClauses holds the three numbered conditions of the BSD 3-Clause text.
// The strings come from <https://spdx.org/licenses/BSD-3-Clause.html>, read 2026-08-11.
var bsdClauses = []string{
	"1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.",
	"2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.",
	"3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.",
}

func TestLicenseExistsAtTheRepositoryRoot(t *testing.T) {
	license := readRepoFile(t, "LICENSE")

	if strings.TrimSpace(license) == "" {
		t.Error("LICENSE is empty, and FR-licensing-1 requires the BSD 3-Clause text")
	}
}

func TestLicenseNamesTheCopyrightHolderAndTheYear(t *testing.T) {
	license := readRepoFile(t, "LICENSE")

	first, _, found := strings.Cut(license, "\n")
	if !found {
		t.Fatal("LICENSE holds one line only")
	}

	if first != theCopyrightLine {
		t.Errorf("the first line of LICENSE is %q, and FR-licensing-2 names %q", first, theCopyrightLine)
	}
}

func TestLicenseHoldsTheThreeNumberedClauses(t *testing.T) {
	license := readRepoFile(t, "LICENSE")

	for _, clause := range bsdClauses {
		if !strings.Contains(license, clause) {
			t.Errorf("LICENSE does not hold this clause verbatim:\n%s", clause)
		}
	}
}

func TestLicenseHoldsTheGrantAndTheWarrantyDisclaimer(t *testing.T) {
	license := readRepoFile(t, "LICENSE")

	grant := "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:"
	if !strings.Contains(license, grant) {
		t.Error("LICENSE does not hold the grant sentence verbatim")
	}

	disclaimer := `THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"`
	if !strings.Contains(license, disclaimer) {
		t.Error("LICENSE does not hold the warranty disclaimer")
	}

	if !strings.Contains(license, "EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.") {
		t.Error("LICENSE truncates the warranty disclaimer")
	}
}

// The BSD 3-Clause text carries no "All rights reserved." line. This project adds none.
func TestLicenseAddsNoAllRightsReservedLine(t *testing.T) {
	license := readRepoFile(t, "LICENSE")

	if strings.Contains(license, "All rights reserved") {
		t.Error("LICENSE holds an `All rights reserved` line that the BSD 3-Clause text does not carry")
	}
}

// LICENSE states no claim about the JA4+ methods. NOTICE holds the FoxIO terms.
// Issue #11 writes NOTICE.
func TestLicenseNamesNoJA4PlusMethod(t *testing.T) {
	license := readRepoFile(t, "LICENSE")

	methods := []string{"JA4S", "JA4H", "JA4T", "JA4TS", "JA4L", "JA4X", "JA4SSH", "JA4D", "JA4D6", "FoxIO"}
	for _, method := range methods {
		if strings.Contains(license, method) {
			t.Errorf("LICENSE names %s, and LICENSE covers the original Go code alone", method)
		}
	}
}
