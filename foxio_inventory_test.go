package ja4plus

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The inventory page records the FoxIO source material that every ruling cites. A reader
// who checks a citation reads the page, and never the FoxIO repository. These tests hold
// FR-reference-1 through FR-reference-5.
//
// The page records a hash, and no test re-measures it. A test that hashed the material
// would need the FoxIO repository, and `docs/specs/features/11-foxio-reference.md`
// declines to commit that material.

// foxioInventoryPagePath names the page that holds the inventory.
const foxioInventoryPagePath = "docs/specs/foxio/README.md"

// readFoxioInventoryPage returns the content of the inventory page.
func readFoxioInventoryPage(t *testing.T) string {
	t.Helper()

	content, err := os.ReadFile(foxioInventoryPagePath)
	if err != nil {
		t.Fatalf("read %s: %v", foxioInventoryPagePath, err)
	}

	return string(content)
}

// readFoxioInventoryPin returns the commit that `testdata/foxio.pin` holds.
func readFoxioInventoryPin(t *testing.T) string {
	t.Helper()

	content, err := os.ReadFile("testdata/foxio.pin")
	if err != nil {
		t.Fatalf("read testdata/foxio.pin: %v", err)
	}

	return strings.TrimSpace(string(content))
}

// foxioInventoryFullCommitPattern matches one full commit hash. The word boundaries keep
// it away from a SHA-256 hash, which holds 64 hexadecimal characters and no boundary at
// character 40.
var foxioInventoryFullCommitPattern = regexp.MustCompile(`\b[0-9a-f]{40}\b`)

// foxioInventoryRowPattern matches one table row of the inventory. The three cells hold
// the file name, the byte count and the SHA-256 hash.
var foxioInventoryRowPattern = regexp.MustCompile(
	`(?m)^\|\s*` + "`" + `([A-Za-z0-9._]+\.(?:md|png))` + "`" + `\s*\|\s*([0-9]+)\s*\|\s*` + "`" + `([0-9a-f]{64})` + "`" + `\s*\|`,
)

// FR-reference-5 — the page and the pin must name one commit. A moved pin that leaves the
// page behind means the recorded hashes measure material the project no longer reads.
func TestFoxioInventoryPageNamesTheCommitThatTheFoxioPinHolds(t *testing.T) {
	pin := readFoxioInventoryPin(t)
	page := readFoxioInventoryPage(t)

	commits := foxioInventoryFullCommitPattern.FindAllString(page, -1)
	if len(commits) == 0 {
		t.Fatalf("%s names no full commit hash, and FR-reference-1 records one", foxioInventoryPagePath)
	}

	for _, commit := range commits {
		if commit != pin {
			t.Errorf("%s names the commit %q, and testdata/foxio.pin holds %q", foxioInventoryPagePath, commit, pin)
		}
	}
}

// FR-reference-1 — a reader who cannot reach the source URL cannot check a citation.
//
// Each check anchors on the label of its row. The page carries a commit date as well as a
// retrieval date, so a pattern that matched any date would still pass after somebody
// removed the retrieval date.
func TestFoxioInventoryPageRecordsTheSourceURLAndTheRetrievalDate(t *testing.T) {
	page := readFoxioInventoryPage(t)
	pin := readFoxioInventoryPin(t)

	if !strings.Contains(page, "https://github.com/FoxIO-LLC/ja4") {
		t.Errorf("%s records no source URL, and FR-reference-1 names one", foxioInventoryPagePath)
	}

	if !regexp.MustCompile(`Retrieval date\s*\|\s*\d{4}-\d{2}-\d{2}\b`).MatchString(page) {
		t.Errorf("%s records no retrieval date row, and FR-reference-1 names one", foxioInventoryPagePath)
	}

	if !regexp.MustCompile(`Pinned commit\s*\|\s*` + "`" + pin + "`").MatchString(page) {
		t.Errorf("%s records no pinned commit row that holds %q, and FR-reference-1 names one", foxioInventoryPagePath, pin)
	}
}

// FR-reference-2 — the directory holds twelve files at the pin. The count is a fact of
// `docs/specs/features/11-foxio-reference.md`, and a row that disappears is a defect.
func TestFoxioInventoryPageHoldsOneRowPerFileOfTechnicalDetails(t *testing.T) {
	page := readFoxioInventoryPage(t)

	rows := foxioInventoryRowPattern.FindAllStringSubmatch(page, -1)
	if len(rows) != 12 {
		t.Fatalf("%s holds %d file rows, and technical_details holds 12 files at the pin", foxioInventoryPagePath, len(rows))
	}

	seen := map[string]bool{}
	for _, row := range rows {
		name, byteCount, hash := row[1], row[2], row[3]

		if seen[name] {
			t.Errorf("%s holds two rows for %s", foxioInventoryPagePath, name)
		}
		seen[name] = true

		count, err := strconv.Atoi(byteCount)
		if err != nil || count <= 0 {
			t.Errorf("the row for %s holds the byte count %q, and FR-reference-2 names a positive count", name, byteCount)
		}

		if len(hash) != 64 {
			t.Errorf("the row for %s holds a hash of %d characters, and a SHA-256 hash holds 64", name, len(hash))
		}
	}
}

// FR-reference-3 — the page states the command that reproduces the measurement.
// The command reads the FoxIO repository directly, so a reader reproduces the measurement
// without the corpus. #165 added `technical_details/` to the corpus at
// `testdata/foxio/reference/technical_details/`, and the same command reads it there.
func TestFoxioInventoryPageStatesTheCommandThatReproducesTheMeasurement(t *testing.T) {
	page := readFoxioInventoryPage(t)
	pin := readFoxioInventoryPin(t)

	for _, part := range []string{
		"git clone https://github.com/FoxIO-LLC/ja4.git",
		"git -C ja4 checkout " + pin,
		"shasum -a 256 ja4/technical_details/*",
		"wc -c ja4/technical_details/*",
	} {
		if !strings.Contains(page, part) {
			t.Errorf("%s states no command that holds %q, and FR-reference-3 names one command", foxioInventoryPagePath, part)
		}
	}
}
