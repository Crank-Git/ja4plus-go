package ja4plus

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests hold FR-reference-12 through FR-reference-16 for the two pages that issue
// #18 writes.
//
// FoxIO commit b6f3ff4 deleted seven text specifications from `technical_details/`.
// `docs/specs/foxio/deleted-text-specifications.md` recovers them. The recovered text is
// evidence, and `.claude/rules/ste.md` bars a change to it, so these tests compare the
// copy against the SHA-256 digest of the deleted file.
//
// The digest is the fixed point of the comparison, because no test reaches the network.
// The repository holds one copy of the FoxIO text and no second copy under `testdata/`.
// The maintainer ruled on 2026-08-11 that the page carries the copy, and a reference copy
// under `testdata/` would redistribute the same text a second time.

const (
	// foxioDeletedSpecsPage holds the seven recovered text specifications.
	foxioDeletedSpecsPage = "docs/specs/foxio/deleted-text-specifications.md"

	// foxioZeekPage holds the reading of the FoxIO Zeek package.
	foxioZeekPage = "docs/specs/foxio/zeek.md"

	// foxioReferenceDir holds every FoxIO transcription and reading.
	foxioReferenceDir = "docs/specs/foxio"

	// foxioDeletedSpecsCommit is the FoxIO commit at which this project read the seven
	// deleted files. It is the parent of b6f3ff4, and it is not the pin.
	foxioDeletedSpecsCommit = "7ff7b3275a9d084ab6884559a6e58a9cee08f19d"

	// foxioDeletedSpecsFence opens and closes a recovered file. It is seven characters
	// long, because the recovered text holds fences of three characters.
	foxioDeletedSpecsFence = "```````"
)

// foxioDeletedSpecsDigests names each deleted file and the SHA-256 digest of its content
// at commit 7ff7b32. Re-verify a digest against FoxIO before you change it.
var foxioDeletedSpecsDigests = map[string]string{
	"JA4.md":    "a8c2b4c2ecf4f7836a04ad3f2614ca33d0b9f0836805aa3de9e6d0be6fbd20ec",
	"JA4H.md":   "0587d4180145e7c1f02adde3583fbb2929486e85a05a082f5c139d21d16f918f",
	"JA4L.md":   "bcf02bc318f7d783da45eff5d00aa32fb5f7b874688eb17e766ba3d6956e8247",
	"JA4S.md":   "d762c3aadf34ef3999bcbb777ca43c20db0b42923910cb7018430f292e6baf51",
	"JA4SSH.md": "843c8f737ec40b4e38300021fcaca7ac8a058ed869ecda5de068fc57cf8af66c",
	"JA4T.md":   "d8ec985535f5bbf2cf411989f6ab19b17191585137e4ee448041e9ee91191d76",
	"JA4X.md":   "b094b74a74c541fabb6c3c01150fe10960f41047e6ef5ac8fd15c32259407c8b",
}

// foxioDeletedSpecsNames lists the seven deleted files in the order the page holds them.
var foxioDeletedSpecsNames = []string{
	"JA4.md",
	"JA4H.md",
	"JA4L.md",
	"JA4S.md",
	"JA4SSH.md",
	"JA4T.md",
	"JA4X.md",
}

// foxioDeletedSpecsBlock returns the recovered content of one deleted file.
// It fails the test when the page holds no block for the name.
//
// The page wraps each file in a fence, so a reader of the rendered page sees the FoxIO
// text and never a rendered FoxIO image.
func foxioDeletedSpecsBlock(t *testing.T, page string, name string) string {
	t.Helper()

	begin := "<!-- BEGIN VERBATIM " + name + " -->\n" + foxioDeletedSpecsFence + "\n"
	end := "\n" + foxioDeletedSpecsFence + "\n<!-- END VERBATIM " + name + " -->"

	_, rest, found := strings.Cut(page, begin)
	if !found {
		t.Fatalf("%s holds no %q marker", foxioDeletedSpecsPage, begin)
	}

	content, _, found := strings.Cut(rest, end)
	if !found {
		t.Fatalf("%s holds no %q marker", foxioDeletedSpecsPage, end)
	}

	// The fence consumes the final newline of the file, so the comparison restores it.
	return content + "\n"
}

// foxioDeletedSpecsProse returns the page with every recovered file removed.
// It fails the test when the page holds no block for a deleted file.
func foxioDeletedSpecsProse(t *testing.T, page string) string {
	t.Helper()

	prose := page
	for _, name := range foxioDeletedSpecsNames {
		before, rest, found := strings.Cut(prose, "<!-- BEGIN VERBATIM "+name+" -->")
		if !found {
			t.Fatalf("%s holds no block for %s", foxioDeletedSpecsPage, name)
		}

		_, after, found := strings.Cut(rest, "<!-- END VERBATIM "+name+" -->")
		if !found {
			t.Fatalf("%s holds no end marker for %s", foxioDeletedSpecsPage, name)
		}

		prose = before + after
	}

	return prose
}

// FR-reference-12 and FR-reference-15. The recovered text is verbatim, byte for byte.
func TestDeletedSpecsPageReproducesEachFoxIOFileWithoutAChange(t *testing.T) {
	page := readRepoFile(t, foxioDeletedSpecsPage)

	for _, name := range foxioDeletedSpecsNames {
		content := foxioDeletedSpecsBlock(t, page, name)

		digest := sha256.Sum256([]byte(content))
		got := hex.EncodeToString(digest[:])

		if got != foxioDeletedSpecsDigests[name] {
			t.Errorf("%s reproduces %s with digest %s, and FoxIO commit %s holds digest %s", foxioDeletedSpecsPage, name, got, foxioDeletedSpecsCommit, foxioDeletedSpecsDigests[name])
		}
	}
}

// FR-reference-12. The page names the commit it read the seven files at.
func TestDeletedSpecsPageNamesTheCommitItReadTheFilesAt(t *testing.T) {
	page := readRepoFile(t, foxioDeletedSpecsPage)

	for _, want := range []string{
		foxioDeletedSpecsCommit,
		// b6f3ff4 deleted the seven files, and a reader needs the commit that did it.
		"b6f3ff4",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("%s does not name %q", foxioDeletedSpecsPage, want)
		}
	}

	// The pin is a different commit, and the page states the difference on purpose.
	if !strings.Contains(page, foxioPinnedCommit) {
		t.Errorf("%s does not name the pinned commit %s", foxioDeletedSpecsPage, foxioPinnedCommit)
	}
}

// FR-reference-12. The page holds all seven deleted files and no other.
func TestDeletedSpecsPageHoldsSevenRecoveredFiles(t *testing.T) {
	page := readRepoFile(t, foxioDeletedSpecsPage)

	if got := strings.Count(page, "<!-- BEGIN VERBATIM "); got != len(foxioDeletedSpecsNames) {
		t.Errorf("%s holds %d recovered files, and FR-reference-12 names %d", foxioDeletedSpecsPage, got, len(foxioDeletedSpecsNames))
	}
}

// FR-reference-13. A deleted text specification corroborates an image, and it never
// outranks one.
func TestDeletedSpecsPageStatesThatAnImageOutranksTheDeletedText(t *testing.T) {
	prose := foxioDeletedSpecsProse(t, readRepoFile(t, foxioDeletedSpecsPage))

	for _, want := range []string{
		"corroborates",
		"never outranks",
	} {
		if !strings.Contains(prose, want) {
			t.Errorf("%s does not hold %q, and FR-reference-13 needs the rank statement", foxioDeletedSpecsPage, want)
		}
	}
}

// The maintainer ruled on 2026-08-11 that the page carries the copy and the FoxIO notice.
// `.claude/rules/rulings.md` requires the record of a ruling, and issue #18 holds it.
func TestDeletedSpecsPageCarriesTheFoxIOLicenseNoticeAndTheRuling(t *testing.T) {
	prose := foxioDeletedSpecsProse(t, readRepoFile(t, foxioDeletedSpecsPage))

	for _, want := range []string{
		"FoxIO License 1.1",
		"non-commercial use only",
		"https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE",
		"NOTICE",
		"#18",
		"2026-08-11",
	} {
		if !strings.Contains(prose, want) {
			t.Errorf("%s does not hold %q", foxioDeletedSpecsPage, want)
		}
	}
}

// FR-reference-16. The page links to the FoxIO images, and it renders none of them.
func TestDeletedSpecsPageRendersNoFoxIOImage(t *testing.T) {
	prose := foxioDeletedSpecsProse(t, readRepoFile(t, foxioDeletedSpecsPage))

	if strings.Contains(prose, "![") {
		t.Errorf("%s renders an image outside a recovered file, and FR-reference-16 bars one", foxioDeletedSpecsPage)
	}

	if !strings.Contains(prose, "https://github.com/FoxIO-LLC/ja4/tree/main/technical_details") {
		t.Errorf("%s does not link to the FoxIO images, and FR-reference-16 needs the link", foxioDeletedSpecsPage)
	}
}

// FR-reference-16. The reference directory holds no copy of a FoxIO image.
func TestFoxIOReferenceDirectoryHoldsNoImageFile(t *testing.T) {
	entries, err := os.ReadDir(foxioReferenceDir)
	if err != nil {
		t.Fatalf("read %s: %v", foxioReferenceDir, err)
	}

	for _, entry := range entries {
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp":
			t.Errorf("%s holds the image %s, and FR-reference-16 bars a reproduction", foxioReferenceDir, entry.Name())
		}
	}
}

// FR-reference-14. The Zeek page records the reading at the pinned commit.
func TestZeekPageRecordsTheReadingAtThePinnedCommit(t *testing.T) {
	page := readRepoFile(t, foxioZeekPage)

	if !strings.Contains(page, foxioPinnedCommit) {
		t.Errorf("%s does not name the pinned commit %s", foxioZeekPage, foxioPinnedCommit)
	}

	if !strings.Contains(page, "https://github.com/FoxIO-LLC/ja4/tree/main/zeek") {
		t.Errorf("%s does not link to the FoxIO Zeek package", foxioZeekPage)
	}
}

// FR-reference-14. Every claim on the Zeek page cites a file and a line.
// `.claude/rules/rulings.md` requires the location, so the page holds the `zeek/` form.
func TestZeekPageCitesAFileAndALine(t *testing.T) {
	page := readRepoFile(t, foxioZeekPage)

	// `zeek/ja4l/main.zeek:57` is the citation form the rules file names.
	if got := strings.Count(page, ".zeek:"); got < 10 {
		t.Errorf("%s holds %d `zeek/<file>:<line>` citations, and a reading needs one per claim", foxioZeekPage, got)
	}
}

// FR-reference-14. The page names each value this project declines to treat as a
// reference value. `docs/specs/features/11-foxio-reference.md` names JA4L and JA4LS.
func TestZeekPageNamesEachValueThisProjectDeclines(t *testing.T) {
	page := readRepoFile(t, foxioZeekPage)

	for _, want := range []string{
		"## The values this project declines",
		"JA4L",
		"JA4LS",
		"ja4l_delta",
		"ja4ls_delta",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("%s does not hold %q, and FR-reference-14 needs the declined values", foxioZeekPage, want)
		}
	}
}

// FR-reference-14. The Zeek JA4TS delay is a declined value.
//
// Zeek truncates each delay, and this project rounds each delay. The reading adopts the
// ruling of the Python port, so the page names the port commit. A later reader reverses
// the reading in the port, and `.claude/rules/parity.md` states why.
func TestZeekPageDeclinesTheZeekJA4TSDelay(t *testing.T) {
	page := readRepoFile(t, foxioZeekPage)

	for _, want := range []string{
		"### The Zeek JA4TS delay",
		// The two lines that truncate.
		"zeek/ja4t/main.zeek:180",
		"zeek/ja4t/main.zeek:233",
		// The line that rounds.
		"wireshark/source/packet-ja4.c:277",
		// The port commit that holds the ruling this reading adopts.
		"21299645366591331eb93155355b65a76a3729f3",
		"R12 rule 2",
		".claude/rules/parity.md",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("%s does not hold %q, and FR-reference-14 needs the JA4TS delay decline", foxioZeekPage, want)
		}
	}
}
