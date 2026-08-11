package ja4plus

import (
	"strings"
	"testing"
)

// NOTICE is the file a consumer's lawyer reads. These tests hold FR-licensing-3 through
// FR-licensing-9, so that a later edit cannot drop a term or reword the FoxIO text
// without a failure.
//
// NOTICE holds two parts. The prose part states which license covers which material. The
// verbatim part reproduces FoxIO License 1.1. The two markers below separate them,
// because FR-licensing-4 and FR-licensing-5 apply to different parts. FR-licensing-4
// requires the full FoxIO text. That text names thirteen methods. FR-licensing-5 bars a
// method the library does not implement from this project's own list.

const (
	// noticeLicenseBeginMarker opens the verbatim FoxIO text in NOTICE.
	noticeLicenseBeginMarker = "===== BEGIN FoxIO License 1.1, verbatim ====="

	// noticeLicenseEndMarker closes the verbatim FoxIO text in NOTICE.
	noticeLicenseEndMarker = "===== END FoxIO License 1.1, verbatim ====="

	// noticeMethodListHeading opens the section that holds this project's method list.
	noticeMethodListHeading = "## The methods that this library implements under FoxIO License 1.1"
)

// foxioPinnedCommit is the FoxIO commit at which this project read the license.
// `testdata/foxio.pin` holds the same value.
const foxioPinnedCommit = "27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8"

// noticeMethods holds the nine methods this library implements under FoxIO License 1.1.
// FR-licensing-5 adds JA4LS when Epic 12 lands. Until then the list names nine.
var noticeMethods = []string{
	"JA4S",
	"JA4H",
	"JA4T",
	"JA4TS",
	"JA4L",
	"JA4X",
	"JA4SSH",
	"JA4D",
	"JA4D6",
}

// noticeProse returns the part of NOTICE above the verbatim FoxIO text.
// It fails the test when NOTICE holds no begin marker.
func noticeProse(t *testing.T) string {
	t.Helper()

	prose, _, found := strings.Cut(readRepoFile(t, "NOTICE"), noticeLicenseBeginMarker)
	if !found {
		t.Fatalf("NOTICE holds no %q marker", noticeLicenseBeginMarker)
	}

	return prose
}

// noticeMethodList returns the lines of the method-list section of NOTICE.
// It fails the test when NOTICE holds no method-list heading.
func noticeMethodList(t *testing.T) []string {
	t.Helper()

	_, rest, found := strings.Cut(noticeProse(t), noticeMethodListHeading)
	if !found {
		t.Fatalf("NOTICE holds no %q heading", noticeMethodListHeading)
	}

	section, _, _ := strings.Cut(rest, "\n## ")

	var names []string
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "JA4") {
			names = append(names, line)
		}
	}

	return names
}

func TestNoticeExistsAtTheRepositoryRoot(t *testing.T) {
	notice := readRepoFile(t, "NOTICE")

	if strings.TrimSpace(notice) == "" {
		t.Error("NOTICE is empty, and FR-licensing-3 requires the FoxIO terms")
	}
}

// FR-licensing-4. The FoxIO text is verbatim evidence, and `.claude/rules/ste.md` bars a
// change to it. `testdata/foxio-license-1.1.txt` holds the reference copy, read from
// `LICENSE` at the pinned FoxIO commit. This test compares byte for byte.
//
// No test reaches the network, so the reference copy is the fixed point of the
// comparison. Issue #11 read it at the pinned commit, and its SHA-256 digest is
// 7781abaf8b8f1cd550de05de5cba4387886dabd493e618b630b359c450f4d8f0. Re-verify the copy
// against FoxIO before you change it.
func TestNoticeHoldsTheFoxIOLicenseTextWithoutAChange(t *testing.T) {
	notice := readRepoFile(t, "NOTICE")
	reference := readRepoFile(t, "testdata/foxio-license-1.1.txt")

	if !strings.Contains(notice, reference) {
		t.Error("NOTICE does not hold the FoxIO License 1.1 text byte for byte; compare it with testdata/foxio-license-1.1.txt")
	}

	if !strings.Contains(notice, noticeLicenseEndMarker) {
		t.Errorf("NOTICE holds no %q marker", noticeLicenseEndMarker)
	}
}

// FR-licensing-5.
func TestNoticeNamesTheNineMethodsThisLibraryImplements(t *testing.T) {
	names := noticeMethodList(t)

	if len(names) != len(noticeMethods) {
		t.Fatalf("the method list of NOTICE names %d methods, and FR-licensing-5 names %d today: %v", len(names), len(noticeMethods), names)
	}

	for i, want := range noticeMethods {
		if names[i] != want {
			t.Errorf("the method list of NOTICE names %q at position %d, and FR-licensing-5 names %q", names[i], i, want)
		}
	}
}

// FR-licensing-5 bars a method the library does not implement from this project's list.
// JA4LS joins the list when Epic 12 lands, and the FoxIO records name four more methods
// that this library does not implement.
func TestNoticeMethodListExcludesEveryUnimplementedMethod(t *testing.T) {
	names := noticeMethodList(t)

	absent := []string{"JA4LS", "JA4TScan", "JA4SScan", "JA4Scan", "JA4E"}
	for _, name := range names {
		for _, unimplemented := range absent {
			if name == unimplemented {
				t.Errorf("the method list of NOTICE names %s, and this library does not implement it", unimplemented)
			}
		}
	}
}

// FR-licensing-5a. NOTICE asserts no equality with the FoxIO list, and it cites the three
// FoxIO records that name three different sets.
func TestNoticeAssertsNoEqualityWithTheFoxIOList(t *testing.T) {
	prose := noticeProse(t)

	for _, want := range []string{
		"asserts no equality",
		"License FAQ.md:5",
		"twelve",
		"README.md:293",
		"nine",
		"LICENSE:3",
		"thirteen",
		"JA4SScan",
		// The FoxIO README names nine methods, and this library also names nine. The two
		// sets are different, and a reader must not read the two counts as one set.
		"The two sets are different.",
		foxioPinnedCommit,
	} {
		if !strings.Contains(prose, want) {
			t.Errorf("NOTICE does not hold %q, and FR-licensing-5a needs the three FoxIO records", want)
		}
	}
}

// FR-licensing-6.
func TestNoticeStatesThatBSD3ClauseCoversJA4(t *testing.T) {
	prose := noticeProse(t)

	for _, want := range []string{
		"BSD 3-Clause",
		"LICENSE-JA4",
		"https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4",
	} {
		if !strings.Contains(prose, want) {
			t.Errorf("NOTICE does not hold %q, and FR-licensing-6 needs the JA4 license", want)
		}
	}
}

// FR-licensing-7.
func TestNoticeNamesTheFoxIOMappingFile(t *testing.T) {
	prose := noticeProse(t)

	for _, want := range []string{
		"data/ja4plus-mapping.csv",
		"FoxIO",
		"FoxIO License 1.1",
	} {
		if !strings.Contains(prose, want) {
			t.Errorf("NOTICE does not hold %q, and FR-licensing-7 needs the source of the mapping file", want)
		}
	}
}

// FR-licensing-8.
func TestNoticeLinksToTheFoxIOLicense(t *testing.T) {
	prose := noticeProse(t)

	if !strings.Contains(prose, "https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE") {
		t.Error("NOTICE does not link to <https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE>, and FR-licensing-8 needs the link")
	}
}

// FR-licensing-9.
func TestNoticeStatesThatTheLicensePermitsNonCommercialUseOnly(t *testing.T) {
	prose := noticeProse(t)

	if !strings.Contains(prose, "non-commercial use only") {
		t.Error("NOTICE does not state that FoxIO License 1.1 permits non-commercial use only, and FR-licensing-9 needs that statement")
	}
}

// The edge-case table of `docs/specs/features/01-licensing.md` states that a later FoxIO
// change produces a new issue. A reader needs the commit at which this project read the
// text, so NOTICE records it.
func TestNoticeRecordsTheCommitAtWhichThisProjectReadTheLicense(t *testing.T) {
	prose := noticeProse(t)

	if !strings.Contains(prose, foxioPinnedCommit) {
		t.Errorf("NOTICE does not record the FoxIO commit %s", foxioPinnedCommit)
	}

	pin := strings.TrimSpace(readRepoFile(t, "testdata/foxio.pin"))
	if pin != foxioPinnedCommit {
		t.Errorf("testdata/foxio.pin holds %q, and NOTICE records %q", pin, foxioPinnedCommit)
	}
}

// The § License section of `CLAUDE.md` bars an unqualified BSD 3-Clause claim. This test
// holds the negative half: the method-list section names no BSD 3-Clause license.
// `noticeMethodListHeading` holds the positive half, because the heading itself reads
// `under FoxIO License 1.1`, and every helper above fails when that heading is absent.
func TestNoticeMethodListNamesNoBSD3ClauseLicense(t *testing.T) {
	_, rest, found := strings.Cut(noticeProse(t), noticeMethodListHeading)
	if !found {
		t.Fatalf("NOTICE holds no %q heading", noticeMethodListHeading)
	}

	section, _, _ := strings.Cut(rest, "\n## ")
	if strings.Contains(section, "BSD 3-Clause") {
		t.Error("the method-list section of NOTICE names the BSD 3-Clause license, and FoxIO License 1.1 covers those methods")
	}
}
