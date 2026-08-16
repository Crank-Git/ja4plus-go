package repocheck

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// A page of `docs/specs/foxio/` cites a path, and the reader joins that path to a base
// directory. `docs/specs/foxio/README.md` `## How to read a citation` declares seven
// bases. #254 repaired every citation against that rule and could not hold the repair,
// because its acceptance criteria barred a Go file change. This file holds it, and it
// holds FR-reference-18a through FR-reference-18l.
//
// The failure this guard catches is silent. A writer joins `python/ja4.py` to
// `testdata/foxio/` by habit, the directory exists, and the file does not. #254 records
// one such citation that reached a ruling on 2026-08-12.

// `foxio_deleted_specs_test.go` declares foxioReferenceDir, and that directory holds the
// pages that carry a citation.

// This file records no count of pages. `docs/specs/foxio/README.md:51-53` states that a
// count of pages goes stale at the next edit, and that the citation rule needs none. A
// constant here would break the rule this file holds.

// foxioCorpusReferenceDir holds the FoxIO repository at the pin.
// `scripts/fetch-corpus.sh:167` writes it, and `make corpus` runs that script.
const foxioCorpusReferenceDir = "testdata/foxio/reference"

// `foxio_deleted_specs_test.go` declares foxioDeletedSpecsPage, and that page is base 4.

// foxioCitationExtension names the file extension that marks a code span as a path.
//
// A span with another extension is not a path, and the directory holds four kinds of
// them: a version such as `v1.1.0`, a Wireshark field such as `tcp.len`, a Zeek log field
// such as `ja4.ja4l`, and a format string such as `%12.12s`. An extension set separates
// the four from a citation, and no other rule does.
//
// The set holds no `log` extension. `conn.log` and `ssl.log` name a Zeek output stream in
// prose, and neither one names a file this project cites. The FoxIO tree holds `conn.log`
// at three paths under `zeek/tests/Traces/`, so a bare-name rule resolves it under no
// single path. It holds `ssl.log` at one path, so that name would resolve by accident.
var foxioCitationExtension = map[string]bool{
	"c": true, "csv": true, "go": true, "json": true, "md": true,
	"pcap": true, "pcapng": true, "pin": true, "png": true, "py": true,
	"rs": true, "sh": true, "snap": true, "toml": true, "txt": true,
	"yml": true, "zeek": true,
}

// foxioMovedDirectory maps the FoxIO path a citation names to the corpus directory that
// holds it. `scripts/fetch-corpus.sh:149` moves the three out of the staged tree, so a
// citation of one of the three reaches no path under `testdata/foxio/reference/`.
var foxioMovedDirectory = [][2]string{
	{"pcap/", "testdata/foxio/pcap/"},
	{"python/test/testdata/", "testdata/foxio/python/"},
	{"wireshark/test/testdata/", "testdata/foxio/wireshark/"},
}

// foxioTopLevelDirectory names each directory that the FoxIO repository holds at the root
// at the pin. The shape check reads this set, and it runs with no corpus.
//
// TestTheFoxioTopLevelDirectorySetMatchesTheCorpus holds the set against the fetched
// corpus, so a pin move that adds a directory fails a test rather than passing silently.
var foxioTopLevelDirectory = map[string]bool{
	".github":           true,
	"python":            true,
	"rust":              true,
	"technical_details": true,
	"wireshark":         true,
	"zeek":              true,
}

// foxioVectorExtension names the extension a file of a moved corpus directory carries.
// `testdata/foxio/pcap/` holds the captures, `testdata/foxio/python/` holds the per-stream
// vectors, and `testdata/foxio/wireshark/` holds the per-packet vectors.
//
// None of the three holds a source file. The shape check reads this set, so it names
// `testdata/foxio/python/ja4.py` a defect on a checkout that ran no `make corpus`.
var foxioVectorExtension = map[string]bool{
	"json": true, "pcap": true, "pcapng": true, "txt": true,
}

// foxioPortDirectory names each root directory of the port repository that a page of this
// directory cites at base 7. The port holds it at its root.
//
// #758 removed the mirrored copy of the port's register on 2026-08-16 UTC. That copy used
// the port's own citation forms, and it named `tests` and `.claude` of the port beside
// `ja4plus`. `portPath` accepted those two on the copy alone, and it rejected them on every
// other page, so both entries became unreachable when the copy went.
//
// `ja4plus` stays, and it needs no such restriction: this repository holds no directory of
// that name, so the root decides the repository on any page.
var foxioPortDirectory = map[string]bool{
	"ja4plus": true,
}

// foxioCitationException records a span that resolves under no base, with the reason.
//
// Each entry names one page and one span, and it states the count on that page. A count
// keeps the entry narrow: a fourth `ja4l.py` on a page fails the test, and a page-wide
// skip would hide it. #335 states that requirement.
var foxioCitationException = []struct {
	page   string
	span   string
	count  int
	reason string
}{
	{
		page:  "docs/specs/foxio/README.md",
		span:  "ja4l.py",
		count: 1,
		reason: "The page states why the recorded count of spans under no base is 3, and it " +
			"names the file once to do so. #758 removed the page that wrote the other two " +
			"occurrences on 2026-08-16 UTC. The FoxIO `python/` directory holds no file of " +
			"this name at the pin, so this span resolves under no base and the count keeps " +
			"the entry narrow.",
	},
}

// foxioCitation is one path-shaped code span of one page.
type foxioCitation struct {
	page string
	line int
	span string
	// path is the span without the `:line` suffix.
	path string
	// number is the cited line. It is 0 when the span carries no `:line` suffix.
	number int
}

// foxioResolution names the base a citation reads at, and the file it reaches.
type foxioResolution struct {
	base int
	// file is the path in this checkout. It is empty for base 6 and base 7, because
	// neither one reaches a file of this checkout.
	file string
}

// foxioCitationSpan matches one code span. A span holds no newline and no backtick.
var foxioCitationSpan = regexp.MustCompile("`([^`\n]+)`")

// foxioBlankFencedBlock returns the page with every fenced block line replaced by an
// empty line. A fenced block reproduces FoxIO material verbatim, and no span inside one
// is a citation of this project.
//
// A fence closes only on a fence at least as long as the one that opened it.
// `docs/specs/foxio/deleted-text-specifications.md` wraps each recovered file in a fence
// of seven characters, and five of the recovered files hold a fence of three. A rule that
// closed on any fence would end the block early and read the FoxIO text as prose.
//
// The function blanks a line rather than removing it, so a reported line number names the
// line of the page.
func foxioBlankFencedBlock(page string) []string {
	lines := strings.Split(page, "\n")
	open := 0

	for index, line := range lines {
		fence := foxioFenceLength(line)

		if open == 0 {
			if fence > 0 {
				open = fence
				lines[index] = ""
			}

			continue
		}

		// A closing fence carries nothing after the backticks, and an opening fence
		// carries an info string. A line of content that opens with a longer backtick run
		// therefore closes no block.
		if fence >= open && foxioFenceCloses(line) {
			open = 0
		}

		lines[index] = ""
	}

	return lines
}

// foxioFenceLength returns the count of the leading backticks of a fence line. It returns
// 0 when the line opens and closes no fence.
func foxioFenceLength(line string) int {
	trimmed := strings.TrimSpace(line)

	count := 0
	for count < len(trimmed) && trimmed[count] == '`' {
		count++
	}

	if count < 3 {
		return 0
	}

	return count
}

// foxioFenceCloses reports whether the line can close a fence. A closing fence holds
// backticks alone.
func foxioFenceCloses(line string) bool {
	return strings.Trim(strings.TrimSpace(line), "`") == ""
}

// foxioPathShaped reports whether the span names a path, and returns the path and the
// cited line number.
//
// A path carries an extension of foxioCitationExtension. A path holds no space and no
// glob character, because neither one names one file.
func foxioPathShaped(span string) (path string, number int, ok bool) {
	path = span

	if colon := strings.LastIndex(span, ":"); colon >= 0 {
		suffix := span[colon+1:]
		// The port writes a line range, such as `...snap:215-217`. The range names the
		// first line, and the resolver reads that line.
		if dash := strings.Index(suffix, "-"); dash >= 0 {
			suffix = suffix[:dash]
		}

		if parsed, err := strconv.Atoi(suffix); err == nil && parsed > 0 {
			path, number = span[:colon], parsed
		}
	}

	if strings.ContainsAny(path, " \t*?") {
		return "", 0, false
	}

	// A colon that survives the suffix parse is not a line number. A URL carries one, and
	// a URL names no path of a base.
	if strings.Contains(path, ":") {
		return "", 0, false
	}

	// A final component with an empty stem is an extension and never a path. The page
	// writes `.png` when it counts the image rows.
	final := path[strings.LastIndex(path, "/")+1:]

	dot := strings.LastIndex(final, ".")
	if dot <= 0 || dot == len(final)-1 {
		return "", 0, false
	}

	if !foxioCitationExtension[final[dot+1:]] {
		return "", 0, false
	}

	return path, number, true
}

// foxioCitationPage returns the pages of `docs/specs/foxio/`.
func foxioCitationPage(t *testing.T) []string {
	t.Helper()

	names, err := filepath.Glob(filepath.Join(foxioReferenceDir, "*.md"))
	if err != nil {
		t.Fatalf("list the pages of %s: %v", foxioReferenceDir, err)
	}

	if len(names) == 0 {
		t.Fatalf("%s holds no page, and the citation rule reads every page of it",
			foxioReferenceDir)
	}

	sort.Strings(names)

	return names
}

// foxioReadCitation returns every path-shaped span of every page, outside a fenced block.
func foxioReadCitation(t *testing.T) []foxioCitation {
	t.Helper()

	var citations []foxioCitation

	for _, page := range foxioCitationPage(t) {
		for index, line := range foxioBlankFencedBlock(readRepoFile(t, page)) {
			for _, match := range foxioCitationSpan.FindAllStringSubmatch(line, -1) {
				path, number, ok := foxioPathShaped(match[1])
				if !ok {
					continue
				}

				citations = append(citations, foxioCitation{
					page:   filepath.ToSlash(page),
					line:   index + 1,
					span:   match[1],
					path:   path,
					number: number,
				})
			}
		}
	}

	// A pattern that matched nothing would pass every test below and read no citation.
	if len(citations) == 0 {
		t.Fatalf("%s holds no path-shaped code span", foxioReferenceDir)
	}

	return citations
}

// foxioResolver resolves a citation against the bases. It holds the index of the corpus,
// and it holds the recovered files of the base 4 page.
type foxioResolver struct {
	// corpus reports whether `make corpus` has run.
	corpus bool
	// referenceName maps a bare file name to each path of the FoxIO tree that holds it.
	referenceName map[string][]string
	// captureName maps a bare capture name to its path under the moved directories.
	captureName map[string][]string
	// recoveredLines maps a recovered file name to the line count of its block.
	recoveredLines map[string]int
}

// newFoxioResolver builds the resolver. It reads the corpus when the corpus is present,
// and the caller reads the corpus field to learn which bases the resolver reaches.
func newFoxioResolver(t *testing.T) *foxioResolver {
	t.Helper()

	resolver := &foxioResolver{
		referenceName:  map[string][]string{},
		captureName:    map[string][]string{},
		recoveredLines: foxioRecoveredLineCount(t),
	}

	if info, err := os.Stat(foxioCorpusReferenceDir); err == nil && info.IsDir() {
		resolver.corpus = true
	}

	if !resolver.corpus {
		return resolver
	}

	resolver.index(t, foxioCorpusReferenceDir, resolver.referenceName)

	for _, moved := range foxioMovedDirectory {
		resolver.index(t, strings.TrimSuffix(moved[1], "/"), resolver.captureName)
	}

	return resolver
}

// index records each file below the root, keyed by its bare name.
func (r *foxioResolver) index(t *testing.T, root string, into map[string][]string) {
	t.Helper()

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil //nolint:nilerr // An unreadable entry indexes nothing, and the walk continues.
		}

		name := filepath.Base(path)
		into[name] = append(into[name], filepath.ToSlash(path))

		return nil
	})
	if err != nil {
		t.Fatalf("index %s: %v", root, err)
	}
}

// foxioFileExists reports whether the path names a file of this checkout.
func foxioFileExists(path string) bool {
	info, err := os.Stat(path)

	return err == nil && !info.IsDir()
}

// resolve returns the base the citation reads at.
//
// It tries the bases in the order of the table of `## How to read a citation`, because
// two bases can hold one path and the first row is the common case.
func (r *foxioResolver) resolve(citation foxioCitation) (foxioResolution, bool) {
	path := citation.path

	if r.corpus {
		if file := filepath.Join(foxioCorpusReferenceDir, path); foxioFileExists(file) {
			return foxioResolution{base: 1, file: file}, true
		}

		if !strings.Contains(path, "/") {
			file := filepath.Join(foxioCorpusReferenceDir, "technical_details", path)
			if foxioFileExists(file) {
				return foxioResolution{base: 2, file: file}, true
			}
		}

		for _, moved := range foxioMovedDirectory {
			if !strings.HasPrefix(path, moved[0]) {
				continue
			}

			if file := moved[1] + strings.TrimPrefix(path, moved[0]); foxioFileExists(file) {
				return foxioResolution{base: 3, file: file}, true
			}
		}

		// A capture reaches a moved directory under its bare name. `docs/specs/foxio/
		// JA4L.md` writes `ssh2.pcapng`, and the corpus holds one file of that name.
		if match, ok := r.unique(r.captureName, path); ok {
			return foxioResolution{base: 3, file: match}, true
		}

		// A bare source file name is a short form of base 1, so it reads before base 5.
		// `docs/specs/foxio/README.md` `## How to read a citation` states that form, and
		// that page writes `ja4.py`. A name that this repository also holds at its root
		// would otherwise read as base 5, and the line bound would then read the wrong file.
		if match, ok := r.unique(r.referenceName, path); ok {
			return foxioResolution{base: 1, file: match}, true
		}
	}

	if _, ok := r.recoveredLines[path]; ok {
		return foxioResolution{base: 4, file: foxioDeletedSpecsPage}, true
	}

	// Base 7 outranks base 5 on the verbatim copy. The copy cites
	// `.claude/rules/external-apis.md:95`, and this repository holds a file of that path
	// with 62 lines. Base 5 would resolve that citation to the wrong repository, and the
	// reader would read a line the port never named.
	if r.portPath(citation) {
		return foxioResolution{base: 7}, true
	}

	if foxioFileExists(path) {
		return foxioResolution{base: 5, file: path}, true
	}

	// Base 6. FoxIO deleted the file before the pin, so the corpus holds it at no path.
	//
	// The rule names the recovered files, and it accepts no other `technical_details/`
	// path. A bare prefix rule would accept `technical_details/JA4ZZZ.md`, which names a
	// file that existed at no commit. `docs/specs/foxio/README.md:86-87` states that five
	// of the seven recovered files exist at no commit after `b6f3ff4`, and the other two
	// resolve at base 1.
	if name, found := strings.CutPrefix(path, "technical_details/"); found {
		if _, recovered := r.recoveredLines[name]; recovered {
			return foxioResolution{base: 6, file: foxioDeletedSpecsPage}, true
		}
	}

	return foxioResolution{}, false
}

// unique returns the one path the index holds for the bare name. It returns false when
// the name holds a directory part, and when the index holds the name at no path or at
// more than one path.
func (r *foxioResolver) unique(index map[string][]string, path string) (string, bool) {
	if strings.Contains(path, "/") {
		return "", false
	}

	if match := index[path]; len(match) == 1 {
		return match[0], true
	}

	return "", false
}

// portPath reports whether the citation names a path of the port repository.
//
// `ja4plus/` is the port's package directory, and this repository holds no directory of
// that name, so the rule reads it on every page.
func (r *foxioResolver) portPath(citation foxioCitation) bool {
	root, _, found := strings.Cut(citation.path, "/")
	if !found {
		return false
	}

	return foxioPortDirectory[root]
}

// foxioRecoveredLineCount returns the line count of each recovered file that the base 4
// page reproduces. A citation of base 4 names a line of the recovered file, and never a
// line of the page.
//
// It reads the blocks through foxioDeletedSpecsBlock, so one extractor serves the
// verbatim check and this resolver.
func foxioRecoveredLineCount(t *testing.T) map[string]int {
	t.Helper()

	page := readRepoFile(t, foxioDeletedSpecsPage)
	count := map[string]int{}

	for _, name := range foxioDeletedSpecsNames {
		block := foxioDeletedSpecsBlock(t, page, name)
		count[name] = len(strings.Split(strings.TrimSuffix(block, "\n"), "\n"))
	}

	return count
}

// foxioExceptionKey names one entry of the exception table.
type foxioExceptionKey struct {
	page string
	span string
}

// foxioExceptionCount returns the recorded count of each exception.
func foxioExceptionCount() map[foxioExceptionKey]int {
	count := map[foxioExceptionKey]int{}

	for _, entry := range foxioCitationException {
		count[foxioExceptionKey{page: entry.page, span: entry.span}] += entry.count
	}

	return count
}

// foxioCorpusAbsentMessage states that the resolver read no corpus. #335 records that a
// silent skip is not a guard, so every skip below writes this sentence.
//
// The sentence carries no word of `conformanceSkipMarker`, because
// `.github/workflows/ci.yml` fails the conformance job on that marker and this skip means
// something else. TestTheCISkipDetectorMatchesNoUntaggedSkipMessage holds that separation.
const foxioCorpusAbsentMessage = "the citation resolver read no corpus at " +
	foxioCorpusReferenceDir + "; run `make corpus` to resolve base 1, base 2 and base 3. " +
	"The shape check of FR-reference-18b ran, and it needs no corpus."

// FR-reference-18a — every path-shaped code span of `docs/specs/foxio/` resolves under a
// base that `## How to read a citation` declares, or the exception table holds it.
//
// The corpus gates this test, because base 1, base 2 and base 3 each read a fetched file.
// FR-reference-18b holds the pages without the corpus.
func TestEveryCitationOfTheFoxioDirectoryResolvesUnderADeclaredBase(t *testing.T) {
	resolver := newFoxioResolver(t)
	if !resolver.corpus {
		t.Skip(foxioCorpusAbsentMessage)
	}

	exception := foxioExceptionCount()
	seen := map[foxioExceptionKey]int{}

	for _, citation := range foxioReadCitation(t) {
		if _, ok := resolver.resolve(citation); ok {
			continue
		}

		key := foxioExceptionKey{page: citation.page, span: citation.span}
		seen[key]++

		if seen[key] > exception[key] {
			t.Errorf("%s:%d cites %q, and it resolves under no base of `## How to read a citation`.\n"+
				"\tThe exception table holds %d span of this page with this text, and the page holds %d.\n"+
				"\tJoin the citation to a declared base, or record an exception with the reason.",
				citation.page, citation.line, citation.span, exception[key], seen[key])
		}
	}
}

// FR-reference-18b, FR-reference-18c and FR-reference-18d — the shape check reads the
// first directory of each span, it opens no file of the corpus, and it runs on every
// checkout.
//
// A span that reaches no file of this checkout must still name a directory that one of
// the bases holds. #254 records the failure this catches: a writer joins `python/ja4.py`
// to `testdata/foxio/`, that directory exists, and the file does not.
func TestEveryCitationOfTheFoxioDirectoryNamesADirectoryOfADeclaredBase(t *testing.T) {
	resolver := newFoxioResolver(t)
	exception := foxioExceptionCount()
	seen := map[foxioExceptionKey]int{}

	for _, citation := range foxioReadCitation(t) {
		if foxioShapeIsDeclared(resolver, citation) {
			continue
		}

		key := foxioExceptionKey{page: citation.page, span: citation.span}
		seen[key]++

		if seen[key] > exception[key] {
			t.Errorf("%s:%d cites %q, and its first directory belongs to no base of "+
				"`## How to read a citation`.\n"+
				"\tThe FoxIO repository holds %s at the root, and the corpus holds a moved "+
				"directory at %s.\n"+
				"\tJoin the citation to a declared base, or record an exception with the reason.",
				citation.page, citation.line, citation.span,
				foxioSortedKeys(foxioTopLevelDirectory), "pcap/")
		}
	}
}

// foxioShapeIsDeclared reports whether the citation names a directory of a declared base.
// It reads the corpus for no answer, so it holds on a checkout that ran no `make corpus`.
func foxioShapeIsDeclared(resolver *foxioResolver, citation foxioCitation) bool {
	path := citation.path

	// Base 4 and base 5 each reach a file of this checkout.
	if _, ok := resolver.recoveredLines[path]; ok {
		return true
	}

	if foxioFileExists(path) {
		return true
	}

	// Base 7 reaches the port, and base 6 reaches a deleted FoxIO file.
	if resolver.portPath(citation) {
		return true
	}

	// A page names the corpus location where a reader resolves base 1, base 2 and base 3.
	// That location is a path of this checkout, so base 5 resolves it when the corpus is
	// present. The two rules below hold it when the corpus is absent.
	if rest, found := strings.CutPrefix(path, foxioCorpusReferenceDir+"/"); found {
		root, _, hasDirectory := strings.Cut(rest, "/")

		return !hasDirectory || foxioTopLevelDirectory[root]
	}

	// A moved corpus directory holds the captures and the vectors, and it holds no source
	// file. #254 records the silent failure of a reader who joins `python/ja4.py` to
	// `testdata/foxio/`: that directory exists, and it never holds a source file.
	for _, moved := range foxioMovedDirectory {
		if rest, found := strings.CutPrefix(path, moved[1]); found {
			return foxioVectorExtension[foxioExtension(rest)]
		}
	}

	root, _, found := strings.Cut(path, "/")
	if !found {
		// A bare file name is a short form of base 1 and of base 3. The resolution check
		// of FR-reference-18a holds it against the corpus.
		return true
	}

	if foxioTopLevelDirectory[root] {
		return true
	}

	for _, moved := range foxioMovedDirectory {
		if strings.HasPrefix(path, moved[0]) {
			return true
		}
	}

	return false
}

// foxioExtension returns the extension of the path, without the dot.
func foxioExtension(path string) string {
	final := path[strings.LastIndex(path, "/")+1:]

	dot := strings.LastIndex(final, ".")
	if dot < 0 {
		return ""
	}

	return final[dot+1:]
}

// FR-reference-18e, FR-reference-18f and FR-reference-18g — an exception that now
// resolves fails the test. A stale exception
// hides the next defect, exactly as a page-wide skip does.
func TestTheCitationExceptionTableHoldsNoSpanThatNowResolves(t *testing.T) {
	resolver := newFoxioResolver(t)
	if !resolver.corpus {
		t.Skip(foxioCorpusAbsentMessage)
	}

	unresolved := map[foxioExceptionKey]int{}

	for _, citation := range foxioReadCitation(t) {
		if _, ok := resolver.resolve(citation); ok {
			continue
		}

		unresolved[foxioExceptionKey{page: citation.page, span: citation.span}]++
	}

	for _, entry := range foxioCitationException {
		key := foxioExceptionKey{page: entry.page, span: entry.span}

		if entry.reason == "" {
			t.Errorf("the exception for %q of %s states no reason", entry.span, entry.page)
		}

		if unresolved[key] != entry.count {
			t.Errorf("the exception table records %d span %q of %s, and the page holds %d "+
				"that resolve under no base.\n\tThe recorded reason is: %s",
				entry.count, entry.span, entry.page, unresolved[key], entry.reason)
		}
	}
}

// FR-reference-18h — no citation names a line past the end of the file it names.
//
// A citation that names a line the file does not hold sends a reader to nothing, and the
// reader cannot tell that from a moved line.
func TestNoCitationOfTheFoxioDirectoryNamesALinePastTheEndOfItsFile(t *testing.T) {
	resolver := newFoxioResolver(t)
	if !resolver.corpus {
		t.Skip(foxioCorpusAbsentMessage)
	}

	for _, citation := range foxioReadCitation(t) {
		resolution, ok := resolver.resolve(citation)
		if !ok || citation.number == 0 {
			continue
		}

		// Base 7 reaches the port, and this checkout holds no file of it, so no line
		// count bounds it.
		if resolution.base == 7 {
			continue
		}

		count := 0

		switch resolution.base {
		case 4:
			// Base 4 names a line of the recovered file, and never a line of the page.
			count = resolver.recoveredLines[citation.path]
		case 6:
			// Base 6 names the same deleted file that base 4 reproduces, under the
			// `technical_details/` path. The recovered block therefore bounds it.
			name, _ := strings.CutPrefix(citation.path, "technical_details/")
			count = resolver.recoveredLines[name]
		default:
			content, err := os.ReadFile(resolution.file)
			if err != nil {
				t.Errorf("%s:%d cites %q, and %s does not open: %v",
					citation.page, citation.line, citation.span, resolution.file, err)

				continue
			}

			count = len(strings.Split(strings.TrimSuffix(string(content), "\n"), "\n"))
		}

		// A base that reaches no file counts no line, and a zero count bounds nothing.
		if count == 0 {
			continue
		}

		if citation.number > count {
			t.Errorf("%s:%d cites %q, and %s holds %d lines at base %d",
				citation.page, citation.line, citation.span, resolution.file, count, resolution.base)
		}
	}
}

// FR-reference-18i and FR-reference-18j — the test names each page that states its own
// base, and it states the reason for that page.
//
// `docs/specs/foxio/deleted-text-specifications.md` is base 4, and it reproduces each
// recovered file verbatim. A page name that goes stale would make the resolver read a page
// that no tree holds.
//
// One page carried base 7 until 2026-08-16 UTC, and #758 removed it. Base 7 stays a base
// of `docs/specs/foxio/README.md`, and a citation of it now names `ja4plus/...` of the port
// at the tag rather than a page of this repository.
func TestEachPageThatStatesItsOwnCitationBaseExists(t *testing.T) {
	for page, reason := range map[string]string{
		foxioDeletedSpecsPage: "base 4. The page reproduces each recovered FoxIO file " +
			"verbatim, and a citation of base 4 names a line of the reproduced block.",
	} {
		if !foxioFileExists(page) {
			t.Errorf("%s does not exist, and the citation resolver reads it as %s", page, reason)
		}
	}
}

// FR-reference-18k — the recorded FoxIO root directories match the corpus. The shape
// check reads the recorded set, so a pin move that adds a directory must fail here rather
// than pass silently.
func TestTheFoxioTopLevelDirectorySetMatchesTheCorpus(t *testing.T) {
	resolver := newFoxioResolver(t)
	if !resolver.corpus {
		t.Skip(foxioCorpusAbsentMessage)
	}

	entries, err := os.ReadDir(foxioCorpusReferenceDir)
	if err != nil {
		t.Fatalf("read %s: %v", foxioCorpusReferenceDir, err)
	}

	found := map[string]bool{}

	for _, entry := range entries {
		if entry.IsDir() {
			found[entry.Name()] = true
		}
	}

	for name := range foxioTopLevelDirectory {
		if !found[name] {
			t.Errorf("foxioTopLevelDirectory names %q, and the corpus holds no such directory", name)
		}
	}

	for name := range found {
		if !foxioTopLevelDirectory[name] {
			t.Errorf("the corpus holds the directory %q, and foxioTopLevelDirectory names it not", name)
		}
	}
}

// FR-reference-18l — the resolver states that it read no corpus, and it never skips
// without that sentence. #335 records that a test which skips silently is not a guard.
func TestTheCitationResolverStatesThatItReadNoCorpus(t *testing.T) {
	if !strings.Contains(foxioCorpusAbsentMessage, foxioCorpusReferenceDir) {
		t.Errorf("the skip message names no corpus directory: %s", foxioCorpusAbsentMessage)
	}

	if !strings.Contains(foxioCorpusAbsentMessage, "make corpus") {
		t.Errorf("the skip message names no repair: %s", foxioCorpusAbsentMessage)
	}

	source := readRepoFile(t, "internal/repocheck/foxio_citation_base_test.go")

	// Every skip of this file writes the one message, so no skip of it is silent.
	skips := regexp.MustCompile(`t\.Skipf?\(([^)]*)\)`).FindAllStringSubmatch(source, -1)
	if len(skips) == 0 {
		t.Fatal("foxio_citation_base_test.go holds no skip, and the corpus gates three tests")
	}

	for _, skip := range skips {
		if strings.TrimSpace(skip[1]) != "foxioCorpusAbsentMessage" {
			t.Errorf("foxio_citation_base_test.go skips with %q, and every skip must write "+
				"foxioCorpusAbsentMessage", strings.TrimSpace(skip[1]))
		}
	}
}

// foxioSortedKeys returns the keys of the set, sorted, for a failure message.
func foxioSortedKeys(set map[string]bool) string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}

	sort.Strings(names)

	return strings.Join(names, ", ")
}
