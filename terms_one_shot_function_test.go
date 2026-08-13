package ja4plus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// These tests hold the vocabulary that the ruling of #356 needs, and issue #379 adds it.
//
// The maintainer ruled on 2026-08-13 that `generate_ja4l` and `generate_ja4ssh` are
// `not applicable`. A one-shot call reaches no value for a method that reads more than one
// packet. `.claude/rules/ste.md` states that every domain word sits in the
// `## Terms` table of `docs/specs/spec.md`, and that table held neither word.
//
// `parity_one_shot_not_applicable_test.go` holds the ruling itself, against two names that
// it writes as literals. These tests read the term row instead, so they cover every method
// the row names. `ComputeJA4LS` is the name that separates them: FR-ja4ls-10 of
// `docs/specs/features/12-ja4ls.md` proposes it, and no other test rejects it.

// termsTableFile names the document that holds the controlled vocabulary.
const termsTableFile = "docs/specs/spec.md"

// termsTableHeading opens the section that holds the table.
const termsTableHeading = "\n## Terms\n"

// oneShotFunctionTerm names the term that a reader of the ruling of #356 looks up.
const oneShotFunctionTerm = "one-shot function"

// multiPacketMethodTerm names the term that states the other side of that distinction.
const multiPacketMethodTerm = "multi-packet method"

// oneShotFunctionPrefix names the exported functions of package ja4plus that the
// `one-shot function` row describes. The row cites `ComputeJA4T`, and every one-shot
// function of this package carries the prefix.
const oneShotFunctionPrefix = "Compute"

// methodNamePattern matches one JA4+ method name that a term row states.
var methodNamePattern = regexp.MustCompile(`JA4[A-Z0-9]*`)

// termsRow holds the four columns of one row of the `## Terms` table.
type termsRow struct {
	Term         string
	PartOfSpeech string
	Meaning      string
	DoNotUse     string
}

// termsTableCellCount states the column count of the `## Terms` table.
const termsTableCellCount = 4

// parseTermsTableRows returns one entry for each term row of the `## Terms` table section,
// and the first cell of each malformed row.
//
// A row is malformed when it splits into a count of cells that is not
// `termsTableCellCount`. A `|` character inside a cell produces one. The result holds no
// malformed row, so the caller reports every name of the second result.
func parseTermsTableRows(section string) (map[string]termsRow, []string) {
	rows := map[string]termsRow{}
	malformed := []string{}

	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| ") {
			continue
		}

		cells := strings.Split(strings.Trim(line, "|"), "|")
		term := strings.TrimSpace(cells[0])

		if len(cells) != termsTableCellCount {
			malformed = append(malformed, term)
			continue
		}

		if term == "Term" || strings.HasPrefix(term, "---") {
			continue
		}

		rows[term] = termsRow{
			Term:         term,
			PartOfSpeech: strings.TrimSpace(cells[1]),
			Meaning:      strings.TrimSpace(cells[2]),
			DoNotUse:     strings.TrimSpace(cells[3]),
		}
	}

	return rows, malformed
}

// readTermsTableRows returns one entry for each term row of the `## Terms` table.
//
// The table sits between its own heading and the next second-level heading, so a later
// table of the document reaches no row of this map.
//
// #428 — the reader dropped a malformed row and it reported nothing, so a guard that reads
// the dropped term read nothing and still passed. The reader now fails the test and it
// names the first cell of each malformed row.
func readTermsTableRows(t *testing.T) map[string]termsRow {
	t.Helper()

	page := readRepoFile(t, termsTableFile)

	start := strings.Index(page, termsTableHeading)
	if start < 0 {
		t.Fatalf("%s holds no %q heading, and the controlled vocabulary sits under it", termsTableFile, "## Terms")
	}

	section := page[start+len(termsTableHeading):]
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}

	rows, malformed := parseTermsTableRows(section)

	for _, term := range malformed {
		t.Errorf("the row %q of the `## Terms` table of %s splits into a count of cells that is not %d, and this reader drops it. A `|` character inside a cell produces that split. Remove that character from the cell",
			term, termsTableFile, termsTableCellCount)
	}

	if len(malformed) > 0 {
		t.FailNow()
	}

	if len(rows) == 0 {
		t.Fatalf("%s holds no term row under the %q heading", termsTableFile, "## Terms")
	}

	return rows
}

// #428 — a `|` character inside a cell removes the row from the map of the reader above.
// Each guard of this file then reads one term of a map that no longer holds it. This test
// builds the malformed row that `docs/specs/spec.md` must never hold, and it holds the
// reader against it.
//
// It reads a section that the test states, because the tree holds no malformed row today
// and this project adds none to prove a guard.
func TestTheTermsTableReaderReportsARowThatHoldsOtherThanFourCells(t *testing.T) {
	section := strings.Join([]string{
		"| Term | Part of speech | Meaning | Do not use |",
		"|---|---|---|---|",
		"| deviation | noun | A recorded difference, written `a | b`. | mismatch |",
		"| ruling | noun | One determination the maintainer makes. | decision |",
		"| reading | noun | One conclusion about a source. |",
		"",
	}, "\n")

	rows, malformed := parseTermsTableRows(section)

	for _, term := range []string{"deviation", "reading"} {
		if !slices.Contains(malformed, term) {
			t.Errorf("the reader reports the malformed rows %q, and the row %q holds a count of cells that is not %d",
				malformed, term, termsTableCellCount)
		}

		if _, held := rows[term]; held {
			t.Errorf("the reader returns a row for %q, and it must drop a malformed row rather than read four cells of it", term)
		}
	}

	if _, held := rows["ruling"]; !held {
		t.Errorf("the reader returns no row for %q, and that row holds %d cells", "ruling", termsTableCellCount)
	}

	if slices.Contains(malformed, "ruling") {
		t.Errorf("the reader reports the malformed rows %q, and the row %q holds %d cells", malformed, "ruling", termsTableCellCount)
	}
}

// #428 — every guard of this file reads one named row, and no guard reads the whole table.
// A malformed row therefore reaches a failure through the guard that reads that one term,
// and a malformed row of any other term reached no failure at all.
//
// This test names the defect, so a reader of the failure repairs the table rather than the
// guard that dropped a term. It holds no logic of its own, and the reader above states the
// row that fails.
func TestEveryRowOfTheTermsTableSplitsIntoFourCells(t *testing.T) {
	readTermsTableRows(t)
}

// The word that carries a ruling belongs in the controlled vocabulary, and #379 adds these
// two. A reader of FR-ja4ls-10 looks the words up here.
func TestTheTermsTableDefinesTheOneShotFunctionAndTheMultiPacketMethod(t *testing.T) {
	rows := readTermsTableRows(t)

	for _, term := range []string{oneShotFunctionTerm, multiPacketMethodTerm} {
		row, held := rows[term]
		if !held {
			t.Errorf("the `## Terms` table of %s holds no row for %q, and the ruling of #356 turns on that word", termsTableFile, term)
			continue
		}

		if row.PartOfSpeech != "noun" {
			t.Errorf("the row for %q states the part of speech %q, and both terms are nouns", term, row.PartOfSpeech)
		}

		if row.DoNotUse == "" {
			t.Errorf("the row for %q names no declined synonym, and every one of the other rows of the `## Terms` table names at least one", term)
		}
	}

	if row, held := rows[multiPacketMethodTerm]; held {
		if !strings.Contains(row.Meaning, oneShotFunctionTerm) {
			t.Errorf("the row for %q states the meaning %q, and it must name the term %q that it stands against",
				multiPacketMethodTerm, row.Meaning, oneShotFunctionTerm)
		}
	}
}

// The ruling of #356 — a multi-packet method holds connection state, and an exported
// one-shot function for it would carry that state across the package boundary.
//
// This test reads the method names from the term row, so a method the row later names is
// covered without a change here. `ComputeJA4LS` is the name no other test rejects.
//
// **The ruling of #356 names JA4L and JA4SSH, and it never named JA4LS.** Open question 2
// of `docs/specs/features/12-ja4ls.md` asks whether `ComputeJA4LS` is worth adding, and the
// maintainer answers it. This test blocks the name until then, and it settles nothing.
func TestPackageJa4plusExportsNoOneShotFunctionForAMultiPacketMethod(t *testing.T) {
	rows := readTermsTableRows(t)

	row, held := rows[multiPacketMethodTerm]
	if !held {
		t.Fatalf("the `## Terms` table of %s holds no row for %q", termsTableFile, multiPacketMethodTerm)
	}

	named := methodNamePattern.FindAllString(row.Meaning, -1)
	if len(named) == 0 {
		t.Fatalf("the row for %q names no method, and this test reads the method names from it", multiPacketMethodTerm)
	}

	exported := readExportedPackageNames(t)

	// This test guards the one name that the ruling of #356 never reached, and
	// `parity_one_shot_not_applicable_test.go` guards the two that it did. One name has one
	// home and one reversal instruction, which the cross-member review of this batch asked
	// for. #356 named `generate_ja4l` and `generate_ja4ssh`, so it named JA4L and JA4SSH and
	// it named no JA4LS.
	ruled := map[string]bool{"JA4L": true, "JA4SSH": true}

	for _, method := range named {
		if ruled[method] {
			continue
		}

		name := "Compute" + method
		if exported[name] {
			t.Errorf("package ja4plus exports %q, and %s is a %s. The ruling of #356 never named %s, and open question 2 of docs/specs/features/12-ja4ls.md asks whether to add the name, so the maintainer settles it before you add it",
				name, method, multiPacketMethodTerm, method)
		}
	}
}

// readOneShotFunctionDocComments returns the doc comment of each exported one-shot
// function of package ja4plus, keyed by the function name.
//
// It reads the non-test Go files of the package directory alone. A file of another
// package, a document and a data file each fall outside it.
func readOneShotFunctionDocComments(t *testing.T) map[string]string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}

	docComments := map[string]string{}
	fileSet := token.NewFileSet()

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fileSet, name, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Recv != nil || !function.Name.IsExported() {
				continue
			}

			if !strings.HasPrefix(function.Name.Name, oneShotFunctionPrefix) {
				continue
			}

			docComments[function.Name.Name] = function.Doc.Text()
		}
	}

	return docComments
}

// readmeFile names the page that presents the library to a first reader.
const readmeFile = "README.md"

// readmeOneShotHeading opens the section that holds the one-shot function code block.
const readmeOneShotHeading = "\n### One-Shot Functions\n"

// readmeCallPattern matches one call of an exported one-shot function of package ja4plus.
var readmeCallPattern = regexp.MustCompile(`ja4plus\.(` + oneShotFunctionPrefix + `[A-Za-z0-9]*)\(`)

// readReadmeOneShotBlockNames returns the one-shot function name of each call of the code
// block under the `### One-Shot Functions` heading of `README.md`.
//
// It reads the first fenced block of that section, and it reads no later section. It reads
// a call of a function that carries the one-shot function prefix, so a call of another
// exported function reaches no name of the result.
func readReadmeOneShotBlockNames(t *testing.T) map[string]bool {
	t.Helper()

	page := readRepoFile(t, readmeFile)

	start := strings.Index(page, readmeOneShotHeading)
	if start < 0 {
		t.Fatalf("%s holds no %q heading, and the code block sits under it", readmeFile, "### One-Shot Functions")
	}

	section := page[start+len(readmeOneShotHeading):]
	if end := strings.Index(section, "\n### "); end >= 0 {
		section = section[:end]
	}

	open := strings.Index(section, "```go\n")
	if open < 0 {
		t.Fatalf("the %q section of %s holds no Go code block", "### One-Shot Functions", readmeFile)
	}

	block := section[open+len("```go\n"):]
	if end := strings.Index(block, "```"); end >= 0 {
		block = block[:end]
	}

	names := map[string]bool{}

	for _, match := range readmeCallPattern.FindAllStringSubmatch(block, -1) {
		names[match[1]] = true
	}

	if len(names) == 0 {
		t.Fatalf("the code block of the %q section of %s names no call of package ja4plus", "### One-Shot Functions", readmeFile)
	}

	return names
}

// #403 — the code block listed seven names, and package ja4plus exported ten one-shot
// functions. A reader of the block found no one-shot function for JA4D and for JA4D6, and
// each one exists.
//
// This guard compares the block against the exported set, so a one-shot function that a
// later issue adds or removes fails here until the block states it. It reads the exported
// set that the other guards of this file read, and it holds no list of its own. **Reverse
// it by deleting this test alone**, because no other test of the tree reads the code block.
//
// It states no rule about which method reaches a one-shot function. The ruling of #356
// states that rule, `parity_one_shot_not_applicable_test.go` holds it for JA4L and JA4SSH,
// and `TestPackageJa4plusExportsNoOneShotFunctionForAMultiPacketMethod` above holds it for
// JA4LS.
func TestTheReadmeOneShotBlockNamesEveryExportedOneShotFunction(t *testing.T) {
	exported := readOneShotFunctionDocComments(t)
	if len(exported) == 0 {
		t.Fatalf("package ja4plus exports no %s* function, and this guard then reads nothing", oneShotFunctionPrefix)
	}

	block := readReadmeOneShotBlockNames(t)

	for name := range exported {
		if !block[name] {
			t.Errorf("package ja4plus exports %q, and the code block of the %q section of %s names it nowhere. Add the call to the block",
				name, "### One-Shot Functions", readmeFile)
		}
	}

	for name := range block {
		if _, held := exported[name]; !held {
			t.Errorf("the code block of the %q section of %s names %q, and package ja4plus exports no such %s* function. Remove the call from the block",
				"### One-Shot Functions", readmeFile, name, oneShotFunctionPrefix)
		}
	}
}

// #399 — fourteen sites of the tree wrote a declined synonym for this concept. The
// `Do not use` column of the `one-shot function` row names that synonym. This guard holds
// the repair of the seven sites that are doc comments.
//
// The guard reads the `Do not use` column rather than a list of its own, so a synonym that
// the maintainer declines later is covered without a change here.
//
// **The scope is the doc comment of each exported `Compute*` function of package ja4plus,
// and the guard reads nothing else.** The term row names that concept: it cites
// `ComputeJA4T`, and a doc comment is where the library states the concept to a caller.
// A wider scan reaches the generic English sense of the same words, which the row declines
// for no concept. `internal/parser/ssh.go` carries `ParseKEXINITFromPacket`, which computes
// no fingerprint. The term reaches no such function, and this guard reads no file of that
// package.
//
// **The guard reads no file that another member of batch #402 writes.** It reads the
// package directory of package ja4plus, and it reads `docs/specs/spec.md`.
func TestNoOneShotFunctionDocCommentWritesADeclinedSynonym(t *testing.T) {
	rows := readTermsTableRows(t)

	row, held := rows[oneShotFunctionTerm]
	if !held {
		t.Fatalf("the `## Terms` table of %s holds no row for %q", termsTableFile, oneShotFunctionTerm)
	}

	declined := []string{}

	for _, word := range strings.Split(row.DoNotUse, ",") {
		if word = strings.TrimSpace(word); word != "" {
			declined = append(declined, word)
		}
	}

	if len(declined) == 0 {
		t.Fatalf("the row for %q names no declined synonym, and this guard reads that column", oneShotFunctionTerm)
	}

	docComments := readOneShotFunctionDocComments(t)
	if len(docComments) == 0 {
		t.Fatalf("package ja4plus exports no %s* function, and this guard then reads nothing", oneShotFunctionPrefix)
	}

	for name, docComment := range docComments {
		lowered := strings.ToLower(docComment)

		for _, word := range declined {
			if strings.Contains(lowered, strings.ToLower(word)) {
				t.Errorf("the doc comment of %s writes %q, and the row for %q of the `## Terms` table of %s declines that word. Write %q instead",
					name, word, oneShotFunctionTerm, termsTableFile, oneShotFunctionTerm)
			}
		}
	}
}
