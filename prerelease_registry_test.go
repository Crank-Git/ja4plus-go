package ja4plus

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The registry of the pre-release cases, and the guards that hold the `prerelease` target.
//
// This file carries no build tag, so `go test ./...` holds the target and the documents.
// `prerelease_test.go` carries the `prerelease` tag, and it holds the cases themselves.
// A reader who moves a guard here into the tagged file removes it from the ordinary gate.

// prereleaseFeatureFile holds the requirements that the registry below covers.
const prereleaseFeatureFile = "docs/specs/features/16-pre-release-validation.md"

// prereleaseCase names one case of `docs/specs/features/16-pre-release-validation.md`.
//
// A case that no issue has built carries `built: false`. The summary of the pre-release
// run names it, so a reader separates an unbuilt case from a case that passed.
type prereleaseCase struct {
	// name states the case in the words of the feature file.
	name string
	// requirements names each requirement the case proves.
	requirements []string
	// issue names the issue that builds the case.
	issue int
	// built states whether the tree holds the case today.
	built bool
}

// prereleaseCases holds one row for each case of the feature set.
//
// #95 built the clean environment on 2026-08-14. #96 built the module install, #97 built
// the published module contents, #98 built the binaries, and #99 built the documentation
// site and the release gate, each on the same day.
//
// A row that reads a published tag reads `v0.3.0`, because this project has cut no tag
// since it. The maintainer ruled that scope on 2026-08-14, at #94: a member writes its
// case against `v0.3.0` and it records each expected failure. So a built row can report a
// failure that the next tag repairs, and `make prerelease` is red until Epic 10 ships one.
//
// **A row that reads no tag does not wait.** The documentation site reads
// `docs/requirements.txt`, and the release gate reads the tracked tree. **Two rows of #99
// wait on something other than a tag, and each one states what.**
var prereleaseCases = []prereleaseCase{
	{
		name:         "the clean environment",
		requirements: []string{"FR-prerelease-1", "FR-prerelease-2", "FR-prerelease-3", "FR-prerelease-4", "FR-prerelease-5"},
		issue:        95,
		built:        true,
	},
	{
		name:         "the module install",
		requirements: []string{"FR-prerelease-6", "FR-prerelease-7", "FR-prerelease-8", "FR-prerelease-9", "FR-prerelease-10", "FR-prerelease-11"},
		issue:        96,
		built:        true,
	},
	{
		name:         "the published module contents",
		requirements: []string{"FR-prerelease-12", "FR-prerelease-13", "FR-prerelease-14", "FR-prerelease-15", "FR-prerelease-16", "FR-prerelease-17"},
		issue:        97,
		built:        true,
	},
	{
		name:         "the binaries",
		requirements: []string{"FR-prerelease-18", "FR-prerelease-19", "FR-prerelease-20", "FR-prerelease-21", "FR-prerelease-22"},
		issue:        98,
		built:        true,
	},
	{
		name:         "the documentation site",
		requirements: []string{"FR-prerelease-23", "FR-prerelease-24", "FR-prerelease-25"},
		issue:        99,
		built:        true,
	},
	{
		name:         "the release gate",
		requirements: []string{"FR-prerelease-27", "FR-prerelease-29", "FR-prerelease-30"},
		issue:        99,
		built:        true,
	},
	// #99 split the two requirements below out of the release gate row on 2026-08-14.
	//
	// The `built` field states one fact for a whole row, and the release gate held five
	// requirements in three states. Three of them run, one waits on a maintainer answer, and
	// one waits on a second epic. One row would have reported all five as one state, and the
	// summary of FR-prerelease-5 exists to separate a case that runs from a case that does
	// not.
	//
	// **The split renumbers no requirement and it reorders no row.** Each requirement of the
	// feature file still reaches exactly one row.
	{
		name:         "the pre-release run before the tag",
		requirements: []string{"FR-prerelease-26"},
		issue:        99,
		built:        false,
	},
	{
		name:         "the mutation sweep report",
		requirements: []string{"FR-prerelease-28"},
		issue:        99,
		built:        false,
	},
}

// TestThePrereleaseRegistryCoversEveryRequirement holds FR-prerelease-5.
//
// `make prerelease` runs every case of the feature set, so the registry names every
// requirement of the feature file. A requirement that reaches no row would run in no case,
// and the summary would report a complete run over an incomplete set.
func TestThePrereleaseRegistryCoversEveryRequirement(t *testing.T) {
	feature := readRepoFile(t, prereleaseFeatureFile)

	declared := []string{}
	for _, match := range regexp.MustCompile(`\*\*(FR-prerelease-\d+)\*\*`).FindAllStringSubmatch(feature, -1) {
		if !slices.Contains(declared, match[1]) {
			declared = append(declared, match[1])
		}
	}

	if len(declared) == 0 {
		t.Fatalf("%s declares no requirement, and the pattern reads no requirement number", prereleaseFeatureFile)
	}

	covered := map[string]int{}
	for _, prereleaseCase := range prereleaseCases {
		for _, requirement := range prereleaseCase.requirements {
			covered[requirement]++
		}
	}

	for _, requirement := range declared {
		switch covered[requirement] {
		case 1:
		case 0:
			t.Errorf("%s declares %s, and no case of the registry names it", prereleaseFeatureFile, requirement)
		default:
			t.Errorf("%d cases of the registry name %s, and one case owns one requirement", covered[requirement], requirement)
		}
	}

	for requirement := range covered {
		if !slices.Contains(declared, requirement) {
			t.Errorf("the registry names %s, and %s declares no such requirement", requirement, prereleaseFeatureFile)
		}
	}
}

// TestThePrereleaseRegistryNamesTheCaseThisSliceBuilt holds FR-prerelease-1 through
// FR-prerelease-4 against the registry.
//
// A row that reports a case as built while the tree holds no case is the failure this
// guard prevents.
//
// **Every member of Epic 16 edits the list below, and that is by construction.** A member
// that builds its case adds the name of the case here, in the order the registry states.
// Each member appends its own name and it moves no other name, and the project manager
// resolves the union at the sub-merge.
//
// **The comparison reads equality over one shared slice, so every append conflicts.** A set
// comparison would not, and no member changes the shape of this guard to avoid the conflict.
//
// **The project manager resolved three such merges on 2026-08-14**: #97 against #98, that
// result against #99, and that result against #96. #95 built the clean environment, #96
// built the module install, #97 built the published module contents, #98 built the
// binaries, and #99 built the documentation site and the release gate.
//
// **Six rows of the registry are built, and two are not.** `the pre-release run before the
// tag` waits on the maintainer answer that #633 carries, and `the mutation sweep report`
// waits on Epic #89. **So this list holds six names and the registry holds eight rows**, and
// a reader who counts one against the other reads no disagreement.
func TestThePrereleaseRegistryNamesTheCaseThisSliceBuilt(t *testing.T) {
	built := []string{}
	for _, prereleaseCase := range prereleaseCases {
		if prereleaseCase.built {
			built = append(built, prereleaseCase.name)
		}
	}

	expected := []string{
		"the clean environment",         // #95
		"the module install",            // #96
		"the published module contents", // #97
		"the binaries",                  // #98
		"the documentation site",        // #99
		"the release gate",              // #99
	}

	if !slices.Equal(built, expected) {
		t.Errorf("the registry reports %v as built, and the tree holds %v", built, expected)
	}
}

// TestTheMakefileRunsThePrereleaseCases holds FR-prerelease-5.
//
// `prerelease` is not a directory of this repository today, so make would find no file of
// that name and would run the recipe. A later commit that adds such a directory would stop
// the target, and the `.PHONY` entry holds the recipe against that. `make docs` records
// the same defect, and `TestTheMakefileBuildsTheSite` holds that entry.
func TestTheMakefileRunsThePrereleaseCases(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")

	phony := regexp.MustCompile(`(?m)^\.PHONY:(.*)$`).FindStringSubmatch(makefile)
	if phony == nil {
		t.Fatal("the Makefile states no .PHONY line")
	}
	if !slices.Contains(strings.Fields(phony[1]), "prerelease") {
		t.Errorf(".PHONY names [%s], and it does not name prerelease", strings.TrimSpace(phony[1]))
	}

	if !regexp.MustCompile(`(?m)^prerelease:\s*$`).MatchString(makefile) {
		t.Fatal("the Makefile holds no prerelease recipe")
	}

	recipe := makefileRecipe(t, "prerelease")
	if !strings.Contains(recipe, "-tags prerelease") {
		t.Errorf("the prerelease recipe does not select the prerelease build tag:\n%s", recipe)
	}
	if !strings.Contains(recipe, "-count=1") {
		t.Errorf("the prerelease recipe does not defeat the test cache, so a cached run builds no clean environment:\n%s", recipe)
	}
	if !strings.Contains(recipe, "-v") {
		t.Errorf("the prerelease recipe is not verbose, so the run prints no summary:\n%s", recipe)
	}
}

// TestTheCommandsTableStatesThatThePrereleaseTargetIsBuilt holds the `## Commands` table
// of `CLAUDE.md` against the Makefile.
//
// #95 added the target on 2026-08-14. A table that still calls it absent sends a reader to
// a target that runs, and the reader then reads an exit status the target never returns.
// This guard reads the `prerelease` row alone, because #90 owns the `mutate` row.
func TestTheCommandsTableStatesThatThePrereleaseTargetIsBuilt(t *testing.T) {
	claude := readRepoFile(t, "CLAUDE.md")

	row := ""
	for _, line := range strings.Split(claude, "\n") {
		if strings.HasPrefix(line, "| `make prerelease` |") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("CLAUDE.md holds no `make prerelease` row in the Commands table")
	}
	if strings.Contains(row, "Not built yet") {
		t.Errorf("the Commands table calls the prerelease target absent, and the Makefile defines it:\n%s", row)
	}

	for _, claim := range []string{
		"defines neither `mutate` nor `prerelease`",
		"`make mutate` and `make prerelease` each exit 2",
	} {
		if strings.Contains(claude, claim) {
			t.Errorf("CLAUDE.md states %q, and the Makefile defines the prerelease target", claim)
		}
	}
}

// TestTheFeatureFileNamesThePrereleaseBuildTag holds the `Data touched` table of the
// feature file against the tree.
//
// The feature file names `prerelease_test.go` and the `prerelease` build tag. A reader who
// looks for the cases must find them where the design says they are.
func TestTheFeatureFileNamesThePrereleaseBuildTag(t *testing.T) {
	feature := readRepoFile(t, prereleaseFeatureFile)

	for _, target := range []string{"`prerelease_test.go`", "Build tag `prerelease`"} {
		if !strings.Contains(feature, target) {
			t.Errorf("%s names no %s, and this slice built the file it describes", prereleaseFeatureFile, target)
		}
	}

	source := readRepoFile(t, "prerelease_test.go")
	if !strings.HasPrefix(source, "//go:build prerelease\n") {
		t.Errorf("prerelease_test.go opens with %q, and the feature file names the prerelease build tag",
			fmt.Sprintf("%.30s", source))
	}
}
