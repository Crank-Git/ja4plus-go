package ja4plus

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/repofile"
)

// The two publish workflows of Epic 14 hold ten requirements, and no Go code reads either
// file. So no compiler and no linter of this repository sees a change to one, and a silent
// edit removes a requirement without a message.
//
// The tests below read each file as text and hold one requirement each. They read the
// files as text rather than as YAML, because this module declares no YAML dependency.
// `mkdocs_config_test.go` states the same reading for `mkdocs.yml`.
//
// **A test of this file proves the shape of a workflow, and it proves no run.** Every
// commit of batch #83 carries `[skip ci]`, and this epic merges to `dev`. So no run of
// either workflow exists, and #88 claims none.

// TestTheDocsBuildWorkflowRunsOnEveryPullRequest holds FR-documentation-33.
//
// The trigger carries no branch filter. `.github/workflows/ci.yml` filters on three
// branches, and a copy of that filter here would skip a pull request into an integration
// branch. Such a pull request also changes a page.
func TestTheDocsBuildWorkflowRunsOnEveryPullRequest(t *testing.T) {
	workflow := readRepoFile(t, repofile.DocsBuildWorkflow)

	if !regexp.MustCompile(`(?m)^\s{2}pull_request:\s*$`).MatchString(workflow) {
		t.Fatal("FR-documentation-33 states that docs-build.yml runs on every pull request")
	}
	if regexp.MustCompile(`(?m)^\s+branches:`).MatchString(workflow) {
		t.Error("FR-documentation-33 names every pull request, and this file holds a branch filter")
	}
}

// TestTheDocsBuildWorkflowUploadsTheArtifactWhenTheCallerAsks holds FR-documentation-30.
func TestTheDocsBuildWorkflowUploadsTheArtifactWhenTheCallerAsks(t *testing.T) {
	workflow := readRepoFile(t, repofile.DocsBuildWorkflow)

	if !regexp.MustCompile(`(?m)^\s{2}workflow_call:\s*$`).MatchString(workflow) {
		t.Fatal("FR-documentation-30 states that a caller builds the site through this workflow")
	}
	if !strings.Contains(workflow, "actions/upload-pages-artifact@") {
		t.Error("FR-documentation-30 states that this workflow uploads the site artifact")
	}
	if !strings.Contains(workflow, "if: inputs.upload-artifact") {
		t.Error("FR-documentation-30 states that the upload answers the caller, and no condition reads the input")
	}
	if !strings.Contains(workflow, "run: make docs") {
		t.Error("the build runs `make docs`, so the runner and a developer build with one command")
	}
}

// countPermissionLines counts the lines of the workflow that grant the permission.
//
// The count reads a YAML line and never a comment. A comment of either workflow quotes the
// permission name, and a text count would read that quotation as a grant.
func countPermissionLines(t *testing.T, workflow, permission string) int {
	t.Helper()
	line := regexp.MustCompile(`(?m)^[ \t]+` + regexp.QuoteMeta(permission) + `[ \t]*$`)
	return len(line.FindAllString(workflow, -1))
}

// TestTheDocsBuildWorkflowPublishesNothing holds FR-documentation-33.
func TestTheDocsBuildWorkflowPublishesNothing(t *testing.T) {
	workflow := readRepoFile(t, repofile.DocsBuildWorkflow)

	if strings.Contains(workflow, "actions/deploy-pages@") {
		t.Error("FR-documentation-33 states that docs-build.yml publishes nothing, and it names the deploy action")
	}
	for _, permission := range []string{"pages: write", "id-token: write"} {
		if countPermissionLines(t, workflow, permission) != 0 {
			t.Errorf("FR-documentation-33 states that docs-build.yml publishes nothing, and it grants %q", permission)
		}
	}
}

// TestTheDocsPublishWorkflowRunsOnAPushToMaster holds FR-documentation-31.
func TestTheDocsPublishWorkflowRunsOnAPushToMaster(t *testing.T) {
	workflow := readRepoFile(t, repofile.DocsPublishWorkflow)

	if !regexp.MustCompile(`(?m)^\s{2}push:\s*$`).MatchString(workflow) {
		t.Fatal("FR-documentation-31 states that docs.yml publishes on a push")
	}
	if !regexp.MustCompile(`(?m)^\s+branches:\s*\[master\]\s*$`).MatchString(workflow) {
		t.Error("FR-documentation-31 names a push to master, and no branch filter names it")
	}
}

// TestTheDocsPublishWorkflowCallsTheBuildWorkflow holds FR-documentation-32.
func TestTheDocsPublishWorkflowCallsTheBuildWorkflow(t *testing.T) {
	workflow := readRepoFile(t, repofile.DocsPublishWorkflow)

	if !strings.Contains(workflow, "uses: ./"+repofile.DocsBuildWorkflow) {
		t.Errorf("FR-documentation-32 states that docs.yml calls %s", repofile.DocsBuildWorkflow)
	}
	// A second build recipe would publish a site that no pull request ever built.
	for _, recipe := range []string{"mkdocs build", "make docs", "requirements.txt"} {
		if strings.Contains(workflow, recipe) {
			t.Errorf("FR-documentation-32 bars a second build recipe, and docs.yml holds %q", recipe)
		}
	}
}

// TestTheDocsPublishWorkflowReadsThePagesSettingFirst holds FR-documentation-34.
//
// The message of each failure branch names the repair. The edge-case table of
// `docs/specs/features/14-documentation.md` states that a status other than 200 or 404
// fails the run, prints the status and the body, and claims nothing about the setting.
func TestTheDocsPublishWorkflowReadsThePagesSettingFirst(t *testing.T) {
	workflow := readRepoFile(t, repofile.DocsPublishWorkflow)

	if !strings.Contains(workflow, "  pages-setting:") {
		t.Fatal("FR-documentation-34 states that docs.yml reads the Pages setting")
	}
	if !strings.Contains(workflow, "/repos/$GITHUB_REPOSITORY/pages") {
		t.Error("FR-documentation-34 reads the Pages setting, and no step calls the Pages endpoint")
	}
	if !strings.Contains(workflow, "needs: pages-setting") {
		t.Error("FR-documentation-34 states that the read comes first, and no job waits for it")
	}
	if !strings.Contains(workflow, `if [ "$status" = "404" ]`) {
		t.Error("the 404 case states that Pages is off, and no branch separates it")
	}
	if !strings.Contains(workflow, `if [ "$status" != "200" ]`) {
		t.Error("a status other than 200 and 404 fails the run, and no branch separates it")
	}
	// The message escapes each quotation mark for the shell, so the test reads the part of
	// the sentence that carries no quotation mark.
	if strings.Count(workflow, "The repair: open Settings, click Pages under") < 2 {
		t.Error("FR-documentation-34 names the repair, and a failure branch states it without the setting")
	}
}

// TestTheDeployJobAloneHoldsThePagesPermissions holds FR-documentation-35.
//
// The two workflows are the whole publish path, so the count reads both files.
func TestTheDeployJobAloneHoldsThePagesPermissions(t *testing.T) {
	publish := readRepoFile(t, repofile.DocsPublishWorkflow)
	build := readRepoFile(t, repofile.DocsBuildWorkflow)

	for _, permission := range []string{"pages: write", "id-token: write"} {
		count := countPermissionLines(t, publish, permission) + countPermissionLines(t, build, permission)
		if count != 1 {
			t.Errorf("FR-documentation-35 gives %q to the deploy job alone, and the two workflows grant it %d times",
				permission, count)
		}
	}

	_, deploy, found := strings.Cut(publish, "\n  deploy:\n")
	if !found {
		t.Fatal("FR-documentation-35 names the deploy job, and docs.yml holds no such job")
	}
	for _, permission := range []string{"pages: write", "id-token: write"} {
		if countPermissionLines(t, deploy, permission) != 1 {
			t.Errorf("FR-documentation-35 states that the deploy job grants %q", permission)
		}
	}
}

// TestOneDeploymentRunsAtATime holds FR-documentation-36.
func TestOneDeploymentRunsAtATime(t *testing.T) {
	workflow := readRepoFile(t, repofile.DocsPublishWorkflow)

	if !regexp.MustCompile(`(?m)^concurrency:\s*$`).MatchString(workflow) {
		t.Fatal("FR-documentation-36 runs one deployment at a time, and docs.yml holds no concurrency block")
	}
	if !regexp.MustCompile(`(?m)^\s+group:\s+pages\s*$`).MatchString(workflow) {
		t.Error("FR-documentation-36 needs one concurrency group, and the block names none")
	}
	if !regexp.MustCompile(`(?m)^\s+cancel-in-progress:\s+false\s*$`).MatchString(workflow) {
		t.Error("FR-documentation-36 cancels no run in progress, and cancel-in-progress is not false")
	}
}

// TestEveryActionReferenceIsPinnedToACommitHash holds FR-documentation-37.
//
// A local reusable workflow carries no ref, and it is no action reference. The reusable
// workflow reference states that `./.github/workflows/{filename}` reads the called workflow
// from the commit of the caller, so a hash there names nothing new.
func TestEveryActionReferenceIsPinnedToACommitHash(t *testing.T) {
	pinned := regexp.MustCompile(`^[\w.-]+/[\w.-]+(/[\w.-]+)*@[0-9a-f]{40}$`)
	usesLine := regexp.MustCompile(`(?m)^\s*(?:- )?uses:\s+(\S+)`)

	for _, path := range []string{repofile.DocsBuildWorkflow, repofile.DocsPublishWorkflow} {
		workflow := readRepoFile(t, path)
		matches := usesLine.FindAllStringSubmatch(workflow, -1)
		if len(matches) == 0 {
			t.Errorf("%s names no action and no workflow", path)
			continue
		}
		for _, match := range matches {
			reference := match[1]
			if strings.HasPrefix(reference, "./") {
				continue
			}
			if !pinned.MatchString(reference) {
				t.Errorf("FR-documentation-37 pins every action reference to a commit hash, and %s holds %q",
					path, reference)
			}
		}
	}
}

// TestTheSiteURLAndTheReadmeLinkNameOneAddress holds FR-documentation-38 and
// FR-documentation-39.
//
// #84 wrote the `site_url` of `mkdocs.yml`, and #85 wrote the README link. This test reads
// both against one value, so a later move of the address cannot leave one of them behind.
func TestTheSiteURLAndTheReadmeLinkNameOneAddress(t *testing.T) {
	config := readRepoFile(t, repofile.MkdocsConfigPath)
	if !strings.Contains(config, "site_url: "+repofile.DocumentationSiteURL) {
		t.Errorf("FR-documentation-38 states that the site URL is %s", repofile.DocumentationSiteURL)
	}

	readme := readRepoFile(t, "README.md")
	if !strings.Contains(readme, repofile.DocumentationSiteURL) {
		t.Errorf("FR-documentation-39 states that the README links to %s", repofile.DocumentationSiteURL)
	}
}
