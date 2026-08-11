---
id: documentation
feature: Documentation site
epic: "Epic 14: Documentation site"
status: planned
issues: []
mockups: [mockups/04-docs-site.html]
---

## Purpose

The port publishes a documentation site to GitHub Pages. This project publishes a README
and nothing else. A user who reads one repository and then the other finds a manual on one
side and a single long file on the other.

This feature set builds the same site here: the same generator, the same theme, the same
navigation shape and the same page set. A reader moves between the two without relearning
where anything is.

**The API reference is the one page that differs, and the reason is Go.** The port
generates its reference from docstrings with `mkdocstrings`. Go already publishes a
canonical API surface at `pkg.go.dev`, built from the same doc comments by the module
proxy. A second generated copy would drift, and a drift check would cost more than the
pages are worth. The site therefore holds a hand-written reference that explains the
types and links to `pkg.go.dev` for the signatures.

## User stories

- As a library author, I want a usage guide with runnable examples, so that I do not read
  the tests to learn the interface.
- As an analyst, I want one page per method that states what the fingerprint means, so
  that I can read a value.
- As a library author, I want the concurrency contract on its own page, so that I find it
  before I share a `Processor`.
- As a user who reads both libraries, I want the same navigation, so that I find the same
  page in the same place.
- As a maintainer, I want a broken internal link to fail the build, so that a rename does
  not publish a dead page.

## Functional requirements

### The generator

- **FR-documentation-1** — The site is built with MkDocs and the Material theme.
- **FR-documentation-2** — `mkdocs.yml` sits at the repository root.
- **FR-documentation-3** — `docs_dir` is `docs/`.
- **FR-documentation-4** — `strict: true` is set, so a warning fails the build.
- **FR-documentation-5** — The `validation` block raises a broken link and a broken anchor
  to a warning.
- **FR-documentation-6** — `docs/specs/` is excluded from the site. It is design material
  and it links outside `docs_dir`.
- **FR-documentation-7** — `docs/audit/` is excluded, for the same reason.
- **FR-documentation-8** — Every generator version is pinned in one file.
- **FR-documentation-9** — The theme offers a light palette and a dark palette.
- **FR-documentation-10** — The table-of-contents slug matches the GitHub slug, so one
  link resolves in both readers.

### The pages

- **FR-documentation-11** — The site holds a home page.
- **FR-documentation-12** — The site holds a usage guide.
- **FR-documentation-13** — The site holds an output-schema page.
- **FR-documentation-14** — The site holds a concurrency page.
- **FR-documentation-15** — The site holds a packet-throughput page.
- **FR-documentation-16** — The site holds a live-capture page.
- **FR-documentation-17** — The site holds one page per method. **Eleven methods reach
  eleven pages**, because JA4L and JA4LS each hold one.
- **FR-documentation-18** — `docs/methods/index.md` states the method count and names the
  methods this project does not implement.
- **FR-documentation-19** — The site holds an API-reference section.
- **FR-documentation-20** — Each API-reference page links to the matching `pkg.go.dev`
  anchor.
- **FR-documentation-21** — The site holds an implementation-notes page.
- **FR-documentation-22** — The site holds a licensing page that states the FoxIO terms.
- **FR-documentation-23** — Every page listed above appears in the navigation.
- **FR-documentation-24** — A page under `docs_dir` that no navigation entry names fails
  the build.

### The examples

- **FR-documentation-25** — The repository holds an `examples/` directory.
- **FR-documentation-26** — Each example is a runnable Go program.
- **FR-documentation-27** — `go build ./examples/...` gates every pull request.
- **FR-documentation-28** — Every Go code sample in `docs/` appears in `example_test.go`
  as a testable example.
- **FR-documentation-29** — A test asserts that every fenced Go block of `docs/` matches a
  block in `example_test.go`.

### The publish

- **FR-documentation-30** — `.github/workflows/docs-build.yml` builds the site and uploads
  the artifact when the caller asks.
- **FR-documentation-31** — `.github/workflows/docs.yml` publishes to GitHub Pages on a
  push to `master`.
- **FR-documentation-32** — `docs.yml` calls `docs-build.yml` and holds no second build
  recipe.
- **FR-documentation-33** — `docs-build.yml` runs on every pull request and publishes
  nothing.
- **FR-documentation-34** — `docs.yml` reads the Pages setting first and fails with a
  message that names the repair.
- **FR-documentation-35** — The deploy job holds `pages: write` and `id-token: write`, and
  no other job holds either.
- **FR-documentation-36** — One deployment runs at a time, and a run in progress is not
  cancelled.
- **FR-documentation-37** — Every action reference is pinned to a commit hash.
- **FR-documentation-38** — The site URL is `https://crank-git.github.io/ja4plus-go/`.
- **FR-documentation-39** — The README links to the site.

## User flows

### A reader finds the concurrency contract

1. The reader opens the site.
2. The reader selects `Concurrency` in the navigation.
3. The page states the one-processor-one-goroutine rule, `GetShardKey` and
   `SyncProcessor`, with a runnable example.

### A maintainer publishes a change

1. The maintainer merges a batch into `dev`. `docs-build.yml` builds the site and
   publishes nothing.
2. The maintainer promotes `dev` to `master`.
3. `docs.yml` reads the Pages setting, calls the build, and deploys the artifact.
4. The site serves the change.

### An engineer renames a page

1. The engineer renames the file and misses one link.
2. `mkdocs build --strict` reports a warning and fails.
3. The pull request is red before it reaches `master`.

## Screens & states

`mockups/04-docs-site.html` shows the navigation shape, the light palette and the dark
palette, and one method page.

| State | What the reader sees |
|---|---|
| Site home | The overview, the install command, and the eleven-method statement. |
| A method page | The form, one example value, and what each part means. |
| The API reference | The type, its contract, and a link to `pkg.go.dev`. |
| A build failure | Nothing is published. The old site stays served. |

## Behaviour rules

- **Two recipes for one site drift apart.** `docs.yml` owns no build steps of its own, and
  a change to the build lands in one file.
- **A warning is a failure.** `strict: true` alone does not catch a dead anchor, so the
  `validation` block raises it.
- **The site publishes from the live branch alone.** A push to `dev` builds and publishes
  nothing.
- **The site holds no design material.** `docs/specs/` and `docs/audit/` are excluded, and
  a reader who wants them reads the repository.
- **`pkg.go.dev` is the API surface.** The site explains and links; it does not copy
  signatures that the proxy already publishes.

## Data touched

| File | Change |
|---|---|
| `mkdocs.yml` | New. |
| `docs/README.md`, `docs/usage.md`, `docs/output-schema.md`, `docs/concurrency.md`, `docs/performance.md`, `docs/live-capture.md`, `docs/implementation_notes.md`, `docs/licensing.md` | New. |
| `docs/methods/index.md` and eleven method pages | New. |
| `docs/reference/` | New. The hand-written API pages. |
| `docs/requirements.txt` | New. The pinned generator versions. |
| `examples/` | New. |
| `example_test.go` | New. |
| `.github/workflows/docs-build.yml`, `.github/workflows/docs.yml` | New. |
| `README.md` | Links to the site. |
| `.gitignore` | Ignores `site/`. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| MkDocs | 1.6 | <https://www.mkdocs.org/user-guide/configuration/> |
| Material for MkDocs | 9.7.7 | <https://squidfunk.github.io/mkdocs-material/> |
| `actions/deploy-pages` | v5.0.0 | <https://github.com/actions/deploy-pages/tree/v5.0.0> |
| `actions/upload-pages-artifact` | v5.0.0 | <https://github.com/actions/upload-pages-artifact/tree/v5.0.0> |
| GitHub Pages REST API | 2022-11-28 | <https://docs.github.com/en/rest/pages/pages> |
| `pkg.go.dev` | Current | <https://pkg.go.dev/github.com/Crank-Git/ja4plus-go> |

Retrieved 2026-08-11. **The versions above are the ones the port pinned on 2026-08-10**,
and this project reads the same documentation before it pins its own.

**GitHub Pages must be set to build from GitHub Actions**, and that setting is not a file
in the repository. FR-documentation-34 makes a wrong setting a red run with a named
repair, because the port found that a silent misconfiguration published nothing for two
days.

## Edge cases & failures

| Case | Expected behaviour |
|---|---|
| GitHub Pages is not enabled. | FR-documentation-34 fails the run and names the setting to change. |
| The Pages API answers a status other than 200 or 404. | The run fails and prints the status and the body. The message does not claim Pages is off. |
| A page links to `docs/specs/`. | The build fails, because the directory is excluded. |
| A generator release breaks the build. | The pins in `docs/requirements.txt` hold. A bump is a commit that does nothing else. |
| A code sample in `docs/` does not compile. | FR-documentation-29 fails. |
| Two pushes to `master` arrive together. | FR-documentation-36 runs one deployment and queues the second. |
| A method page is added and the navigation is not. | FR-documentation-24 fails the build. |

## Acceptance criteria

1. `mkdocs build --strict` succeeds from a clean environment that holds only
   `docs/requirements.txt`.
2. The site holds eleven method pages, and `docs/methods/index.md` states eleven methods
   and ten fingerprinters.
3. A deliberately broken internal link fails the build.
4. A page under `docs_dir` that no navigation entry names fails the build.
5. A push to `master` publishes the site, and the URL serves the change.
6. A push to `dev` builds the site and publishes nothing.
7. `go build ./examples/...` succeeds.
8. `go test -run Example ./...` passes.
9. Every action reference in both workflows is a commit hash.
10. The README links to the site, and the site links to the repository.

## Out of scope

- A generated API reference. `pkg.go.dev` is the generated surface.
- Versioned documentation. The site serves the live branch alone.
- A search index other than the theme's own.
- Translating any page.
- Publishing `docs/specs/` or `docs/audit/`.

## Open questions

1. **Does a Python toolchain in CI belong in a Go repository?** The maintainer accepted it
   on 2026-08-11, because the site matches the port and no Go generator produces the same
   pages. The cost is one job that installs pinned Python packages, and it gates
   documentation alone.
2. **Should `docs/README.md` and the repository `README.md` be one file?** The port keeps
   two. Two files drift; one file must serve two very different readers.
