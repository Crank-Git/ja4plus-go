---
name: docs
description: Build and preview the ja4plus-go documentation site locally, and check it before a push. Use when asked about the docs site, GitHub Pages, mkdocs, a broken link, a method page, or publishing documentation.
allowed-tools: Bash, Read, Edit, Glob
---

# Build the documentation site

The site is MkDocs with the Material theme. GitHub Pages serves it at
`https://crank-git.github.io/ja4plus-go/`. `docs/specs/features/14-documentation.md` holds
the requirements.

## 1. Install the pinned generator

```
python3 -m venv .venv-docs && .venv-docs/bin/pip install -r docs/requirements.txt
```

**Every version is pinned in `docs/requirements.txt`.** A generator release has broken this
build before. Bump a pin in a commit that does nothing else.

## 2. Build

```
make docs
```

That runs `mkdocs build --strict`.

**A warning fails the build.** `strict: true` and the `validation` block in `mkdocs.yml`
carry that together, and neither one carries it alone. `strict: true` alone does not catch
a dead anchor.

## 3. Preview

```
.venv-docs/bin/mkdocs serve
```

Read the page you changed at `http://127.0.0.1:8000`.

## What the build refuses

| Failure | The repair |
|---|---|
| A broken internal link. | Fix the link. A rename breaks every link into the page. |
| A dead anchor. | Read the heading. The slug follows the GitHub form, not the Python-Markdown default. |
| A page under `docs/` that no `nav` entry names. | Add the `nav` entry, or move the file out of `docs/`. |
| A link into `docs/specs/` or `docs/audit/`. | Both are excluded. Link to the repository instead. |

## What the site does not publish

- `docs/specs/` — the spec package. It is design material and it links outside `docs_dir`,
  so a strict build could never resolve it.
- `docs/audit/` — the findings report and the recorded decisions.

## The page set

One page per method. **Eleven methods reach eleven pages**, because `JA4LFingerprinter`
writes both JA4L and JA4LS and each holds its own page. Plus the home page, the usage
guide, the output schema, concurrency, live capture, packet throughput, the API reference,
licensing, implementation notes and the mutation sweep.

**The API reference is hand-written and links to `pkg.go.dev`.** Go already publishes a
generated surface from the same doc comments. Do not add a second generator; a second copy
drifts. Explain the contract here, and link out for the signature.

## Publishing

- A push to `dev` builds the site and publishes nothing.
- A push to `master` publishes it.
- `.github/workflows/docs.yml` owns no build steps. It calls `docs-build.yml`, because two
  recipes for one site drift apart.

**GitHub Pages must be set to build from GitHub Actions**, and that setting is not a file
in the repository. The workflow reads the setting first and fails with a message that names
the repair.

## Before you push a page change

1. `make docs` succeeds.
2. `go test -run Example ./...` passes, when the page holds a Go sample.
3. Every method count on the page reads eleven methods and ten fingerprinters.
