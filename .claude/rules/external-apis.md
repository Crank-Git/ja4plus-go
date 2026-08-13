---
paths:
  - "**/*.go"
  - ".github/workflows/*.yml"
  - "scripts/**"
  - "docs/specs/**/*.md"
---

# External interfaces — read the documentation, never assume

Before you write code against any interface below, confirm the operation name, the
required parameters, the response shape and the error cases from its documentation. Cite
the URL and the version in the pull-request body.

Never describe an external interface from memory. A capability you cannot confirm goes to
`Risks & open questions` in the spec, not into a requirement.

| Interface | Version pinned | Documentation |
|---|---|---|
| FoxIO JA4+ reference | The commit in `testdata/foxio.pin` | <https://github.com/FoxIO-LLC/ja4> |
| FoxIO per-stream vectors | At the pinned commit | <https://github.com/FoxIO-LLC/ja4/tree/main/python/test/testdata> |
| FoxIO per-packet vectors | At the pinned commit | <https://github.com/FoxIO-LLC/ja4/tree/main/wireshark/test/testdata> |
| FoxIO License 1.1 | Read 2026-08-06 at `27f0cbf` | <https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE> |
| `github.com/gopacket/gopacket` | v1.6.1 | <https://pkg.go.dev/github.com/gopacket/gopacket> |
| `golang.org/x/crypto` | v0.37.0 | <https://pkg.go.dev/golang.org/x/crypto> |
| `ja4db.com` read API | Unversioned | <https://ja4db.com> |
| `govulncheck` | Pinned in the workflow | <https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck> |
| `golangci-lint` | Pinned in `.golangci.yml` | <https://golangci-lint.run/usage/configuration/> |
| GitHub Actions workflow syntax | Current | <https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions> |
| Dependabot configuration | Version 2 | <https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference> |

## Protocol specifications

The fingerprint definitions come from FoxIO. The wire formats come from these.

| Protocol | Specification | URL |
|---|---|---|
| GREASE | RFC 8701 | <https://www.rfc-editor.org/rfc/rfc8701> |
| QUIC transport | RFC 9000 | <https://www.rfc-editor.org/rfc/rfc9000> |
| QUIC TLS | RFC 9001 | <https://www.rfc-editor.org/rfc/rfc9001> |
| QUIC version negotiation | RFC 9369 | <https://www.rfc-editor.org/rfc/rfc9369> |
| GRE | RFC 2784 | <https://www.rfc-editor.org/rfc/rfc2784> |
| VXLAN | RFC 7348 | <https://www.rfc-editor.org/rfc/rfc7348> |
| Geneve | RFC 8926 | <https://www.rfc-editor.org/rfc/rfc8926> |
| pcapng | IETF draft | <https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html> |

## Rules for this project

- **The FoxIO reference decides every disputed fingerprint.** When a library test and a
  FoxIO vector disagree, the test is wrong. Never change a vector.
- **The corpus is fetched, never committed.** It is FoxIO-licensed material. The pin in
  `testdata/foxio.pin` keeps the fetch reproducible. Move the pin in a commit that does
  nothing else.
- **`ja4db.com` publishes no versioned API documentation.** Confirm the response shape
  against a live call before you change the response parser, and record the observed shape
  in the issue. Until then, leave the current parser unchanged.
- **Any network call carries a timeout, verifies the server certificate, and bounds the
  response body.** Never use `http.DefaultClient`; it has no timeout.
- **The library reaches the network only from a function whose name says it does.** A
  fingerprint lookup never performs network input or output as a side effect.
- Read-only calls are the safe way to learn the shape of a real response. Confirm anything
  that writes with the user first.
