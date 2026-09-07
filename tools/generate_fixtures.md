# Refreshing the Trivy fixtures (Phase B — executed 2026-08-05)

**Phase B is done.** `contracts/trivy-input.md` is now labelled VERIFIED against Trivy
0.73.0, and `tests/fixtures/trivy/real_*.json` hold output that Trivy really produced.
Every field assumption held; see the results table in that contract.

The other `tests/fixtures/trivy/*.json` remain hand-authored on purpose. They cover
shapes real scans do not conveniently produce — truncated JSON, a valid document with no
`Results`, duplicate CVEs across packages — and they are still the right tool for those
cases. The `real_*.json` fixtures are what pin the field names.

This document stays as the procedure for **re-verifying against a future Trivy release**.

## Why this is confined to one module

Every Trivy-shaped assumption lives in `src/trivy_report/trivy_parser.py` and nowhere
else (research D12). Nothing downstream of `normalize.py` knows Trivy's field names. A
wrong assumption therefore costs one module plus a fixture refresh, not a rewrite.

## Procedure

Generate real output from two different base images, so both an OS-package ecosystem and
a language ecosystem are represented. Trivy runs as a container — no local binary needed.
Mount a cache volume or every scan re-downloads the ~100 MB vulnerability DB:

```bash
mkdir -p out
docker run --rm -v trivy-cache:/root/.cache/trivy -v "$PWD/out:/out" \
  aquasec/trivy:latest image --format json --output /out/alpine.json alpine:3.20
docker run --rm -v trivy-cache:/root/.cache/trivy -v "$PWD/out:/out" \
  aquasec/trivy:latest image --skip-db-update --format json --output /out/node.json node:18-slim
```

`node:18-slim` is the useful second target: it yields `os-pkgs` (debian) **and**
`lang-pkgs` (node-pkg) in one document, which is what exercises the two-`Results`-block
path. To reproduce the `Class: "secret"` exclusion check, build a throwaway image
containing a dummy key and add `-v /var/run/docker.sock:/var/run/docker.sock` — that
mount is needed only for locally built images, not for registry pulls.

Then verify each assumption:

1. Confirm every field listed as "consumed" in `contracts/trivy-input.md` exists with the
   expected name, casing, and type.
2. Note the observed `SchemaVersion` values and **pin the accepted range** in
   `trivy_parser.py`. This is the one deliberate looseness in the contract: the parser
   currently checks presence and numeric type only, because gating on a guessed value
   risks rejecting valid production output.
3. Confirm the `Class` values observed match the result-class table (`os-pkgs`,
   `lang-pkgs` counted; `secret`, `config`, `license` excluded).
4. Confirm a clean image really omits or nulls `Vulnerabilities` rather than emitting
   `[]`. All three are handled, but the fixture should match reality.
5. Confirm `PkgPath` appears for language ecosystems and is absent or empty for OS
   packages.
6. Refresh `tests/fixtures/trivy/*.json` from the real output, trimmed to the consumed
   fields plus a couple of ignored ones — keeping a few ignored fields is what proves
   they stay harmless.
7. Correct `trivy_parser.py` if any assumption was wrong, and record the correction in
   `specs/001-trivy-vuln-reports/research.md` under D12.

## After the refresh

- Update the status banner in `contracts/trivy-input.md` with the observed Trivy version
  and the results table. *(Done for 0.73.0.)*
- Add the observed value to `OBSERVED_SCHEMA_VERSIONS` in `trivy_parser.py`. Do **not**
  turn it into a hard gate; the reasoning is in that contract's `SchemaVersion` section.
- Update the corresponding row in `plan.md` § Complexity Tracking.
- The full suite must still pass **offline** afterwards, with the container runtime
  stopped: fixtures are committed precisely so Trivy is never required to run the tests
  (constitution Principle VII). This is the check that matters most after a refresh — it
  is easy to leave a test that silently depends on a running daemon.

## Fixture inventory

| Fixture | Represents |
|---------|-----------|
| `clean_no_vulns.json` | Clean image — `Vulnerabilities` omitted entirely. Zero findings, **not** a failure |
| `mixed_severities.json` | All four rated severities present |
| `multi_result_os_and_lang.json` | Two `Results` blocks: `os-pkgs` and `lang-pkgs` |
| `unknown_severity.json` | Absent, empty, and unrecognised `Severity` values → UNKNOWN bucket |
| `duplicate_cve_two_packages.json` | Same CVE at two `PkgName`; same `(CVE, PkgName)` at two `PkgPath`; one exact repeat |
| `secret_and_license_classes.json` | `secret`, `config`, `license` classes — must be excluded from counts |
| `malformed_truncated.json` | Unterminated JSON → `MALFORMED_JSON` |
| `valid_json_wrong_schema.json` | Valid JSON, no `Results` → `SCHEMA_MISMATCH`, **never** zero vulnerabilities |

### Real output (Trivy 0.73.0, Phase B)

| Fixture | Source | Pins |
|---------|--------|------|
| `real_alpine_clean.json` | `alpine:3.20` | A clean image omits `Vulnerabilities` **entirely** — not `null`, not `[]` |
| `real_node_os_and_lang.json` | `node:18-slim` | `os-pkgs` + `lang-pkgs` in one document; `PkgPath` present only for lang; real `UNKNOWN` severities |
| `real_secret_class.json` | throwaway image with a dummy private key | A real `Class: "secret"` finding at `Severity: HIGH` that must not reach the counts |
