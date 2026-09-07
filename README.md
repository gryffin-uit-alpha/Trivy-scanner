# trivy-report

Turns Trivy JSON scan results into Markdown vulnerability reports with day-over-day
trend indicators.

This application handles **business logic only**. Repository checkout, image discovery,
Trivy invocation, scanner cache management, artifact publishing, and all credential
handling belong to the CI/CD pipeline. It reads files the pipeline produced and writes
files the pipeline publishes — it never shells out to `git`, `kubectl`, `docker`, or
`trivy`, and never authenticates to a registry.

## Install

```bash
pip install -e ".[dev]"
```

Zero runtime dependencies — the standard library only. `pytest` and `ruff` are
development dependencies and are not imported by anything under `src/`.

## Run

```bash
trivy-report \
  --input       ./trivy-results \
  --manifest    ./trivy-results/manifest.json \
  --history-dir ./scan-history \
  --output-dir  ./reports \
  --scan-date   2026-08-05
```

Equivalent: `python -m trivy_report <same args>`.

Produces `reports/overall.md` (fleet-wide, grouped by repository) and
`reports/repositories/<repo>.md` (one per repository). The names are fixed and
date-free, so the pipeline publishes from a static path; the scan date lives inside
the documents.

### Options

| Option | Required | Default | Meaning |
|--------|----------|---------|---------|
| `--input DIR` | yes | — | Directory of Trivy JSON results. Read-only; never modified. Must exist. |
| `--manifest FILE` | yes | — | Sidecar manifest mapping each result file to a repository and image. Must exist and validate. |
| `--history-dir DIR` | yes | — | Dated history files. Created if absent. Read for the baseline, written at the end. |
| `--output-dir DIR` | yes | — | Where reports are written. Created if absent, along with `repositories/`. |
| `--scan-date DATE` | no | manifest `scan_date` | Logical scan date, `YYYY-MM-DD`. **The system clock is never consulted** — that is what makes the output reproducible. |
| `--retention-days N` | no | `90` | History retention window, inclusive of the scan date itself. Minimum `1`. Files whose names are not `YYYY-MM-DD.json` are never touched. |
| `--fail-on SEV=N` | no | none | Exit `3` when the unique-image grand total for `SEV` reaches `N`. Repeatable. `SEV` ∈ `CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN`. Without it, exit `3` is impossible. |
| `--verbose` | no | off | Raises log detail to DEBUG. Never changes reports or exit codes. |
| `--version`, `--help` | no | — | Print and exit `0`. |

Argument validation failures — a missing required argument, a nonexistent `--input`, a
malformed date, `--retention-days 0`, an unparseable `--fail-on` — exit `1` and write
nothing.

Progress goes to stdout (resolved settings, one line per repository, a final summary);
warnings and errors go to stderr. Neither stream is machine-readable output — the exit
code is.

## Exit codes

The pipeline branches on these alone — no log parsing, no report inspection.

| Code | Name | Reports written? | Meaning |
|------|------|------------------|---------|
| `0` | SUCCESS | yes | Every manifest entry processed; no threshold met |
| `1` | FATAL | **no** | Could not run: bad arguments, missing or invalid manifest, unwritable output, filename collision |
| `2` | PARTIAL | yes | Reports complete for everything processable; one or more inputs failed |
| `3` | THRESHOLD | yes | Reports complete; a `--fail-on` threshold was met |

Precedence when several conditions hold: `1` > `3` > `2` > `0`. A threshold breach is
never masked by a parse failure — the security signal outranks the data-quality signal.
Codes `2` and `3` guarantee the reports exist; only `1` means nothing was written.

## Guarantees

1. **Deterministic** — identical input, manifest, history, and `--scan-date` produce
   byte-identical reports. (Log text is not covered; report files are.)
2. **Offline** — no socket is opened and no hostname resolved, at any point.
3. **Non-destructive to inputs** — `--input` and the manifest are never written to.
4. **Non-destructive to unreadable history** — a history file that cannot be parsed is
   preserved byte-identical and named in the summary, never deleted or overwritten.
5. **Scoped deletion** — only `<output-dir>/repositories/*.md` and out-of-window
   `YYYY-MM-DD.json` history files are ever deleted. The output root is not cleared, so
   unrelated pipeline files there are safe.
6. **Idempotent per date** — re-running for the same `--scan-date` replaces that date's
   history file and rewrites the reports; no duplicate entry accumulates.
7. **Out of scope** — no checkout, image discovery, Trivy invocation, cache management,
   or artifact publishing.

## Documentation

- **Run it locally without Trivy**: [`specs/001-trivy-vuln-reports/quickstart.md`](specs/001-trivy-vuln-reports/quickstart.md)
- **The pipeline that feeds it** (job graph, adding a GitOps repository, secrets): [`pipeline/README.md`](pipeline/README.md)
- **Project principles (governance)**: [`.specify/memory/constitution.md`](.specify/memory/constitution.md)
- **Design and module map**: [`specs/001-trivy-vuln-reports/plan.md`](specs/001-trivy-vuln-reports/plan.md)
- **Contracts** (CLI, manifest, history, report format, Trivy input): [`specs/001-trivy-vuln-reports/contracts/`](specs/001-trivy-vuln-reports/contracts/)

## Status

**Phase A complete** — the Python core, validated against committed fixtures. The full
test suite runs offline with no container runtime, no Trivy binary, and no network.

**Phase B complete** — [`contracts/trivy-input.md`](specs/001-trivy-vuln-reports/contracts/trivy-input.md)
is verified against **Trivy 0.73.0**. Real `trivy image --format json` output from
`alpine:3.20`, `node:18-slim`, and a secret-bearing image confirmed every field name,
casing, and type; that output is committed as `tests/fixtures/trivy/real_*.json` and
asserted by `tests/contract/test_real_trivy_output.py`. Procedure for re-verifying
against a future Trivy release: [`tools/generate_fixtures.md`](tools/generate_fixtures.md).

**Phase C built** — the Azure DevOps pipeline and image discovery live in
[`pipeline/`](pipeline/README.md), outside this package. `prepare → scan_<repo>* → report → gate`:
one scanning job per GitOps repository, a fan-in reporting job, and the severity gate as a
separate later job so a threshold breach cannot stop history from being persisted. The
application needed no change — the manifest and CLI contracts were sufficient as written.
The scripts are unit-tested against committed fixtures; the YAML itself has not yet run on
an agent.

## Tests

```bash
pytest                        # full suite, offline
ruff check src tests pipeline
```
