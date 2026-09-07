# trivy-report — Technical Documentation

**Scope of this document**: the Python application that turns Trivy JSON scan results
into Markdown vulnerability reports. This is the piece that is built, tested, and
verified against real Trivy output.

The Azure DevOps pipeline that calls it — checkout, image discovery, Trivy invocation,
caching, artifact publishing — is **not** covered here and is not built. See
[Boundaries](#1-boundaries) for exactly where the line falls and why.

**Status**: complete and verified against Trivy 0.73.0. 993 tests pass offline with no
container runtime, no Trivy binary, and no network.

---

## Contents

1. [Boundaries — what this owns and what it refuses to own](#1-boundaries)
2. [Interface — CLI, inputs, outputs, exit codes](#2-interface)
3. [Data flow — the seven stages](#3-data-flow)
4. [Counting rules — the decisions that determine every number](#4-counting-rules)
5. [Trends — how day-over-day comparison works](#5-trends)
6. [History — the only persisted state](#6-history)
7. [Failure handling — degrade or fail loud](#7-failure-handling)
8. [Report format](#8-report-format)
9. [Guarantees and how each is enforced](#9-guarantees)
10. [Verification — what was tested, and against what](#10-verification)
11. [Module reference](#11-module-reference)
12. [Operating it](#12-operating-it)
13. [Known limitations](#13-known-limitations)

---

## 1. Boundaries

The application is **business logic only**. It reads files a pipeline produced and
writes files a pipeline publishes.

It never:

- shells out to `git`, `kubectl`, `docker`, or `trivy`
- opens a socket or resolves a hostname
- authenticates to a registry or handles a credential
- reads the system clock to decide what a scan date is

Those are not stylistic preferences; each one is a testable property, and each has a
test that fails if it stops holding.

| Concern | Owner |
|---------|-------|
| Repository checkout | Pipeline |
| Image discovery (`kubectl kustomize`) | Pipeline |
| Trivy invocation and DB caching | Pipeline |
| Writing the manifest that maps result files to repositories | Pipeline |
| Parsing Trivy JSON, normalising, deduplicating | **This application** |
| Persisting scan history, pruning it | **This application** |
| Comparing against a baseline, computing trends | **This application** |
| Rendering Markdown reports | **This application** |
| Publishing reports as build artifacts | Pipeline |
| Failing the build | Pipeline, using this application's exit code |

**Why the split is drawn here.** Everything on the pipeline side needs credentials,
network access, or a container runtime. Everything on the application side is a pure
function of files on disk. That makes the application testable with committed fixtures
alone — no infrastructure, no secrets, no flake — and it means a credential leak is
structurally impossible in application code, because there is nothing there to leak.

---

## 2. Interface

### Invocation

```bash
trivy-report \
  --input       ./trivy-results \
  --manifest    ./trivy-results/manifest.json \
  --history-dir ./scan-history \
  --output-dir  ./reports \
  --scan-date   2026-08-05
```

Equivalent: `python -m trivy_report <same args>`.

### Options

| Option | Required | Default | Meaning |
|--------|----------|---------|---------|
| `--input DIR` | yes | — | Directory of Trivy JSON results. Read-only; never modified. Must exist. |
| `--manifest FILE` | yes | — | Sidecar manifest mapping each result file to a repository and image. Must exist and validate. |
| `--history-dir DIR` | yes | — | Dated history files. Created if absent. Read for the baseline, written at the end. |
| `--output-dir DIR` | yes | — | Where reports are written. Created if absent, along with `repositories/`. |
| `--scan-date DATE` | no | manifest `scan_date` | Logical scan date, `YYYY-MM-DD`. |
| `--retention-days N` | no | `90` | History retention window, inclusive of the scan date. Minimum `1`. |
| `--fail-on SEV=N` | no | none | Exit `3` when the unique-image grand total for `SEV` reaches `N`. Repeatable. |
| `--verbose` | no | off | Raises log detail to DEBUG. Never changes reports or exit codes. |
| `--version`, `--help` | no | — | Print and exit `0`. |

`--scan-date` exists so the output is reproducible. **The system clock is never
consulted for anything that affects output** — not for the report date, not for the
history filename, not for the retention cutoff. A run replayed six months later against
the same inputs produces byte-identical reports.

### Input: the manifest

The pipeline writes this during image discovery. It is the authority on which repository
an image belongs to — Trivy's own `ArtifactName` is diagnostic only, and the manifest
wins on disagreement.

```json
{
  "schema_version": 1,
  "scan_date": "2026-08-05",
  "generator": "azure-pipelines/discover-images.sh",
  "entries": [
    {
      "image_name": "registry.example.com/payments/api",
      "image_tag": "1.24.3",
      "repository": "gitops-payments",
      "result_file": "gitops-payments/api.json"
    }
  ]
}
```

`result_file` is resolved relative to `--input` and **must stay inside it**. An absolute
path, or one that escapes via `..`, is fatal — a manifest is machine-generated, so a
path escaping its root means something upstream is wrong or hostile, and neither is
something to work around silently.

Full schema: `specs/001-trivy-vuln-reports/contracts/manifest.schema.json`.

### Input: Trivy JSON

Ten fields are consumed. Everything else Trivy emits is read past silently.

| Path | Required | Use |
|------|----------|-----|
| `SchemaVersion` | yes | Presence and numeric type checked; value warned on but not gated |
| `ArtifactName` | no | Diagnostics only — manifest wins |
| `ArtifactType` | no | Diagnostics only |
| `Results` | yes | Must be a list; may be empty |
| `Results[].Class` | no | Decides whether the block counts |
| `Results[].Vulnerabilities` | no | **Absent or `null` means zero findings** — normal for a clean image |
| `…[].VulnerabilityID` | yes | Dedup key component |
| `…[].PkgName` | yes | Dedup key component |
| `…[].PkgPath` | no | Dedup key component, defaults to `""` |
| `…[].InstalledVersion` | no | Informational; deliberately **not** in the dedup key |
| `…[].Severity` | no | Absent, empty, or unrecognised → `UNKNOWN` |

Every Trivy-shaped assumption lives in one module (`trivy_parser.py`). Nothing
downstream of `normalize.py` knows a Trivy field name exists, so a future Trivy rename
costs one module and a fixture refresh rather than a rewrite.

### Outputs

| Path | Content |
|------|---------|
| `<output-dir>/overall.md` | Fleet-wide report, grouped by repository, with subtotals and two grand totals |
| `<output-dir>/repositories/<repo>.md` | One report per repository |
| `<history-dir>/YYYY-MM-DD.json` | This run's counts, for tomorrow's comparison |

Report filenames are **fixed and date-free** so the pipeline publishes from a static
path. The scan date lives inside the documents.

### Exit codes

The pipeline branches on these alone — no log parsing, no report inspection.

| Code | Name | Reports written? | Meaning |
|------|------|------------------|---------|
| `0` | SUCCESS | yes | Every manifest entry processed; no threshold met |
| `1` | FATAL | **no** | Could not run: bad arguments, missing or invalid manifest, unwritable output, filename collision |
| `2` | PARTIAL | yes | Reports complete for everything processable; one or more inputs failed |
| `3` | THRESHOLD | yes | Reports complete; a `--fail-on` threshold was met |

**Precedence: `1` > `3` > `2` > `0`.**

The ordering of `3` above `2` is deliberate and is the single most important line in
this section. A run with both a parse failure and a threshold breach exits `3`. If
`2` won, a pipeline configured to tolerate partial scans would swallow a real security
signal — the data-quality problem would mask the vulnerability. Codes `2` and `3` both
guarantee the reports exist; only `1` means nothing was written.

---

## 3. Data flow

Seven stages, each a pure function over frozen dataclasses:

```
manifest ─▶ parse ─▶ normalize ─▶ aggregate ─▶ compare ─▶ render ─▶ persist
```

| Stage | Module | Input → Output |
|-------|--------|----------------|
| Load manifest | `manifest.py` | manifest file → validated entries |
| Parse | `trivy_parser.py` | Trivy JSON → `Finding` stream, or a typed failure |
| Normalize | `normalize.py` | `Finding` stream → deduplicated `SeverityCounts` |
| Aggregate | `aggregate.py` | per-image counts → repository subtotals, two grand totals |
| Compare | `compare.py` | this run + baseline → `TrendSet` per tracked subject |
| Render | `reporting/` | run + comparison → Markdown strings |
| Persist | `history.py`, `reporting/writer.py` | strings → files, atomically |

All filesystem and process concerns live in exactly four modules — `cli.py`,
`history.py`, `manifest.py`, `reporting/writer.py`. Every business rule above is
testable without touching disk, which is why the suite runs in 44 seconds with no
infrastructure.

Findings are consumed as a **stream** and discarded as counted, so memory scales with
image count rather than finding count. A fleet with a hundred thousand findings holds
only the dedup keys for the image currently being processed.

---

## 4. Counting rules

Every number in every report follows from four decisions. They are stated here because
a reader who disagrees with a count is almost always disagreeing with one of these.

### 4.1 A count is a finding instance, not a distinct CVE

The unit is `(image, CVE, package, package path)`. One CVE affecting two packages in one
image counts **twice**, because it is two things to remediate. Both reports say this
inline, above the first table, so a number is never read as a CVE count by mistake.

### 4.2 The dedup key excludes `InstalledVersion` and includes `PkgPath`

Key: `(VulnerabilityID, PkgName, PkgPath)`, scoped per image — dedup runs once per image,
so the image component is implicit in the call boundary rather than stored in the key.
That is also what keeps the seen-set small on a large fleet.

- **`InstalledVersion` excluded** — two Trivy result blocks reporting the same
  vulnerability with different observed versions describe one problem. Including it
  would let a version disagreement inflate the total.
- **`PkgPath` included** — one library vendored at two paths is two instances to fix.

On a duplicate key whose severities disagree, the first occurrence wins. The bucket
choice is arbitrary; the total is not. The instance is counted exactly once either way,
and inflating the total would be the actual error.

### 4.3 Only CVE-bearing result classes count

| `Class` | Counted? | Why |
|---------|----------|-----|
| `os-pkgs` | yes | OS package vulnerabilities |
| `lang-pkgs` | yes | Language dependency vulnerabilities |
| `secret` | **no** | Leaked secrets, not CVEs |
| `config` | **no** | Misconfigurations, not CVEs |
| `license` | **no** | License findings, not CVEs |
| absent / unrecognised | yes, with a warning | Fail open, so a new CVE-bearing class is not silently dropped |

Both directions are deliberate. Known non-CVE classes are excluded so severity totals
stay meaningful; unknown classes are included so a future Trivy addition is visible
rather than invisible.

This matters more than it looks. Trivy reports secrets, licences, and misconfigurations
in the **same document** as CVEs, under the **same severity vocabulary**. A `Class:
"secret"` finding at `Severity: HIGH` is not a HIGH CVE. Getting this wrong produces
inflated numbers that look exactly like real risk — see [§10](#10-verification) for the
real-data test that pins it.

### 4.4 Two grand totals, not one

An image can belong to several GitOps repositories.

- **Unique images** — each image counted once, no matter how many repositories
  reference it. This is the fleet's real exposure, and **this is what `--fail-on`
  evaluates.**
- **Sum of subtotals** — shared images counted once per repository. This is what you
  get by adding the per-repository sections, so it must appear or the report looks
  like it cannot add up.

Reporting one alone would either misrepresent exposure or contradict the sections above
it. The overall report states which one drives the threshold.

---

## 5. Trends

### 5.1 The trend key is `(repository, image_name)` — never the full reference

A tag bump is the **same tracked subject with different counts**. Keying trends on the
full image reference (including tag) would make every deploy read as one image
disappearing and a different one appearing, and the trend column — the reason this
feature exists — would be permanently empty.

Two keys therefore coexist, on purpose:

| Key | Used for |
|-----|----------|
| `(repository, image_name)` | Trend comparison |
| `ImageRef.ref` (name + tag) | Unique-image identity in grand totals |

### 5.2 Cell shapes

| Rendered | Meaning |
|----------|---------|
| `12 ↑ +3` | Rose by 3 since the baseline |
| `9 ↓ -3` | Fell by 3 |
| `7 → 0` | Compared, unchanged |
| `7 (new)` | First time this subject was seen — **no arrow** |
| `?` | This image's input could not be parsed — count unknown |

**`(new)` is not `→ 0`.** "Nothing to compare against" is a different fact from "no
change". Rendering an arrow for a first sighting would assert a comparison that never
happened. A flat count renders `→ 0`, not `→ +0`.

**`?` is not `0`.** An image whose file failed to parse gets `?` in every column and no
trend. A zero would be a claim of a clean bill of health, and it would also compare as a
huge improvement against yesterday's real numbers — the most dangerous possible cell in
a security report.

### 5.3 Baseline selection

The baseline is the **most recent history entry strictly before the scan date**. Not
"yesterday" — if a weekend was skipped, Monday compares against Friday, and the report
names the date it actually used. An unparseable history file is skipped, and selection
falls through to the next-most-recent, so a corrupt archive costs one day of comparison
rather than the whole trend.

---

## 6. History

The dated history archive is the only persisted state the application owns. It is
written by one process and read back days later by a different process on a different
machine, which drives three rules.

**1. Writes are atomic.** Temp file in the same directory, then `os.replace`. An
interrupted or killed run leaves either the old entry or the new one, never a truncated
document. A half-written history file would silently poison every future comparison.

**2. Validation is symmetric with the contract.** Deserialisation rejects exactly what
`contracts/history.schema.json` rejects. Validation is hand-written because the
application carries zero runtime dependencies — a test-only `jsonschema` would validate
something production never runs.

**3. A file that cannot be trusted is skipped and preserved — never repaired, never
deleted.** Trends degrade by one day; the archive stays intact for a human to inspect.

Malformed history is recoverable in a way a malformed manifest is not. History is
supporting evidence, so a bad entry costs one comparison. A bad manifest would mean
every count in the report is attributed to a repository on a guess, so it is fatal.

### Retention

`--retention-days N` keeps an **inclusive** window `N` days wide counting the scan date
itself, so `--retention-days 7` keeps a week and the cutoff is six days back.
`--retention-days 1` keeps exactly this run's entry.

Deletion is tightly scoped: only files matching `YYYY-MM-DD.json` **zero-padded** are
ever considered. `2026-8-4.json` is not history — accepting a second naming form would
make "the most recent entry" depend on how a file happened to be written. Anything else
in the directory is left alone.

The cutoff is computed from `--scan-date`, never the clock, so a replayed run prunes
exactly what the original did.

### Idempotence

Re-running for the same `--scan-date` **replaces** that date's entry and rewrites the
reports. No duplicate accumulates. A retried pipeline stage is safe.

---

## 7. Failure handling

The governing principle: **fail loud on ambiguity, degrade on recoverable input.**

### Fatal — nothing is written, exit `1`

- A required argument missing, `--input` nonexistent, a malformed date,
  `--retention-days 0`, an unparseable `--fail-on`
- The manifest missing, unreadable, or invalid
- A `result_file` path that is absolute or escapes `--input`
- Two repositories whose names sanitise to the same report filename
- The output directory not writable

These share a shape: the correct output is not merely unknown, it is not defined. Half a
report from a manifest that could not be read is worse than no report, because it looks
complete.

### Recoverable — reports are still written, exit `2`

| Condition | Kind |
|-----------|------|
| Not valid JSON (truncated, empty, not JSON) | `MALFORMED_JSON` |
| Valid JSON but no `SchemaVersion`, or `Results` absent/not a list | `SCHEMA_MISMATCH` |
| A vulnerability missing `VulnerabilityID` or `PkgName` | `SCHEMA_MISMATCH` |
| Unreadable (permissions, IO error) | `UNREADABLE` |
| Listed in the manifest, file absent | `FILE_MISSING` |
| Present in `--input`, absent from the manifest | `ORPHAN_FILE` |

Each is named in a warning on stderr and counted in the report's Run Summary. Every
other image is reported normally.

### The distinction the whole design turns on

> **A valid-JSON-wrong-schema file is a failure, never an image with zero
> vulnerabilities.**

Reporting a clean bill of health for a file that could not be understood is the worst
available failure mode for a security report, and it is the one a naive
`data.get("Results", [])` produces.

The mirror case is equally deliberate: **`Vulnerabilities` being absent *is* zero
findings**, because that is exactly what Trivy emits for a clean image. The difference
between the two rows is the difference between *"Trivy said nothing is wrong"* and
*"we could not tell what Trivy said"*.

### Streams

Progress to stdout (resolved settings, one line per repository, a final summary).
Warnings and errors to stderr. Neither stream is machine-readable output — the exit code
is.

---

## 8. Report format

### Per-repository — `repositories/<repo>.md`

```markdown
# Vulnerability Report: gitops-backend

**Scan date**: 2026-08-06
**Compared against**: 2026-08-05
**Generated by**: trivy-report 0.1.0

> Counts are finding instances, not distinct CVEs: one count per (image, CVE, package, package path).
> The same CVE affecting two packages in one image counts twice.

## Images

| Image | Tags | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | Total |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `…/backend` | 1.2.0 | 2 ↑ +1 | 1 ↓ -1 | 2 ↑ +1 | 1 → 0 | 0 → 0 | 6 |
| **Subtotal** |  | **2 ↑ +1** | **1 ↓ -1** | **2 ↑ +1** | **1 → 0** | **0 → 0** | **6** |

## Run Summary

- **Files expected**: 1
- **Files processed**: 1
- **Files failed**: 0
- **Images covered**: 1
- **Baseline**: 2026-08-05
```

### Overall — `overall.md`

Adds a Summary block (repositories scanned, distinct images, images shared across
repositories, baseline), the two grand totals, then one section per repository.

### Determinism in rendering

- Repositories sort by name; images sort by reference; tags sort within a cell.
- Severity columns are always CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN — never
  data-dependent.
- No timestamp, no hostname, no run ID, no path that varies by machine.

A repository known from the baseline but **absent from this run** still gets a section,
and it deliberately gets **no table**:

```markdown
### gitops-platform

**Not scanned in this run.** Present in the 2026-08-05 baseline with 3 CRITICAL, 6 HIGH, 5 MEDIUM, 1 LOW, 0 UNKNOWN.
```

Two choices there. A row of zeros would read as a clean scan, so there is no table at
all. And the last-known counts are what make the notice actionable — "not scanned" alone
does not tell a reader whether to care.

The same reasoning drives the whole-fleet case. When **nothing** was scanned,
`overall.md` is not the normal report with zeros substituted in: there is no Grand Totals
table, and the disclaimer is in words — *"This is not a clean bill of health — it means
nothing was scanned"* — because "0 images scanned" is a fact a reader has to interpret.
The exit code stays `0`, because the application did its job; the pipeline is what may
have failed, and the report is where that gets said.

Report filenames are derived from repository names by sanitisation. Two names collapsing
to one filename is **fatal**, not silently overwritten: one repository's report
overwriting another's is a wrong report presented as a right one.

---

## 9. Guarantees

Each is a property with a test behind it, not an aspiration.

| # | Guarantee | How it is enforced |
|---|-----------|--------------------|
| 1 | **Deterministic** — identical inputs and `--scan-date` produce byte-identical reports | Sorted iteration everywhere; no clock, no randomness, no environment in output. Test writes twice and compares bytes. |
| 2 | **Offline** — no socket opened, no hostname resolved | No networking import in `src/`; asserted by test. |
| 3 | **Zero runtime dependencies** — standard library only | `pyproject.toml` declares none; a test walks imports and fails on a third-party module. |
| 4 | **Inputs are read-only** — `--input` and the manifest are never written | No write path targets them; verified by checking inputs are unchanged after runs. |
| 5 | **Unreadable history is preserved** — byte-identical, named in the summary, never deleted or overwritten | Corrupt-history test asserts the bytes afterwards. |
| 6 | **Scoped deletion** — only `<output-dir>/repositories/*.md` and out-of-window `YYYY-MM-DD.json` | Prune matches a strict zero-padded pattern; the output root is never cleared, so unrelated pipeline files there are safe. |
| 7 | **Atomic writes** — temp file plus `os.replace` | No partially written history or report is observable. |
| 8 | **Idempotent per date** — re-running a date replaces, never appends | Same-date test asserts one entry. |
| 9 | **No credentials in application code** | Nothing authenticates; there is nothing to leak. |

Log *text* is explicitly not covered by guarantee 1. Report and history files are.

---

## 10. Verification

### Test suite

**993 tests, all passing**, in four layers:

| Layer | Covers |
|-------|--------|
| `tests/unit/` | Counting, dedup, trends, retention, model invariants, filename sanitisation, exit precedence |
| `tests/contract/` | CLI surface, manifest schema, history schema, report format, real Trivy output |
| `tests/integration/` | End-to-end runs: baseline, trends, multi-day, partial failure, threshold, precedence, determinism, 200 images, new/unscanned repository |
| Property tests | Zero-dependency check, offline check |

The suite requires no infrastructure: no Trivy binary, no container runtime, no
registry, no network. Verified by running the whole suite with
`DOCKER_HOST=unix:///nonexistent/docker.sock` — 993 pass, and no test invokes Docker.

```bash
pytest                  # full suite, offline
ruff check src tests
```

### Verified against real Trivy

The Trivy input contract was written **before** a Trivy binary was reachable, so every
field in it was an assumption. Those assumptions have since been checked against
`aquasec/trivy:latest` reporting `Version: 0.73.0`, run over `alpine:3.20`,
`node:18-slim`, and a purpose-built image carrying a dummy private key.

| Assumption | Result |
|------------|--------|
| Field names, casing, types: `SchemaVersion`, `Results[]`, `Class`, `Type`, `Vulnerabilities[]`, `VulnerabilityID`, `PkgName`, `PkgPath`, `InstalledVersion`, `Severity` | **Confirmed exactly.** All present with expected casing; all `str` except `SchemaVersion` (`int`) |
| `Class` values `os-pkgs` / `lang-pkgs` | **Confirmed.** `node:18-slim` produced both in one document (`Type: debian`, `Type: node-pkg`) |
| A clean image omits `Vulnerabilities` | **Confirmed.** `alpine:3.20` scanned clean and the key was *absent entirely* — not `null`, not `[]` |
| `PkgPath` present for language ecosystems, absent for OS packages | **Confirmed.** 0/223 OS findings carried it; 27/27 npm findings did |
| `secret` / `config` / `license` excluded from counts | **Confirmed on real data.** A real `Class: "secret"` block at `Severity: HIGH` did not reach the counts and did not trip `--fail-on HIGH=1` |
| `SchemaVersion` value | **Observed `2`.** Recorded, warned on, not gated — see below |

Two results are worth calling out.

**Counts were verified independently, not just self-consistently.** Recomputing severity
tallies straight from the raw untrimmed JSON gave `CRITICAL 8, HIGH 46, MEDIUM 104,
LOW 83, UNKNOWN 9` = 250, matching the generated report exactly.

**Real `UNKNOWN` severities occur in production advisory data** — 9 of 223 Debian
findings. That bucket is not a synthetic edge case invented for the fixtures.

The observed output is committed as `tests/fixtures/trivy/real_*.json`, trimmed to the
consumed fields plus `Title` and `FixedVersion` — which are *ignored*, and retained
precisely to keep proving that unconsumed fields stay harmless.

### `SchemaVersion` — a recorded trade-off, not a gap

Trivy 0.73.0 emits `SchemaVersion: 2`, recorded in `OBSERVED_SCHEMA_VERSIONS`.

It is still **not** a gate. Presence and numeric type are required; an unrecognised
*value* warns and the document is parsed anyway.

The reasoning: Trivy renumbering that field is far more likely than Trivy renaming every
field beneath it. Hard-gating would convert a cosmetic upstream bump into a failed
security report — refusing valid production output is the worse error. The field-level
checks are what actually decide whether a document is understood.

Tested both directions: `test_the_observed_schema_version_parses_without_a_warning` and
`test_an_unobserved_schema_version_warns_but_still_parses`.

### Demonstration scenarios

`testing/` holds six end-to-end scenarios with their inputs and exact outputs, so the
reports can be **read** rather than only asserted about. `testing/run-all.sh`
regenerates everything and asserts every exit code.

| # | Demonstrates | Exit |
|---|--------------|------|
| 00 | Two consecutive days over one real image — trend arrows in both directions | `0`, `0` |
| 01 | Baseline run: every cell `(new)`, no arrows | `0` |
| 02 | Day 2 of the same fleet: `↑ +1` beside `→ 0` | `0` |
| 03 | Unreadable input — reports still written, PARTIAL is not FATAL | `2` |
| 04 | All four failure kinds in one run, beside fixtures that parse cleanly | `2` |
| 05 | Real Trivy 0.73.0 output, `--fail-on CRITICAL=5` against a real count of 8 | `3` |

See `testing/README.md`. Determinism is observable there: re-run `run-all.sh` and diff —
reports and history are byte-identical.

---

## 11. Module reference

~4,200 lines across 21 modules. Boundaries follow the data flow; each stage is a pure
function over frozen dataclasses.

| Module | Lines | Responsibility |
|--------|------:|----------------|
| `models.py` | 664 | Frozen dataclasses and their invariants: `Severity`, `SeverityCounts`, `Finding`, `ImageRef`, `ImageScan`, `ScanRun`, `HistoryEntry`, `Comparison`, `TrendSet`, `FailureKind` |
| `history.py` | 564 | Serialise, validate, write atomically, select baseline, prune |
| `cli.py` | 560 | Argument parsing, orchestration, exit-code resolution |
| `reporting/overall_report.py` | 344 | Fleet report: summary, two grand totals, per-repository sections |
| `manifest.py` | 326 | Manifest load, schema validation, path confinement |
| `trivy_parser.py` | 284 | **The only module that knows a Trivy field name** |
| `reporting/markdown.py` | 256 | Table and cell rendering vocabulary, trend cell shapes |
| `reporting/writer.py` | 206 | Atomic writes, filename sanitisation, collision detection |
| `aggregate.py` | 183 | Subtotals and both grand totals |
| `reporting/repo_report.py` | 183 | Per-repository report |
| `compare.py` | 120 | Baseline comparison, trend computation |
| `reporting/empty_report.py` | 100 | Repositories with no images, and unscanned repositories |
| `run_summary.py` | 85 | Files expected/processed/failed, images covered, baseline |
| `normalize.py` | 84 | Deduplication and folding into counts |
| `config.py` | 84 | Resolved settings |
| `logging_setup.py` | 72 | Stream routing |
| `exit_codes.py` | 44 | Codes and precedence |
| `errors.py` | 37 | Fatal error types |

`reporting/` is the only subpackage, because it is the only stage with more than one
output artifact and a shared rendering vocabulary.

---

## 12. Operating it

### Install

```bash
pip install -e ".[dev]"
```

`pytest` and `ruff` are development dependencies and are not imported by anything under
`src/`.

### Pipeline integration

The pipeline needs to do four things:

1. Write a manifest during image discovery (`contracts/manifest.schema.json`).
2. Run Trivy per image with `--format json`, into a directory.
3. Call `trivy-report` with that directory, the manifest, a persisted history directory,
   and an output directory.
4. Branch on the exit code and publish `<output-dir>` as an artifact.

The history directory must **persist across runs** — it is the only thing that makes
trends possible. Cache it or commit it; if it is empty, every run is a baseline run and
every cell reads `(new)`.

Pass `--scan-date` explicitly from the pipeline rather than relying on the manifest
default, so a re-run of a past build reproduces that build's reports.

### Reading the exit code

```
0 → publish, pass
1 → fail the stage; no reports exist to publish
2 → publish the reports, then decide: they are complete for everything readable,
      but something upstream produced a file that could not be parsed
3 → publish the reports and fail the build: a severity threshold was met
```

---

## 13. Known limitations

Stated plainly rather than left to be discovered.

1. **Trends are count-based, not identity-based.** A repository can go from 1 MEDIUM to
   2 MEDIUM while *no* original MEDIUM finding survives — the cell reads `↑ +1`, which
   is true of the count and silent about the churn beneath it. Scenario 00 in `testing/`
   is exactly this case.

2. **Reports carry counts, not per-CVE detail.** No CVE identifier appears in a
   generated report. The reports answer "how exposed are we, and is it getting worse",
   not "which CVE do I fix first". The Trivy JSON remains the source for that.

3. **`SchemaVersion` is not gated on value** — a future Trivy 3 warns and parses. This
   is deliberate ([§10](#10-verification)), but it does mean a genuine breaking schema
   change would surface as wrong counts plus a warning rather than a clean refusal. The
   field-level checks are what catch that in practice.

4. **Verified against Trivy 0.73.0 only.** Re-verification procedure for future releases
   is in `tools/generate_fixtures.md`.

5. **Azure DevOps pipeline YAML is not built.** `contracts/cli.md` carries an
   illustrative sketch; nothing is authored or tested. This is the remaining piece of
   the overall task, and it is out of scope for this document.
