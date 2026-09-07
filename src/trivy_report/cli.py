"""The thin shell: argument surface, orchestration, exit code (contracts/cli.md).

Every rule the library enforces is enforced in the library. What lives here is
only what a command line adds: parsing arguments, deciding what a bad one costs,
sequencing the stages, and turning the outcome into a number a pipeline can
branch on.

Three properties of this module are contractual rather than stylistic:

- **``main`` is the only caller of ``sys.exit`` (Principle V).** Every stage
  returns or raises; nothing below this file can terminate the process. That is
  what makes the whole application importable and testable in-process.
- **Exit ``1`` writes nothing.** Argument validation, manifest loading and scan
  date resolution all complete *before* the first directory is created, so a
  pipeline can treat ``1`` as "there is no report to publish" without inspecting
  the output directory (FR-024b).
- **The system clock is never consulted (D7).** The scan date comes from
  ``--scan-date`` or the manifest, and its absence is fatal. Defaulting to today
  would make two runs over one input set disagree, which is precisely what the
  determinism guarantee forbids.

``argparse``'s own exit behaviour is intercepted for both reasons above: it exits
``2`` on a bad argument, and ``2`` in this contract means "reports were written".
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path

from trivy_report import __version__
from trivy_report.aggregate import build_scan_run
from trivy_report.compare import compare_run
from trivy_report.config import DEFAULT_RETENTION_DAYS, RunConfig
from trivy_report.errors import FatalError
from trivy_report.exit_codes import ExitCode, resolve
from trivy_report.history import (
    entry_from_run,
    known_repositories,
    prune,
    select_baseline,
    write_entry,
)
from trivy_report.logging_setup import configure
from trivy_report.manifest import (
    Manifest,
    find_missing_files,
    find_orphan_files,
    load_manifest,
)
from trivy_report.models import ImageScan, ParseFailure, ScanRun, Severity
from trivy_report.normalize import normalize_image
from trivy_report.reporting.empty_report import render_empty_report
from trivy_report.reporting.overall_report import render_overall_report
from trivy_report.reporting.repo_report import render_repository_report
from trivy_report.reporting.writer import write_report
from trivy_report.run_summary import build_summary
from trivy_report.trivy_parser import parse_result_file

PROGRAM = "trivy-report"

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DIGITS_RE = re.compile(r"^\d+$")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


class _ArgumentError(Exception):
    """A bad or missing argument. Becomes exit ``1``, never argparse's ``2``."""


class _CleanExit(Exception):
    """``--help`` or ``--version``: print and stop, exit ``0``."""

    def __init__(self, status: int, message: str | None = None) -> None:
        super().__init__(message or "")
        self.status = status
        self.message = message


class _Parser(argparse.ArgumentParser):
    """An ``ArgumentParser`` that cannot terminate the process.

    ``error`` and ``exit`` both raise instead, so the exit code stays this
    module's decision. Left to argparse, a missing ``--input`` would exit ``2``,
    which this contract defines as "reports were written and are complete for the
    processable data" — the opposite of what happened.
    """

    def error(self, message: str) -> None:  # type: ignore[override]
        raise _ArgumentError(message)

    def exit(self, status: int = 0, message: str | None = None) -> None:  # type: ignore[override]
        raise _CleanExit(status, message)


def build_parser() -> argparse.ArgumentParser:
    """The complete argument surface from ``contracts/cli.md``."""
    parser = _Parser(
        prog=PROGRAM,
        description=(
            "Turn Trivy JSON scan results into Markdown vulnerability reports "
            "with historical trends."
        ),
        epilog=(
            "Exit codes: 0 success, 1 fatal (nothing written), "
            "2 partial (reports written, some inputs failed), "
            "3 threshold met (reports written). Precedence: 1 > 3 > 2 > 0."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")
    parser.add_argument(
        "--input",
        required=True,
        metavar="DIR",
        help="Directory holding the Trivy JSON results. Read-only; never modified.",
    )
    parser.add_argument(
        "--manifest",
        required=True,
        metavar="FILE",
        help="Sidecar manifest mapping each result file to a repository and image.",
    )
    parser.add_argument(
        "--history-dir",
        required=True,
        metavar="DIR",
        help="Directory of dated history files. Created if absent.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        metavar="DIR",
        help="Where reports are written. Created if absent, along with repositories/.",
    )
    parser.add_argument(
        "--scan-date",
        metavar="YYYY-MM-DD",
        help=(
            "Logical scan date. Defaults to the manifest scan_date; absent from "
            "both is fatal. The system clock is never consulted."
        ),
    )
    parser.add_argument(
        "--retention-days",
        metavar="N",
        default=str(DEFAULT_RETENTION_DAYS),
        help=f"History retention window in days (minimum 1, default {DEFAULT_RETENTION_DAYS}).",
    )
    parser.add_argument(
        "--fail-on",
        action="append",
        default=[],
        metavar="SEVERITY=COUNT",
        help=(
            "Exit 3 when the unique-image grand total for SEVERITY is >= COUNT. "
            "Repeatable. With no --fail-on, exit 3 is impossible."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Raise log detail to DEBUG. Changes neither reports nor exit codes.",
    )
    return parser


def parse_scan_date(raw: str, *, source: str) -> date:
    """Parse a ``YYYY-MM-DD`` date, or raise ``FatalError`` naming its source.

    Strict on shape as well as validity: ``2026-8-5`` names a real day but a
    second accepted spelling would make the history filename depend on how the
    date happened to be written, and "yesterday's entry" is looked up by name.
    """
    if not _DATE_RE.match(raw):
        raise FatalError(f"{source} must be YYYY-MM-DD, got {raw!r}")
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise FatalError(f"{source} is not a real date: {raw!r}") from exc


def parse_retention_days(raw: str) -> int:
    """Parse ``--retention-days``, or raise ``FatalError``.

    Zero is rejected here rather than clamped: it would delete the entry written
    moments earlier, leaving the next run with no baseline and every count
    rendering ``(new)`` forever.
    """
    if not _DIGITS_RE.match(raw):
        raise FatalError(f"--retention-days must be a positive integer, got {raw!r}")
    value = int(raw)
    if value < 1:
        raise FatalError(f"--retention-days must be >= 1, got {value}")
    return value


def parse_thresholds(raw_values: list[str]) -> dict[Severity, int]:
    """Parse every ``--fail-on SEVERITY=COUNT`` into a threshold map.

    Unparseable is fatal, never ignored: a silently dropped ``--fail-on`` would
    turn a configured security gate into a run that always passes, and the
    pipeline author would have no way to notice.

    The severity is matched case-insensitively — a lowercase spelling in a YAML
    file is a typing convention, not a mistake worth failing a build over.
    """
    thresholds: dict[Severity, int] = {}
    for raw in raw_values:
        severity_text, separator, count_text = raw.partition("=")
        if not separator:
            raise FatalError(f"--fail-on must be SEVERITY=COUNT, got {raw!r}")
        try:
            severity = Severity(severity_text.strip().upper())
        except ValueError as exc:
            allowed = ", ".join(s.value for s in Severity)
            raise FatalError(
                f"--fail-on severity must be one of {allowed}, got {severity_text!r}"
            ) from exc
        if not _DIGITS_RE.match(count_text.strip()):
            raise FatalError(f"--fail-on count must be a positive integer, got {count_text!r}")
        count = int(count_text)
        if count < 1:
            # A threshold of 0 fires on a perfectly clean scan, which would make
            # the gate meaningless and the build permanently red.
            raise FatalError(f"--fail-on count must be >= 1, got {count}")
        existing = thresholds.get(severity)
        # A repeated severity keeps the stricter figure: the operator asked to be
        # stopped at that number, and honouring the looser one would let the run
        # pass a gate they configured.
        thresholds[severity] = count if existing is None else min(existing, count)
    return thresholds


def resolve_config(argv: list[str] | None) -> tuple[RunConfig, Manifest]:
    """Validate arguments, load the manifest, and resolve the run configuration.

    Everything that can make a run fatal happens here, before any directory is
    created or any file written. Ordering is deliberate: argument shapes first
    (cheapest and entirely local), then the manifest (the only input whose
    invalidity is fatal), then the scan date, whose fallback lives in the
    manifest and so cannot be resolved earlier.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    retention_days = parse_retention_days(args.retention_days)
    thresholds = parse_thresholds(args.fail_on)
    scan_date_arg = (
        parse_scan_date(args.scan_date, source="--scan-date")
        if args.scan_date is not None
        else None
    )

    manifest = load_manifest(Path(args.manifest))

    # D7 precedence: the argument, then the manifest field, then fatal. Never the
    # clock — a run that invented its own date would produce a report nobody can
    # reproduce and a history entry filed under the wrong day.
    if scan_date_arg is not None:
        scan_date = scan_date_arg
    elif manifest.scan_date is not None:
        scan_date = parse_scan_date(manifest.scan_date, source="manifest scan_date")
    else:
        raise FatalError(
            "no scan date: pass --scan-date YYYY-MM-DD or set scan_date in the manifest "
            "(the system clock is deliberately not used, so output stays reproducible)"
        )

    try:
        config = RunConfig(
            input_dir=Path(args.input),
            manifest_path=Path(args.manifest),
            history_dir=Path(args.history_dir),
            output_dir=Path(args.output_dir),
            scan_date=scan_date,
            retention_days=retention_days,
            thresholds=thresholds,
            verbose=args.verbose,
        )
    except ValueError as exc:
        # RunConfig validates with ValueError because it is a library type with no
        # opinion about exit codes. Translating here is what makes a bad --input
        # an exit 1 with one clear line instead of a traceback.
        raise FatalError(str(exc)) from exc
    return config, manifest


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _collect_scans(
    config: RunConfig, manifest: Manifest, log
) -> tuple[tuple[ImageScan, ...], tuple[ParseFailure, ...], int]:
    """Parse every declared result file into image scans plus failures.

    A file that is missing or unparseable still yields an ``ImageScan`` — with
    ``parse_failed=True`` and no counts — because the image was declared and a
    reader must see it as ``?`` rather than not see it at all. Omitting the row
    would make an unreadable scan indistinguishable from an image with no
    findings, which is the single most dangerous misstatement this report could
    make.

    Returns the scans, the failures, and how many declared files were processed.
    """
    missing = find_missing_files(manifest, config.input_dir)
    missing_files = {failure.file for failure in missing}
    # Declared-but-absent and undeclared-but-present are both discovered by
    # comparing the manifest against the directory, so neither is found by
    # parsing and both must be collected before the parse loop.
    declared: list[ParseFailure] = [*missing, *find_orphan_files(manifest, config.input_dir)]
    failures: list[ParseFailure] = list(declared)

    scans: list[ImageScan] = []
    processed = 0
    for entry in manifest.entries:
        if entry.result_file in missing_files:
            # Already recorded as FILE_MISSING; parsing would report it twice and
            # break the summary arithmetic a reader uses to trust coverage.
            scans.append(
                normalize_image(
                    repository=entry.repository,
                    image=entry.image,
                    findings=(),
                    parse_failed=True,
                )
            )
            continue

        result = parse_result_file(
            config.input_dir / entry.result_file,
            relative_name=entry.result_file,
            repository=entry.repository,
        )
        for warning in result.warnings:
            # Surfaced, never swallowed: an unrecognised result class means this
            # build may be counting something it does not understand.
            log.warning("%s: %s", entry.result_file, warning)
        if result.failure is not None:
            failures.append(result.failure)
            log.warning(
                "%s: %s (%s)",
                entry.result_file,
                result.failure.reason,
                result.failure.kind.value,
            )
        else:
            processed += 1
        scans.append(
            normalize_image(
                repository=entry.repository,
                image=entry.image,
                findings=result.findings,
                parse_failed=result.failure is not None,
            )
        )

    for failure in declared:
        log.warning("%s: %s (%s)", failure.file, failure.reason, failure.kind.value)

    return tuple(scans), tuple(sorted(failures, key=lambda f: f.file)), processed


def evaluate_thresholds(config: RunConfig, run_result: ScanRun, log) -> bool:
    """Decide whether any ``--fail-on`` gate is met (D15, FR-028).

    The gate reads the **unique-image** grand total, never the sum of subtotals.
    The larger figure counts a shared image once per repository, so gating on it
    would fail a build for risk that is deployed exactly once — and no amount of
    remediation in any single repository could clear it.

    ``>=`` rather than ``>``: an operator who writes "fail at 2 CRITICAL" means
    two, and firing only at three would be off by one from what they configured.

    Every breach is logged, not only the first. A build stopped by a CRITICAL gate
    that also breached HIGH needs both on the console, or the second one surfaces
    as a surprise on the next run once the first is fixed. Iteration order is the
    severity declaration order, so the lines are deterministic.
    """
    breached = False
    for severity, limit in config.thresholds.items():
        actual = run_result.unique_image_total.get(severity)
        if actual >= limit:
            log.error("threshold met: %s %d >= %d (unique images)", severity.value, actual, limit)
            breached = True
    return breached


def run(config: RunConfig, manifest: Manifest) -> ExitCode:
    """Execute one run and return its exit code.

    The stage order is the contract's order: manifest → parse → normalize →
    aggregate → compare → write → history. History is written last so a failure
    while rendering cannot leave tomorrow comparing against an entry whose report
    was never produced.
    """
    log = configure(verbose=config.verbose)
    log.info(
        "trivy-report %s: scan date %s, input %s",
        __version__,
        config.scan_date.isoformat(),
        config.input_dir,
    )
    log.debug(
        "history %s, output %s, retention %d day(s), thresholds %s",
        config.history_dir,
        config.output_dir,
        config.retention_days,
        {s.value: n for s, n in config.thresholds.items()} or "none",
    )

    scans, failures, processed = _collect_scans(config, manifest, log)

    # Pruned *before* the baseline is chosen, not after the history write. Two
    # reasons, both about not describing evidence that no longer exists: a report
    # citing a day this same run deleted sends a reader to a file that is gone, and
    # the pruned count belongs in this run's Run Summary — which is rendered before
    # the history entry is written (FR-010, FR-019).
    pruned = prune(
        config.history_dir,
        retention_days=config.retention_days,
        scan_date=config.scan_date,
    )
    if pruned:
        log.info(
            "pruned %d history file(s) outside the %d-day retention window",
            pruned,
            config.retention_days,
        )

    selection = select_baseline(config.history_dir, before=config.scan_date)
    baseline = selection.entry
    if baseline is None:
        log.info("no earlier history entry: this is a baseline run")
    else:
        log.info("comparing against %s", baseline.scan_date.isoformat())

    scanned_repositories = {scan.repository for scan in scans}
    # A repository the archive knows about that this run has no evidence for. It
    # must be carried into the run *before* comparison so the report can state the
    # coverage gap; discovering it afterwards would leave the repository silently
    # absent, which reads as "nothing to report" (Story 2 scenario 4).
    unscanned = tuple(
        name for name in known_repositories(baseline) if name not in scanned_repositories
    )
    summary = build_summary(
        files_expected=len(manifest.entries),
        files_processed=processed,
        failures=failures,
        repositories_covered=len(scanned_repositories),
        # Coverage counts unique images actually read. An unreadable file is no
        # evidence that its image was covered, so it must not inflate this.
        images_covered=len({s.image.ref for s in scans if not s.parse_failed}),
        baseline_date=None if baseline is None else baseline.scan_date,
        history_files_pruned=pruned,
        # Named, not counted: a preserved file is only actionable if a reader can
        # find it, and the report is where someone looks first (FR-011a).
        history_files_skipped=selection.skipped,
    )
    run_result = build_scan_run(
        scans, scan_date=config.scan_date, summary=summary, unscanned=unscanned
    )
    comparison = compare_run(run_result, baseline)

    if manifest.entries:
        overall = render_overall_report(run_result, comparison, baseline)
        bodies = {
            repository.name: render_repository_report(repository, run_result, comparison, baseline)
            for repository in run_result.repositories
            if repository.scanned
        }
    else:
        # FR-021: a Grand Totals table of zeros is exactly the clean bill of health
        # the empty report exists to deny, so the layout differs rather than the
        # numbers. Warned on the console too — a report nobody opens is no warning.
        log.warning(
            "no scan results: the manifest at %s declared zero entries; "
            "check that the scanning stage ran and that the manifest was generated",
            config.manifest_path,
        )
        overall = render_empty_report(run_result, comparison)
        bodies = {}

    written = write_report(config.output_dir, bodies, overall=overall)
    for repository in run_result.repositories:
        if repository.scanned:
            log.info(
                "%s: %d image(s), %d finding(s) → %s",
                repository.name,
                len(repository.images),
                repository.subtotal.total,
                written[repository.name].name,
            )
        else:
            log.warning("%s: not scanned in this run (known from the baseline)", repository.name)

    write_entry(config.history_dir, entry_from_run(run_result))

    log.info(
        "%d of %d file(s) processed, %d failure(s)",
        summary.files_processed,
        summary.files_expected,
        len(summary.failures),
    )
    log.info(
        "unique images %d finding(s), sum of subtotals %d finding(s) across %d repository(ies)",
        run_result.unique_image_total.total,
        run_result.sum_of_subtotals_total.total,
        summary.repositories_covered,
    )
    # Evaluated only after every report and the history entry are on disk. A gate
    # that fires before publishing tells a team the build is red and leaves them
    # nothing to act on (FR-024b).
    return resolve(
        fatal=False,
        threshold_breached=evaluate_thresholds(config, run_result, log),
        # Deliberately not ``summary.had_failures``: an unreadable *history* file
        # degrades the comparison, not the current data, and contracts/cli.md is
        # explicit that it must not by itself produce exit 2.
        had_failures=bool(summary.failures),
    )


def main(argv: list[str] | None = None) -> None:
    """The only ``sys.exit`` caller in the application (Principle V).

    A ``FatalError`` is reported as one line on stderr with no traceback: the
    reader is scanning a CI log, and a stack trace would bury the sentence that
    says what to fix.
    """
    try:
        config, manifest = resolve_config(argv)
    except _CleanExit as clean:  # --help / --version
        if clean.message:
            sys.stderr.write(clean.message)
        sys.exit(clean.status)
    except _ArgumentError as bad:
        sys.stderr.write(f"{PROGRAM}: error: {bad}\n")
        sys.stderr.write(f"Run '{PROGRAM} --help' for usage.\n")
        sys.exit(ExitCode.FATAL)
    except FatalError as fatal:
        sys.stderr.write(f"{PROGRAM}: error: {fatal}\n")
        sys.exit(ExitCode.FATAL)

    try:
        code = run(config, manifest)
    except FatalError as fatal:
        # Reached only for conditions discovered mid-run that make the output
        # untrustworthy — a filename collision, an unwritable output directory.
        configure(verbose=config.verbose).error("%s", fatal)
        sys.exit(ExitCode.FATAL)
    sys.exit(code)
