"""Render one repository's report (contracts/report-format.md § per-repository).

A pure function from the model to text: it reads no files, no clock and no
configuration, so the same ``ScanRun`` always renders the same bytes (Principle
III).

Three decisions here are worth stating out loud:

- **Rows are name-level, not reference-level.** The trend key is
  ``(repository, image_name)`` (D6), so a per-reference row would pair a count for
  ``api:1.1`` with a delta computed for ``api`` as a whole. ``aggregate.image_rows``
  does the collapsing and the Tags column makes it visible.
- **An unreadable image renders ``?`` in every column, including Total.** A total
  of untrustworthy numbers is not a trustworthy number, and a ``0`` here would be a
  clean bill of health for a file nobody could read.
- **Removed Images is scoped to this repository and omitted when empty.** An
  empty section reads as "nothing was checked"; another repository's removal
  belongs in that repository's report.
"""

from __future__ import annotations

from trivy_report import __version__
from trivy_report.aggregate import image_rows
from trivy_report.models import (
    Comparison,
    HistoryEntry,
    RepositoryScan,
    ScanRun,
    SeverityCounts,
    TrendSet,
)
from trivy_report.reporting import markdown as md
from trivy_report.run_summary import expected_failures

IMAGE_HEADERS = ["Image", "Tags", *md.SEVERITY_HEADERS, "Total"]
REMOVED_HEADERS = ["Image", "Last known CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _images_table(repository: RepositoryScan, comparison: Comparison) -> list[str]:
    """The Images table: one row per image name, then a bold Subtotal.

    Every image appears, including zero-finding ones (FR-006): "scanned and clean"
    must be visibly different from "absent", and an omitted row is
    indistinguishable from an image nobody looked at.
    """
    body: list[list[str]] = []
    for row in image_rows(repository):
        trends = comparison.image_trends.get((repository.name, row.name))
        body.append(
            [
                md.code(row.name),
                ", ".join(md.escape(tag) for tag in row.tags),
                # A parse-failed row has no entry in ``image_trends`` at all —
                # comparing its zero against a real baseline would render a large
                # improvement and read as remediation that never happened.
                *md.count_cells(
                    row.counts,
                    trends or TrendSet.all_baseline(),
                    unknown=row.parse_failed,
                ),
            ]
        )
    body.append(
        [
            md.bold("Subtotal"),
            "",
            *md.count_cells(
                repository.subtotal,
                comparison.repo_trends.get(repository.name) or TrendSet.all_baseline(),
                strong=True,
            ),
        ]
    )
    return ["## Images", "", *md.table(IMAGE_HEADERS, body)]


def _removed_images(
    repository: RepositoryScan,
    comparison: Comparison,
    baseline: HistoryEntry | None,
) -> list[str]:
    """Images this repository held in the baseline and no longer holds.

    Rendered without trends: their counts are a record of the last time anyone
    looked, and a delta against a subject that is gone would describe a change in
    *coverage* as a change in *risk*.

    Counts come from the baseline entry rather than from ``Comparison``, which
    carries keys only — a second copy of numbers already on disk could drift from
    the first.
    """
    if baseline is None or comparison.baseline_date is None:
        return []
    removed = [key for key in comparison.removed_images if key[0] == repository.name]
    if not removed:
        return []
    last_known = baseline.image_counts()
    body = [
        [
            md.code(image_name),
            *md.plain_count_cells(last_known.get((repo, image_name), SeverityCounts())),
        ]
        for repo, image_name in removed
    ]
    return [
        "## Removed Images",
        "",
        f"Present in the {comparison.baseline_date.isoformat()} scan, absent from this one:",
        "",
        *md.table(REMOVED_HEADERS, body),
    ]


def _run_summary(run: ScanRun) -> list[str]:
    """The Run Summary, present in every report even on a clean run (FR-019).

    Run-level rather than repository-level on purpose: a reader needs to know
    whether the run itself was complete before trusting any number above. A report
    that only described its own repository could look complete while half the
    fleet failed to parse.

    ``Files failed`` counts expected files only, matching the fleet report's line
    exactly: two reports from one run disagreeing on a jointly-named figure reads
    as a bug in whichever the reader opened second. Orphans are still listed in the
    Failures table (invariant 5).
    """
    summary = run.summary
    return [
        "## Run Summary",
        "",
        md.bullet("Files expected", summary.files_expected),
        md.bullet("Files processed", summary.files_processed),
        md.bullet("Files failed", len(expected_failures(summary.failures))),
        md.bullet("Images covered", summary.images_covered),
        md.baseline_summary_line(summary.baseline_date),
        *md.history_lines(
            pruned=summary.history_files_pruned,
            skipped=summary.history_files_skipped,
        ),
    ]


def _failures(repository: RepositoryScan, run: ScanRun) -> list[str]:
    """Failures that could affect the numbers in *this* report.

    Scoped to this repository plus unattributed failures. An orphan file is by
    definition absent from the manifest, so nobody can say which repository it
    belonged to — it might have been one of these images, and hiding it here would
    let a missing image pass as an image with no findings.
    """
    relevant = [
        failure for failure in run.summary.failures if failure.repository in (repository.name, None)
    ]
    return md.failures_table(relevant)


def render_repository_report(
    repository: RepositoryScan,
    run: ScanRun,
    comparison: Comparison,
    baseline: HistoryEntry | None,
) -> str:
    """Render ``repositories/<repo>.md`` for one repository.

    The title carries the unsanitised name so the document names the repository a
    reader would recognise; the filename is the writer's concern (D11).
    """
    return md.document(
        [
            f"# Vulnerability Report: {md.escape(repository.name)}",
            md.header_block(
                scan_date=run.scan_date,
                baseline_date=comparison.baseline_date,
                version=__version__,
            ),
            md.COUNTING_SEMANTICS_NOTE,
            _images_table(repository, comparison),
            _removed_images(repository, comparison, baseline),
            _run_summary(run),
            _failures(repository, run),
        ]
    )
