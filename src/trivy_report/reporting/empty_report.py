"""Render ``overall.md`` when nothing was scanned (FR-021).

This is the most dangerous state the application can report, and the only report
that has to argue against its own headline. A run that found no vulnerabilities
because everything is clean and a run that found none because the scanning stage
never executed produce the same numbers — zero — and a reader who takes the second
for the first concludes an unscanned fleet is a safe one.

So the layout is deliberately *not* the overall report with zeros substituted in:

- **No Grand Totals table.** A table of zeros is exactly the clean bill of health
  the disclaimer exists to deny, and it would be the first thing a reader's eye
  lands on — outweighing any amount of prose beneath it.
- **A disclaimer in words, not a numeric hint.** "0 images scanned" is a fact a
  reader has to interpret; "this is not a clean bill of health" is not.
- **A next step.** The two things worth checking are the scanning stage and the
  manifest generator, and naming them turns a warning into an action.

The exit code stays ``0`` because the application did its job correctly. The
pipeline is what may have failed, and this report is where that is said.
"""

from __future__ import annotations

from trivy_report import __version__
from trivy_report.models import Comparison, ScanRun
from trivy_report.reporting import markdown as md

DISCLAIMER = (
    "This is not a clean bill of health — it means nothing was scanned. Check "
    "that the scanning stage ran and that the manifest was generated."
)


def _no_results(run: ScanRun) -> list[str]:
    """The headline section, stating the entry count that produced it.

    The count is named so the reader can distinguish "the manifest was empty" from
    "the manifest listed files that all failed" — a different problem with a
    different fix, reported by the ordinary overall report instead.
    """
    return [
        "## No Results",
        "",
        "No scan results were found for this run. The manifest contained "
        f"{run.summary.files_expected} entries.",
        "",
        DISCLAIMER,
    ]


def _run_summary(run: ScanRun) -> list[str]:
    """A zeroed Run Summary, with the baseline date if one exists.

    The baseline line is the reason this section is worth printing at all: an empty
    run that reads like a first run hides the fact that yesterday worked and today
    did not.

    The archive housekeeping lines appear here too. This report is written on the
    day something went wrong upstream, which is exactly the day an operator needs to
    know whether the run also pruned entries or preserved an unreadable one.
    """
    summary = run.summary
    return [
        "## Run Summary",
        "",
        md.bullet("Files expected", summary.files_expected),
        md.bullet("Files processed", summary.files_processed),
        md.bullet("Files failed", len(summary.failures)),
        md.bullet("Repositories covered", summary.repositories_covered),
        md.bullet("Images covered", summary.images_covered),
        md.baseline_summary_line(summary.baseline_date),
        *md.history_lines(
            pruned=summary.history_files_pruned,
            skipped=summary.history_files_skipped,
        ),
    ]


def render_empty_report(run: ScanRun, comparison: Comparison) -> str:
    """Render the no-results ``overall.md``.

    Failures are still listed. An orphan result file beside an empty manifest is
    the single most likely real cause of this state — the scanner worked and the
    manifest generator did not — so suppressing it here would hide the evidence
    that explains the whole report.
    """
    return md.document(
        [
            "# Fleet Vulnerability Report",
            md.header_block(
                scan_date=run.scan_date,
                baseline_date=comparison.baseline_date,
                version=__version__,
            ),
            _no_results(run),
            _run_summary(run),
            md.failures_table(run.summary.failures),
        ]
    )
