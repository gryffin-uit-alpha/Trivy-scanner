"""Render the fleet report (contracts/report-format.md § Overall report).

A pure function from the model to text, like ``repo_report``: no files, no clock,
no configuration, so the same ``ScanRun`` always renders the same bytes
(Principle III).

The fleet report exists to state something the per-repository reports cannot: two
grand totals that disagree with each other. Three decisions here are what keep
that disagreement legible rather than looking like an arithmetic error.

- **Both totals are labelled with their counting rule** (FR-017a). A bare pair of
  different numbers reads as a bug; the labels turn it into two answers to two
  questions — how much distinct risk is deployed, and how much work sits on each
  team's plate.
- **The gap is explained by a count of shared images, and only when there is a
  gap** (FR-017b). Printed beside two identical rows the sentence would send a
  reader hunting for a discrepancy that is not there.
- **A repository that was not scanned gets a section saying so, with no table**
  (Story 2 scenario 4). A silent omission reads as "nothing to report", and a
  table of zeros reads as a clean scan — both are the opposite of the truth.

``Grand Totals`` is an ``##`` heading rather than the ``###`` the contract sample
shows, because ``###`` is reserved for repository sections: the section list is
what a reader skims to find their repository, and a non-repository entry in it
would be read as one.
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
GRAND_TOTAL_HEADERS = ["Grand total", *md.SEVERITY_HEADERS, "Total"]

UNIQUE_LABEL = "Unique images"
SUM_LABEL = "Sum of subtotals"

UNIQUE_RULE = "each image counted once"
SUM_RULE = "shared images counted per repository"

TWO_TOTALS_NOTE = "Two totals are reported because one image can be shared by several repositories."
"""Says the same thing as the gap sentence's clause without reusing its wording.
The phrase "referenced by more than one repository" is reserved for the gap
sentence, which is printed only when there *is* a gap: sharing the phrasing would
put the explanation of a discrepancy on the page beside two identical rows."""

THRESHOLD_NOTE = "Threshold evaluation uses the **unique images** total."


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def _distinct_image_count(run: ScanRun) -> int:
    """Distinct images across the whole fleet, counted by unique-image key.

    One physical image referenced by three repositories is one image (D6), so
    this is deliberately smaller than the number of manifest entries.
    """
    return len({image.image.ref for repo in run.repositories for image in repo.images})


def _scanned(run: ScanRun) -> tuple[RepositoryScan, ...]:
    return tuple(repo for repo in run.repositories if repo.scanned)


def _summary_table(run: ScanRun, comparison: Comparison) -> list[str]:
    """The Summary table: what this run covered, before any count is shown.

    ``Repositories scanned`` counts only repositories with evidence. A repository
    known from history but absent from this run is reported in its own section as
    a coverage gap, and folding it in here would claim it was looked at.
    """
    body = [
        ["Repositories scanned", str(len(_scanned(run)))],
        ["Distinct images", str(_distinct_image_count(run))],
        ["Images shared across repositories", str(run.shared_image_count)],
        [
            "Baseline",
            md.NO_BASELINE_SUMMARY
            if comparison.baseline_date is None
            else comparison.baseline_date.isoformat(),
        ],
    ]
    return ["## Summary", "", *md.table(["Metric", "Value"], body)]


# ---------------------------------------------------------------------------
# Grand totals
# ---------------------------------------------------------------------------


def _gap_sentence(run: ScanRun) -> list[str]:
    """The sentence that accounts for the difference between the two rows.

    Omitted when the totals agree, because there is then nothing to account for.
    The plural is inflected: a sentence reading "2 image" undermines the number it
    exists to explain.
    """
    count = run.shared_image_count
    if count == 0:
        return []
    noun = "image" if count == 1 else "images"
    return [
        f"The gap between the two rows is accounted for by {md.bold(f'{count} {noun}')} "
        "referenced by more than one repository."
    ]


def _grand_totals(run: ScanRun, comparison: Comparison) -> list[str]:
    """Both grand totals, each with its own trend (FR-017d).

    Reusing one total's trend for the other would attach a number to a claim it
    does not support: the unique total can hold steady while the sum of subtotals
    climbs, simply because one more repository started referencing an image that
    was already deployed.
    """
    body = [
        [
            f"{md.bold(UNIQUE_LABEL)} ({UNIQUE_RULE})",
            *md.count_cells(run.unique_image_total, comparison.unique_total_trend, strong=True),
        ],
        [
            f"{md.bold(SUM_LABEL)} ({SUM_RULE})",
            *md.count_cells(run.sum_of_subtotals_total, comparison.sum_total_trend, strong=True),
        ],
    ]
    return [
        "## Grand Totals",
        "",
        TWO_TOTALS_NOTE,
        "",
        *md.table(GRAND_TOTAL_HEADERS, body),
        "",
        *_gap_sentence(run),
        THRESHOLD_NOTE,
    ]


# ---------------------------------------------------------------------------
# By Repository
# ---------------------------------------------------------------------------


def _repositories_by_ref(run: ScanRun) -> dict[str, tuple[str, ...]]:
    """Which repositories reference each unique image, sorted.

    Keyed by ``ref`` rather than by name: two repositories running different
    builds of one name are running different images, and calling that "shared"
    would claim a gap that does not exist.
    """
    found: dict[str, set[str]] = {}
    for repo in run.repositories:
        for image in repo.images:
            found.setdefault(image.image.ref, set()).add(repo.name)
    return {ref: tuple(sorted(names)) for ref, names in found.items()}


def _shared_notes(repository: RepositoryScan, by_ref: dict[str, tuple[str, ...]]) -> list[str]:
    """One blockquote per image this repository shares with another (FR-017c).

    The same image in two repositories is work for both teams, so each section
    has to name the other — a reader who sees the row in only one report concludes
    the other team is clear.
    """
    lines: list[str] = []
    for row in image_rows(repository):
        others = sorted(
            {name for ref in row.refs for name in by_ref.get(ref, ()) if name != repository.name}
        )
        if not others:
            continue
        named = ", ".join(md.code(name) for name in others)
        lines.append(f"> {md.code(row.name)} is also referenced by {named}.")
    return lines


def _images_table(repository: RepositoryScan, comparison: Comparison) -> list[str]:
    """One row per image name, then a bold Subtotal — same shape as the
    per-repository report, so a reader reconciling the two is not re-learning a
    layout."""
    body: list[list[str]] = []
    for row in image_rows(repository):
        trends = comparison.image_trends.get((repository.name, row.name))
        body.append(
            [
                md.code(row.name),
                ", ".join(md.escape(tag) for tag in row.tags),
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
    return md.table(IMAGE_HEADERS, body)


def _unscanned_section(
    repository: RepositoryScan,
    comparison: Comparison,
    baseline: HistoryEntry | None,
) -> list[str]:
    """A repository known from history and absent from this run.

    No table at all: it has no evidence to tabulate, and a row of zeros would read
    as a clean scan. The last-known counts are what make the notice actionable —
    "not scanned" alone does not say whether anyone should care.
    """
    heading = [f"### {md.escape(repository.name)}", ""]
    if baseline is None or comparison.baseline_date is None:
        return [*heading, md.bold("Not scanned in this run.")]
    last_known = baseline.repo_subtotals().get(repository.name, SeverityCounts())
    figures = ", ".join(
        f"{last_known.get(severity)} {severity.value}" for severity in md.SEVERITY_COLUMNS
    )
    return [
        *heading,
        f"{md.bold('Not scanned in this run.')} Present in the "
        f"{comparison.baseline_date.isoformat()} baseline with {figures}.",
    ]


def _repository_sections(
    run: ScanRun,
    comparison: Comparison,
    baseline: HistoryEntry | None,
) -> list[list[str]]:
    """One ``###`` section per repository, sorted by name (FR-017).

    ``run.repositories`` is already sorted by ``ScanRun``, so the order here has
    one definition rather than two that could drift.
    """
    by_ref = _repositories_by_ref(run)
    blocks: list[list[str]] = []
    for repository in run.repositories:
        if not repository.scanned:
            blocks.append(_unscanned_section(repository, comparison, baseline))
            continue
        block = [
            f"### {md.escape(repository.name)}",
            "",
            *_images_table(repository, comparison),
        ]
        notes = _shared_notes(repository, by_ref)
        if notes:
            block += ["", *notes]
        blocks.append(block)
    return blocks


# ---------------------------------------------------------------------------
# Run summary
# ---------------------------------------------------------------------------


def _run_summary(run: ScanRun) -> list[str]:
    """The Run Summary (FR-019).

    Coverage reads ``N of M known`` rather than a bare ``N``: one number alone
    cannot distinguish a one-repository fleet from a fleet that lost a repository
    overnight, and that is exactly the difference a reader needs.

    ``Files failed`` counts only *expected* files, so ``processed + failed ==
    expected`` closes for a reader adding the three numbers up (invariant 5). An
    orphan was never expected by the manifest; it is still listed in the Failures
    table below, described there as a file nobody declared.
    """
    summary = run.summary
    return [
        "## Run Summary",
        "",
        md.bullet("Files expected", summary.files_expected),
        md.bullet("Files processed", summary.files_processed),
        md.bullet("Files failed", len(expected_failures(summary.failures))),
        md.bullet(
            "Repositories covered",
            f"{summary.repositories_covered} of {len(run.repositories)} known",
        ),
        md.bullet("Images covered", summary.images_covered),
        md.baseline_summary_line(summary.baseline_date),
        *md.history_lines(
            pruned=summary.history_files_pruned,
            skipped=summary.history_files_skipped,
        ),
    ]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def render_overall_report(
    run: ScanRun,
    comparison: Comparison,
    baseline: HistoryEntry | None,
) -> str:
    """Render ``overall.md`` for one run.

    Every failure is listed, including ones no repository can be blamed for: an
    orphan file is by definition absent from the manifest, so this is the only
    report where it can be shown at all.
    """
    return md.document(
        [
            "# Fleet Vulnerability Report",
            md.header_block(
                scan_date=run.scan_date,
                baseline_date=comparison.baseline_date,
                version=__version__,
            ),
            md.COUNTING_SEMANTICS_NOTE,
            _summary_table(run, comparison),
            _grand_totals(run, comparison),
            "## By Repository",
            *_repository_sections(run, comparison, baseline),
            _run_summary(run),
            md.failures_table(run.summary.failures),
        ]
    )
