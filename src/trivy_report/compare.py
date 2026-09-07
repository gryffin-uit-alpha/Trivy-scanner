"""Compare one run against its baseline (FR-014 – FR-016, invariants 6 and 7).

Two rules shape everything here.

**The trend key is ``(repository, image_name)``, never the full reference (D6).**
A tag bump is the same tracked subject with different counts, so it must render as
a delta. Keying on the reference would turn every deploy into one image vanishing
and another appearing, and the trend column — the reason this feature exists —
would be permanently empty.

**BASELINE is not FLAT (FR-015).** "Nothing to compare against" is a different
fact from "no change", and rendering `→ 0` for the former would assert a
comparison that never happened.

``Comparison`` carries keys and trends only, never counts. Last-known counts for a
removed image or an unscanned repository already live in the baseline
``HistoryEntry``, and the renderers read them from there — a second copy could
drift from the first.
"""

from __future__ import annotations

from trivy_report.models import (
    Comparison,
    HistoryEntry,
    ScanRun,
    SeverityCounts,
    TrendSet,
)


def _current_image_counts(run: ScanRun) -> dict[tuple[str, str], SeverityCounts]:
    """This run's counts keyed by trend key.

    Two references to one image name inside a repository (a tag rolling forward
    mid-deploy) fold together, matching how the row is rendered and how the entry
    is persisted, so the count and its delta always describe the same subject.

    An image whose file failed to parse is excluded rather than counted as zero:
    it renders ``?`` and gets no trend, because a zero would compare as a large
    improvement and read as remediation that never happened.
    """
    counts: dict[tuple[str, str], SeverityCounts] = {}
    for repository in run.repositories:
        for image in repository.images:
            if image.parse_failed:
                continue
            key = (repository.name, image.image.name)
            counts[key] = counts.get(key, SeverityCounts()) + image.counts
    return counts


def compare_run(run: ScanRun, baseline: HistoryEntry | None) -> Comparison:
    """Build the comparison between ``run`` and ``baseline``.

    ``baseline is None`` — a first run, an empty archive, or an archive holding
    nothing readable and earlier than this date — yields all-BASELINE trends with
    empty new/removed tuples (invariant 7). Listing every image as an addition on
    a first run would be noise, not information.
    """
    scanned = {repo.name for repo in run.repositories if repo.scanned}
    current_images = _current_image_counts(run)
    current_repos = {repo.name: repo.subtotal for repo in run.repositories if repo.scanned}

    if baseline is None:
        return Comparison(
            baseline_date=None,
            image_trends={key: TrendSet.all_baseline() for key in current_images},
            repo_trends={name: TrendSet.all_baseline() for name in current_repos},
            unique_total_trend=TrendSet.all_baseline(),
            sum_total_trend=TrendSet.all_baseline(),
        )

    baseline_images = dict(baseline.image_counts())
    baseline_repos = dict(baseline.repo_subtotals())

    # A repository the baseline knew about that this run did not scan at all. Not
    # a fall to zero: comparing an absent repository against its last-known
    # subtotal would render a large DOWN delta and read as remediation, when in
    # fact nobody looked. It gets an explicit "not scanned" statement instead.
    unscanned = tuple(sorted(name for name in baseline_repos if name not in scanned))
    unscanned_set = set(unscanned)

    image_trends = {
        key: TrendSet.compare(counts, baseline_images.get(key))
        for key, counts in current_images.items()
    }
    repo_trends = {
        name: TrendSet.compare(subtotal, baseline_repos.get(name))
        for name, subtotal in current_repos.items()
    }

    new_images = tuple(sorted(key for key in current_images if key not in baseline_images))
    removed_images = tuple(
        sorted(
            key
            for key in baseline_images
            if key not in current_images
            # Images of an unscanned repository are already covered by that
            # repository's "not scanned" line; listing them again as removals
            # would double-report one coverage gap as two different events.
            and key[0] not in unscanned_set
        )
    )

    return Comparison(
        baseline_date=baseline.scan_date,
        image_trends=image_trends,
        repo_trends=repo_trends,
        # Each grand total is compared against its own counterpart (FR-017d):
        # they answer different questions, so reusing one trend for both would
        # attach a number to a claim it does not support.
        unique_total_trend=TrendSet.compare(run.unique_image_total, baseline.unique_image_total),
        sum_total_trend=TrendSet.compare(
            run.sum_of_subtotals_total, baseline.sum_of_subtotals_total
        ),
        new_images=new_images,
        removed_images=removed_images,
        unscanned_repositories=unscanned,
    )
