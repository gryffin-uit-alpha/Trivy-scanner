"""Aggregation: image scans → repositories → one run.

Every total in a report is produced here by folding with
``SeverityCounts.__add__``, never by arithmetic written into a renderer. A number
a reader sees is therefore the sum of the rows above it by construction, and the
model re-checks that (invariant 2) rather than trusting this module.

Two counting rules coexist deliberately (D6, FR-017a):

- ``image.ref`` (``name@digest`` or ``name:tag``) identifies a *unique image*, and
  so drives deduplication and the unique-image grand total.
- the image *name* identifies the *subject tracked over time*, and so drives the
  rendered rows — which is why ``image_rows`` collapses two tags of one name into
  a single row.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date

from trivy_report.models import (
    ImageScan,
    RepositoryScan,
    RunSummary,
    ScanRun,
    SeverityCounts,
    sum_counts,
)


def fold_repositories(
    scans: Iterable[ImageScan], unscanned: Iterable[str] = ()
) -> tuple[RepositoryScan, ...]:
    """Group image scans into repositories, sorted by name.

    ``unscanned`` names repositories known from history but absent from this run.
    They become empty ``scanned=False`` entries so the report can say so out loud
    — a repository dropping out of the scan is a coverage gap, and a silent
    omission would read as "nothing to report" (Story 2 scenario 4).

    A name appearing in both is treated as scanned: the run has evidence for it,
    which outranks the archive's expectation.
    """
    grouped: dict[str, list[ImageScan]] = {}
    for scan in scans:
        grouped.setdefault(scan.repository, []).append(scan)

    repositories = [
        RepositoryScan(
            name=name,
            images=tuple(images),
            subtotal=sum_counts(i.counts for i in images),
        )
        for name, images in grouped.items()
    ]
    repositories += [
        RepositoryScan(name=name, images=(), subtotal=SeverityCounts(), scanned=False)
        for name in dict.fromkeys(unscanned)
        if name not in grouped
    ]
    # RepositoryScan sorts its own images; ScanRun sorts repositories. Sorting
    # here too keeps the function usable on its own without a ScanRun.
    return tuple(sorted(repositories, key=lambda r: r.name))


@dataclass(frozen=True, slots=True)
class ImageRow:
    """One rendered row of an Images table: name-level, not reference-level.

    The trend key is the image name (D6), so a per-reference row would pair a
    count for ``api:1.1`` with a delta computed for ``api`` as a whole. Collapsing
    to the name keeps the count and its delta describing the same subject, and the
    ``tags`` column makes the collapse visible rather than implicit.
    """

    name: str
    tags: tuple[str, ...]
    """Every tag observed for this name this run, sorted. A reference carrying no
    tag contributes its digest instead, so the column is never empty."""

    counts: SeverityCounts
    parse_failed: bool
    """True when **any** reference under this name failed to parse.

    Deliberately pessimistic: a row summing one good tag and one unreadable tag
    would be a plausible-looking number that is quietly too low, which is worse
    than an honest ``?``.
    """

    refs: tuple[str, ...]
    """The unique-image keys folded into this row, sorted. Not rendered; kept so a
    caller can explain the row without re-deriving it."""


def image_rows(repository: RepositoryScan) -> tuple[ImageRow, ...]:
    """Collapse a repository's image scans into name-level rendered rows."""
    grouped: dict[str, list[ImageScan]] = {}
    for scan in repository.images:
        grouped.setdefault(scan.image.name, []).append(scan)

    rows = [
        ImageRow(
            name=name,
            tags=tuple(sorted({s.image.tag or s.image.digest or "" for s in scans})),
            counts=sum_counts(s.counts for s in scans),
            parse_failed=any(s.parse_failed for s in scans),
            refs=tuple(sorted({s.image.ref for s in scans})),
        )
        for name, scans in grouped.items()
    ]
    return tuple(sorted(rows, key=lambda r: r.name))


def unique_image_counts(
    scans: Iterable[ImageScan],
) -> dict[str, SeverityCounts]:
    """Counts per distinct ``image.ref``, each reference counted exactly once.

    One physical image referenced by three repositories is one deployed risk, so
    the unique total must not multiply it (FR-017a).

    When two repositories report *different* counts for the same reference the
    larger is kept. That can only happen when one of the two source files failed
    to parse, and in that case the parsed number is the better evidence — taking
    the smaller would let one broken file deflate the fleet total.
    """
    per_ref: dict[str, SeverityCounts] = {}
    for scan in sorted(scans, key=lambda s: (s.image.ref, s.repository)):
        existing = per_ref.get(scan.image.ref)
        if existing is None or scan.counts.total > existing.total:
            per_ref[scan.image.ref] = scan.counts
    return per_ref


def shared_image_refs(scans: Iterable[ImageScan]) -> tuple[str, ...]:
    """References that carry findings and appear in more than one repository.

    This number exists in the report for exactly one purpose: to explain the gap
    between the two grand totals (FR-017b). A shared image with no findings widens
    no gap, so counting it would leave the explanation contradicting the
    arithmetic it is meant to explain — and the model rejects that pairing
    outright (invariant 4).
    """
    repositories_by_ref: dict[str, set[str]] = {}
    counts_by_ref: dict[str, int] = {}
    for scan in scans:
        repositories_by_ref.setdefault(scan.image.ref, set()).add(scan.repository)
        counts_by_ref[scan.image.ref] = max(counts_by_ref.get(scan.image.ref, 0), scan.counts.total)
    return tuple(
        sorted(
            ref
            for ref, repositories in repositories_by_ref.items()
            if len(repositories) > 1 and counts_by_ref[ref] > 0
        )
    )


def build_scan_run(
    scans: Sequence[ImageScan],
    *,
    scan_date: date,
    summary: RunSummary,
    unscanned: Iterable[str] = (),
) -> ScanRun:
    """Fold everything one run measured into a single ``ScanRun``.

    Both grand totals are computed because they answer different questions
    (FR-017a): the unique total says how much distinct risk is deployed, the sum
    of subtotals says how much work sits on each team's plate. Reporting only one
    would make the other look like an arithmetic error.
    """
    scans = tuple(scans)
    repositories = fold_repositories(scans, unscanned=unscanned)
    return ScanRun(
        scan_date=scan_date,
        repositories=repositories,
        unique_image_total=sum_counts(unique_image_counts(scans).values()),
        sum_of_subtotals_total=sum_counts(r.subtotal for r in repositories),
        shared_image_count=len(shared_image_refs(scans)),
        summary=summary,
    )
