"""Run summary construction.

Every report carries a summary (FR-019) because a vulnerability report without
coverage information cannot be read safely: "0 CRITICAL" means one thing when
every image was scanned and something very different when half the files failed
to parse.

``RunSummary`` enforces the reconciliation itself (invariant 5). This module's job
is only to hand it consistent numbers and to keep the orphan exclusion in one
place, rather than leaving each caller to remember it.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date

from trivy_report.models import FailureKind, ParseFailure, RunSummary


def expected_failures(failures: Iterable[ParseFailure]) -> tuple[ParseFailure, ...]:
    """The failures that count against ``files_expected``.

    Orphans are excluded: the manifest never claimed them, so counting one as a
    failed *expected* file would make ``processed + failed == expected`` stop
    holding, and that arithmetic is what lets a reader trust the coverage line.
    An orphan is still a failure — it is reported in the Failures table and it
    still drives exit code ``2``.
    """
    return tuple(f for f in failures if f.kind is not FailureKind.ORPHAN_FILE)


def build_summary(
    *,
    files_expected: int,
    files_processed: int,
    failures: Iterable[ParseFailure] = (),
    repositories_covered: int,
    images_covered: int,
    baseline_date: date | None = None,
    history_files_pruned: int = 0,
    history_files_skipped: Iterable[str] = (),
) -> RunSummary:
    """Build the summary for one run.

    Keyword-only throughout: five of the arguments are integers, and a positional
    call site that transposed two of them would produce a summary that reconciles
    arithmetically while describing a different run.
    """
    return RunSummary(
        files_expected=files_expected,
        files_processed=files_processed,
        failures=tuple(failures),
        repositories_covered=repositories_covered,
        images_covered=images_covered,
        baseline_date=baseline_date,
        history_files_pruned=history_files_pruned,
        history_files_skipped=tuple(history_files_skipped),
    )


def _belongs_to(failure: ParseFailure, repository: str) -> bool:
    """Whether this failure should be shown under ``repository``.

    Two ways to qualify, and the difference matters. An *attributed* failure names
    its repository, which is authoritative. An *unattributed* one — an orphan file,
    which by definition no manifest entry claimed — is placed by its leading path
    segment, which is a directory-layout convention rather than a guarantee. That
    guess decides only where the failure is *displayed*; it never sets
    ``failure.repository``, so nothing downstream mistakes it for a fact.
    """
    if failure.repository is not None:
        return failure.repository == repository
    return failure.file.split("/", 1)[0] == repository


def failures_for_repository(summary: RunSummary, repository: str) -> tuple[ParseFailure, ...]:
    """This repository's failures, for its own report's Failures table.

    Orphans are included even though their repository is unknown: the file sits
    under a directory that a reader will associate with some repository, and
    hiding it from every per-repository report would mean the only place it
    appears is the fleet report.
    """
    return tuple(f for f in summary.failures if _belongs_to(f, repository))
