"""Deduplication and folding of findings into counts (FR-003, FR-004, D5).

Findings are consumed as a stream and discarded as they are counted, so memory
stays proportional to image count rather than finding count (SC-004). A fleet
scan with a hundred thousand findings holds only the keys it has already seen for
the *current* image.

The dedup key is ``(image_ref, VulnerabilityID, PkgName, PkgPath)``. Two
decisions in that key carry the design:

- ``InstalledVersion`` is **excluded**: two Trivy result blocks reporting the same
  vulnerability with different observed versions describe one problem, and
  counting it twice would inflate the report.
- ``PkgPath`` is **included**: one library vendored at two paths is two instances
  to remediate.
"""

from __future__ import annotations

from collections.abc import Iterable

from trivy_report.models import (
    Finding,
    ImageRef,
    ImageScan,
    Severity,
    SeverityCounts,
)

_FIELD_FOR = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.UNKNOWN: "unknown",
}


def dedupe_counts(findings: Iterable[Finding]) -> SeverityCounts:
    """Fold a finding stream into deduplicated counts.

    The image reference is not part of the key here because this function is
    called once per image — the ``image_ref`` component of the documented key is
    implicit in the call boundary, which is also what keeps the seen-set small.

    On a duplicate key whose severities disagree, the first occurrence wins. The
    choice of bucket is arbitrary but the total is not: the instance is counted
    exactly once either way, and inflating the total would be the real error.
    """
    tallies = dict.fromkeys(_FIELD_FOR.values(), 0)
    seen: set[tuple[str, str, str]] = set()

    for finding in findings:
        key = finding.dedup_key
        if key in seen:
            continue
        seen.add(key)
        tallies[_FIELD_FOR[finding.severity]] += 1

    return SeverityCounts(**tallies)


def normalize_image(
    *,
    repository: str,
    image: ImageRef,
    findings: Iterable[Finding],
    parse_failed: bool = False,
) -> ImageScan:
    """Turn one image's finding stream into an ``ImageScan``.

    An image with no findings is retained with all-zero counts, never dropped
    (FR-006): a reader must be able to see that an image was scanned and found
    clean, which is different from not appearing at all.

    ``parse_failed=True`` propagates onto the scan so the row can render ``?``
    rather than ``0``. A parse failure must never be presentable as a clean image.
    """
    return ImageScan(
        repository=repository,
        image=image,
        counts=dedupe_counts(findings),
        parse_failed=parse_failed,
    )
