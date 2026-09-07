"""Frozen domain model.

Every entity here is immutable, so each pipeline stage returns new objects and
no stage can corrupt an earlier one's data. Stated invariants are enforced in
``__post_init__`` rather than trusted: a report whose subtotals silently
disagree with its rows is worse than one that refuses to be built.

Validation failures raise ``ValueError``. These are programming errors in the
pipeline, not recoverable input problems — recoverable input problems are
recorded as ``ParseFailure`` values by the modules that read files.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from types import MappingProxyType

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    """Severity levels in fixed report column order (FR-022).

    Declaration order IS the report order. It is never sorted alphabetically and
    never derived from input order, so two runs cannot produce different column
    layouts for the same data.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_trivy(cls, value: object) -> Severity:
        """Map a raw Trivy severity string onto a member.

        Anything unrecognised — absent, empty, a future Trivy level, or a
        non-string — becomes UNKNOWN. It is never folded into LOW and never
        discarded (FR-003): under-reporting a severity is a security failure,
        and dropping the finding entirely is worse.
        """
        if not isinstance(value, str):
            return cls.UNKNOWN
        try:
            return cls(value.strip().upper())
        except ValueError:
            return cls.UNKNOWN


class TrendDirection(StrEnum):
    """Direction of change against the baseline.

    BASELINE is deliberately distinct from FLAT: "nothing to compare" is not
    "no change" (FR-015).
    """

    UP = "UP"
    DOWN = "DOWN"
    FLAT = "FLAT"
    BASELINE = "BASELINE"


class FailureKind(StrEnum):
    """Why one input could not be used."""

    MALFORMED_JSON = "MALFORMED_JSON"  # not parseable as JSON
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"  # valid JSON, not a Trivy report
    FILE_MISSING = "FILE_MISSING"  # manifest entry references an absent file
    ORPHAN_FILE = "ORPHAN_FILE"  # file present, not in the manifest
    UNREADABLE = "UNREADABLE"  # permissions / IO error


# ---------------------------------------------------------------------------
# SeverityCounts — the aggregation unit
# ---------------------------------------------------------------------------

# Field name per severity member, so column iteration stays generic.
_COUNT_FIELDS: Mapping[Severity, str] = MappingProxyType(
    {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
        Severity.UNKNOWN: "unknown",
    }
)


@dataclass(frozen=True, slots=True)
class SeverityCounts:
    """Counts of finding instances, one per (image, CVE, package, path) (D5).

    ``SeverityCounts()`` is a valid and meaningful value: a clean image is a row
    of zeros, not an omission (FR-006).
    """

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0

    def __post_init__(self) -> None:
        # Invariant 1. A negative count means the fold went wrong upstream;
        # surfacing it here beats printing "-3 CRITICAL" in a security report.
        for severity, name in _COUNT_FIELDS.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{name} must be an int, got {value!r}")
            if value < 0:
                raise ValueError(f"{severity} count must be >= 0, got {value}")

    @property
    def total(self) -> int:
        """Sum of all five columns, UNKNOWN included."""
        return self.critical + self.high + self.medium + self.low + self.unknown

    def get(self, severity: Severity) -> int:
        """Count for one severity, for generic column iteration."""
        return getattr(self, _COUNT_FIELDS[severity])

    def __add__(self, other: SeverityCounts) -> SeverityCounts:
        """Field-wise addition. Makes aggregation a fold, not manual arithmetic."""
        if not isinstance(other, SeverityCounts):
            return NotImplemented
        return SeverityCounts(
            critical=self.critical + other.critical,
            high=self.high + other.high,
            medium=self.medium + other.medium,
            low=self.low + other.low,
            unknown=self.unknown + other.unknown,
        )

    def __ge__(self, other: SeverityCounts) -> bool:
        """Field-wise >=, used by the grand-total invariant (invariant 3)."""
        if not isinstance(other, SeverityCounts):
            return NotImplemented
        return all(self.get(s) >= other.get(s) for s in Severity)


def sum_counts(counts: Iterable[SeverityCounts]) -> SeverityCounts:
    """Fold a stream of counts into one. Empty stream yields all zeros."""
    return sum(counts, SeverityCounts())


# ---------------------------------------------------------------------------
# ImageRef — one entity, two keys (D6)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ImageRef:
    """Image identity.

    Carries two keys deliberately (see the plan's Complexity Tracking):

    - ``ref``       — name plus tag or digest. Identifies a *unique image*, and
                      so drives deduplication and the unique-image grand total.
    - ``trend_key`` — the name alone. Combined with the repository it identifies
                      the *subject being tracked over time*, so yesterday's
                      ``api:1.0`` and today's ``api:1.1`` compare as the same
                      image with changed counts rather than one removal plus one
                      addition.
    """

    name: str
    tag: str | None
    digest: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("image name must be a non-empty string")
        if self.tag is not None and (not isinstance(self.tag, str) or not self.tag.strip()):
            raise ValueError("image tag, when present, must be a non-empty string")
        if self.digest is not None and (
            not isinstance(self.digest, str) or not self.digest.strip()
        ):
            raise ValueError("image digest, when present, must be a non-empty string")
        if self.tag is None and self.digest is None:
            # Without either, two different builds of one name are indistinguishable
            # and the unique-image total would silently collapse them (D4).
            raise ValueError(f"image {self.name!r} needs at least one of tag or digest")

        # Registries and digests are case-insensitive; tags are NOT, so a tag's
        # case is preserved verbatim.
        object.__setattr__(self, "name", self.name.strip().lower())
        object.__setattr__(self, "tag", self.tag.strip() if self.tag is not None else None)
        object.__setattr__(
            self, "digest", self.digest.strip().lower() if self.digest is not None else None
        )

    @property
    def ref(self) -> str:
        """Unique-image key. Digest wins when present — it is the exact content."""
        if self.digest:
            return f"{self.name}@{self.digest}"
        return f"{self.name}:{self.tag}"

    @property
    def trend_key(self) -> str:
        """Trend key component: the name, without tag or digest."""
        return self.name


# ---------------------------------------------------------------------------
# Finding — transient, never persisted
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """One vulnerability instance in one image.

    Findings live only between parse and normalize. They are never persisted and
    never held for every image at once, which is what keeps memory proportional
    to image count rather than finding count.
    """

    vulnerability_id: str
    pkg_name: str
    pkg_path: str
    installed_version: str
    severity: Severity

    def __post_init__(self) -> None:
        if not isinstance(self.vulnerability_id, str) or not self.vulnerability_id.strip():
            raise ValueError("vulnerability_id must be a non-empty string")
        if not isinstance(self.pkg_name, str) or not self.pkg_name.strip():
            raise ValueError("pkg_name must be a non-empty string")

    @property
    def dedup_key(self) -> tuple[str, str, str]:
        """``(vulnerability_id, pkg_name, pkg_path)``.

        ``installed_version`` is deliberately excluded (D5): two Trivy result
        blocks reporting the same vulnerability with different observed versions
        describe one problem, and counting it twice would inflate the report.

        ``pkg_path`` IS included: one library vendored at two paths is two
        instances to remediate.
        """
        return (self.vulnerability_id, self.pkg_name, self.pkg_path)


# ---------------------------------------------------------------------------
# ImageScan / RepositoryScan
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ImageScan:
    """One image's result within one repository."""

    repository: str
    image: ImageRef
    counts: SeverityCounts
    parse_failed: bool = False
    """True when the source file could not be read or understood.

    The counts are then not trustworthy and the row renders ``?`` rather than
    ``0``, so a parse failure can never be misread as a clean image.
    """

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not self.repository.strip():
            raise ValueError("repository must be a non-empty string")

    @property
    def trend_key(self) -> tuple[str, str]:
        """``(repository, image_name)`` — coarser than ``ref``, deliberately (D6)."""
        return (self.repository, self.image.trend_key)


@dataclass(frozen=True, slots=True)
class RepositoryScan:
    """One GitOps repository's images and subtotal."""

    name: str
    images: tuple[ImageScan, ...]
    subtotal: SeverityCounts
    scanned: bool = True
    """False when the repository is known from history but absent from this run.

    Such a repository has no images and a zero subtotal, and is flagged in the
    report rather than silently vanishing — a repository dropping out of the
    scan is exactly the kind of coverage gap a reader must be told about.
    """

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("repository name must be a non-empty string")

        # Deterministic order at construction (FR-022), so no later stage has to
        # remember to sort. Secondary key is the full ref, so two tags of one
        # name order stably.
        object.__setattr__(
            self, "images", tuple(sorted(self.images, key=lambda i: (i.image.name, i.image.ref)))
        )

        # Invariant 2. A shared image contributes to EVERY referencing
        # repository's subtotal (FR-017c) — that is a property of the caller's
        # image list, and this check simply keeps the printed subtotal honest
        # about the rows above it.
        expected = sum_counts(i.counts for i in self.images)
        if self.subtotal != expected:
            raise ValueError(
                f"repository {self.name!r} subtotal {self.subtotal} does not equal "
                f"the sum of its {len(self.images)} images {expected}"
            )
        if not self.scanned and self.images:
            raise ValueError(f"repository {self.name!r} is marked unscanned but carries images")


# ---------------------------------------------------------------------------
# Failures and run summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParseFailure:
    """One input that could not be used, recorded rather than raised."""

    file: str
    """Path relative to ``--input``, so the message is reproducible across agents."""

    kind: FailureKind
    reason: str
    """Human-readable. Never a stack trace — the reader is a developer looking at
    a pipeline log, not a debugger."""

    repository: str | None
    """None precisely for ORPHAN_FILE, whose repository is unknowable."""

    def __post_init__(self) -> None:
        if not isinstance(self.file, str) or not self.file.strip():
            raise ValueError("failure file must be a non-empty string")
        if not isinstance(self.kind, FailureKind):
            raise ValueError(f"kind must be a FailureKind, got {self.kind!r}")
        if self.kind is FailureKind.ORPHAN_FILE:
            if self.repository is not None:
                # An orphan is by definition absent from the manifest, so any
                # repository attributed to it was invented.
                raise ValueError("ORPHAN_FILE must not name a repository — it is unknown")
        elif self.repository is not None and not str(self.repository).strip():
            raise ValueError("repository, when present, must be non-empty")


@dataclass(frozen=True, slots=True)
class RunSummary:
    """What happened during one run. Appears in every report (FR-019)."""

    files_expected: int
    files_processed: int
    failures: tuple[ParseFailure, ...]
    repositories_covered: int
    images_covered: int
    baseline_date: date | None
    history_files_pruned: int
    history_files_skipped: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in (
            "files_expected",
            "files_processed",
            "repositories_covered",
            "images_covered",
            "history_files_pruned",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative int, got {value!r}")

        object.__setattr__(self, "failures", tuple(sorted(self.failures, key=lambda f: f.file)))
        object.__setattr__(self, "history_files_skipped", tuple(sorted(self.history_files_skipped)))

        # Invariant 5. Orphans are excluded: an orphan was never expected by the
        # manifest, so counting it here would make the arithmetic un-closeable.
        # Every expected file must be accounted for as either processed or
        # failed, which is what lets a reader trust "N of M images scanned".
        accounted = self.files_processed + sum(
            1 for f in self.failures if f.kind is not FailureKind.ORPHAN_FILE
        )
        if accounted != self.files_expected:
            raise ValueError(
                f"run summary does not reconcile: {self.files_processed} processed + "
                f"{accounted - self.files_processed} non-orphan failures != "
                f"{self.files_expected} expected"
            )

    @property
    def had_failures(self) -> bool:
        """Any failure at all, orphans included — coverage is incomplete either way."""
        return bool(self.failures) or bool(self.history_files_skipped)


# ---------------------------------------------------------------------------
# ScanRun — one execution
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScanRun:
    """One complete execution's results.

    Carries both grand totals because they answer different questions
    (FR-017a): the unique total answers "how much distinct risk is deployed",
    the sum-of-subtotals answers "how much work is on each team's plate".
    """

    scan_date: date
    repositories: tuple[RepositoryScan, ...]
    unique_image_total: SeverityCounts
    sum_of_subtotals_total: SeverityCounts
    shared_image_count: int
    summary: RunSummary

    def __post_init__(self) -> None:
        if not isinstance(self.scan_date, date):
            raise ValueError(f"scan_date must be a datetime.date, got {self.scan_date!r}")
        if (
            not isinstance(self.shared_image_count, int)
            or isinstance(self.shared_image_count, bool)
            or self.shared_image_count < 0
        ):
            raise ValueError(
                f"shared_image_count must be a non-negative int, got {self.shared_image_count!r}"
            )

        object.__setattr__(
            self, "repositories", tuple(sorted(self.repositories, key=lambda r: r.name))
        )

        names = [r.name for r in self.repositories]
        if len(set(names)) != len(names):
            raise ValueError("repository names must be unique within a run")

        # Invariant 3: the sum of subtotals can never be smaller than the unique
        # total, because every unique image is counted at least once in it.
        if not self.sum_of_subtotals_total >= self.unique_image_total:
            raise ValueError(
                f"sum_of_subtotals_total {self.sum_of_subtotals_total} is field-wise less than "
                f"unique_image_total {self.unique_image_total}"
            )

        # Invariant 4: the gap between the two totals is exactly what sharing
        # causes, so shared_image_count == 0 must mean no gap, and any gap must
        # be explained by at least one shared image. Otherwise the report's
        # explanation of its own arithmetic would be wrong.
        totals_equal = self.sum_of_subtotals_total == self.unique_image_total
        if totals_equal and self.shared_image_count != 0:
            raise ValueError(
                f"shared_image_count is {self.shared_image_count} but the two grand totals are "
                f"equal — a shared image must widen the gap"
            )
        if not totals_equal and self.shared_image_count == 0:
            raise ValueError(
                "the two grand totals differ but shared_image_count is 0 — the gap is unexplained"
            )


# ---------------------------------------------------------------------------
# History entities
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HistoryImage:
    """One image's persisted counts, keyed by the TREND key.

    Stores ``image_name`` without tag or digest (D6). Persisting the full ref
    would make every tag bump look like one image disappearing and another
    appearing, which is precisely the comparison the feature exists to avoid.
    """

    repository: str
    image_name: str
    counts: SeverityCounts

    def __post_init__(self) -> None:
        if not self.repository.strip():
            raise ValueError("history image repository must be non-empty")
        if not self.image_name.strip():
            raise ValueError("history image_name must be non-empty")


@dataclass(frozen=True, slots=True)
class HistoryRepo:
    """One repository's persisted subtotal."""

    name: str
    subtotal: SeverityCounts

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("history repository name must be non-empty")


HISTORY_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """One persisted scan date.

    Holds counts only, never findings, so a 90-day archive stays small and can
    be read without re-parsing any Trivy JSON (FR-007).
    """

    schema_version: int
    scan_date: date
    images: tuple[HistoryImage, ...]
    repositories: tuple[HistoryRepo, ...]
    unique_image_total: SeverityCounts
    sum_of_subtotals_total: SeverityCounts
    shared_image_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.scan_date, date):
            raise ValueError(f"scan_date must be a datetime.date, got {self.scan_date!r}")
        if self.shared_image_count < 0:
            raise ValueError("shared_image_count must be >= 0")
        # Sorted for deterministic serialisation (FR-022).
        object.__setattr__(
            self, "images", tuple(sorted(self.images, key=lambda i: (i.repository, i.image_name)))
        )
        object.__setattr__(
            self, "repositories", tuple(sorted(self.repositories, key=lambda r: r.name))
        )

    def image_counts(self) -> Mapping[tuple[str, str], SeverityCounts]:
        """Counts keyed by trend key, for comparison lookup."""
        return MappingProxyType({(i.repository, i.image_name): i.counts for i in self.images})

    def repo_subtotals(self) -> Mapping[str, SeverityCounts]:
        """Subtotals keyed by repository name, for comparison lookup."""
        return MappingProxyType({r.name: r.subtotal for r in self.repositories})


# ---------------------------------------------------------------------------
# Comparison entities
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Trend:
    """One severity's change against the baseline."""

    direction: TrendDirection
    delta: int

    def __post_init__(self) -> None:
        if not isinstance(self.direction, TrendDirection):
            raise ValueError(f"direction must be a TrendDirection, got {self.direction!r}")
        if not isinstance(self.delta, int) or isinstance(self.delta, bool):
            raise ValueError(f"delta must be an int, got {self.delta!r}")

        # Invariant 6. Glyph and number are always rendered together (D10), so a
        # jointly impossible pair — say "↓ +3" — would actively mislead.
        if self.direction is TrendDirection.UP and self.delta <= 0:
            raise ValueError(f"UP requires a positive delta, got {self.delta}")
        if self.direction is TrendDirection.DOWN and self.delta >= 0:
            raise ValueError(f"DOWN requires a negative delta, got {self.delta}")
        if self.direction in (TrendDirection.FLAT, TrendDirection.BASELINE) and self.delta != 0:
            raise ValueError(f"{self.direction} requires a zero delta, got {self.delta}")

    @classmethod
    def compare(cls, current: int, baseline: int | None) -> Trend:
        """Build a trend from a current count and an optional baseline count.

        ``baseline is None`` means no comparable prior record, which yields
        BASELINE rather than FLAT (FR-015).
        """
        if baseline is None:
            return cls(direction=TrendDirection.BASELINE, delta=0)
        delta = current - baseline
        if delta > 0:
            return cls(direction=TrendDirection.UP, delta=delta)
        if delta < 0:
            return cls(direction=TrendDirection.DOWN, delta=delta)
        return cls(direction=TrendDirection.FLAT, delta=0)


@dataclass(frozen=True, slots=True)
class TrendSet:
    """Per-severity trends for one subject: an image row, a repository subtotal,
    or either grand total."""

    critical: Trend
    high: Trend
    medium: Trend
    low: Trend
    unknown: Trend

    def get(self, severity: Severity) -> Trend:
        """Trend for one severity, for generic column iteration."""
        return getattr(self, _COUNT_FIELDS[severity])

    @classmethod
    def compare(cls, current: SeverityCounts, baseline: SeverityCounts | None) -> TrendSet:
        """Compare every column at once. ``baseline=None`` yields all BASELINE."""
        return cls(
            **{
                name: Trend.compare(
                    current.get(severity), None if baseline is None else baseline.get(severity)
                )
                for severity, name in _COUNT_FIELDS.items()
            }
        )

    @classmethod
    def all_baseline(cls) -> TrendSet:
        """The jointly-BASELINE set used on a first run."""
        return cls.compare(SeverityCounts(), None)


@dataclass(frozen=True, slots=True)
class Comparison:
    """The full diff between this run and its baseline."""

    baseline_date: date | None
    image_trends: Mapping[tuple[str, str], TrendSet]
    repo_trends: Mapping[str, TrendSet]
    unique_total_trend: TrendSet
    sum_total_trend: TrendSet
    new_images: tuple[tuple[str, str], ...] = field(default=())
    removed_images: tuple[tuple[str, str], ...] = field(default=())
    unscanned_repositories: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        if self.baseline_date is not None and not isinstance(self.baseline_date, date):
            raise ValueError(f"baseline_date must be a date or None, got {self.baseline_date!r}")

        object.__setattr__(self, "image_trends", MappingProxyType(dict(self.image_trends)))
        object.__setattr__(self, "repo_trends", MappingProxyType(dict(self.repo_trends)))
        object.__setattr__(self, "new_images", tuple(sorted(self.new_images)))
        object.__setattr__(self, "removed_images", tuple(sorted(self.removed_images)))
        object.__setattr__(
            self, "unscanned_repositories", tuple(sorted(self.unscanned_repositories))
        )

        if self.baseline_date is None:
            # Invariant 7. On a first run everything is new, so listing every
            # image as an addition is noise rather than information.
            jointly_baseline = all(
                t.get(s).direction is TrendDirection.BASELINE
                for trends in (self.image_trends.values(), self.repo_trends.values())
                for t in trends
                for s in Severity
            ) and all(
                t.get(s).direction is TrendDirection.BASELINE
                for t in (self.unique_total_trend, self.sum_total_trend)
                for s in Severity
            )
            if not jointly_baseline:
                raise ValueError("no baseline date, so every trend must be BASELINE")
            if self.new_images or self.removed_images:
                raise ValueError("a baseline run has no new or removed images — everything is new")
