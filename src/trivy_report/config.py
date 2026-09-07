"""Resolved run configuration.

Frozen, and validated once at construction. Config that cannot drift mid-run
means any log line describing the settings is true for the whole run, and every
stage sees the same values.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from types import MappingProxyType

from trivy_report.models import Severity

DEFAULT_RETENTION_DAYS = 90


@dataclass(frozen=True, slots=True)
class RunConfig:
    """Everything one run needs, resolved from the CLI and the manifest."""

    input_dir: Path
    manifest_path: Path
    history_dir: Path
    output_dir: Path
    scan_date: date
    """Resolved before construction: ``--scan-date``, then the manifest field, then
    a fatal error. The system clock is never consulted — that is what makes
    output reproducible and 'what changed since yesterday' answerable (D7)."""

    retention_days: int = DEFAULT_RETENTION_DAYS
    thresholds: Mapping[Severity, int] = field(default_factory=dict)
    """Empty by default, so a run that configured no gate can never exit 3
    (FR-028). A tool that fails builds it was not asked to fail gets disabled."""

    verbose: bool = False

    def __post_init__(self) -> None:
        for name in ("input_dir", "manifest_path", "history_dir", "output_dir"):
            value = getattr(self, name)
            if not isinstance(value, Path):
                raise ValueError(f"{name} must be a Path, got {value!r}")

        # Only the inputs must already exist. history_dir and output_dir are
        # created by the application (FR-008a, FR-020b), so requiring them here
        # would make a first run impossible.
        if not self.input_dir.is_dir():
            raise ValueError(f"--input directory does not exist: {self.input_dir}")
        if not self.manifest_path.is_file():
            raise ValueError(f"--manifest file does not exist: {self.manifest_path}")

        if not isinstance(self.scan_date, date):
            raise ValueError(f"scan_date must be a datetime.date, got {self.scan_date!r}")

        if (
            not isinstance(self.retention_days, int)
            or isinstance(self.retention_days, bool)
            or self.retention_days < 1
        ):
            # Zero would delete the entry written moments earlier, leaving the
            # next run with no baseline at all.
            raise ValueError(f"--retention-days must be >= 1, got {self.retention_days!r}")

        resolved: dict[Severity, int] = {}
        for severity, count in self.thresholds.items():
            if not isinstance(severity, Severity):
                raise ValueError(f"threshold key must be a Severity, got {severity!r}")
            if not isinstance(count, int) or isinstance(count, bool) or count < 1:
                # A threshold of 0 would fire on a perfectly clean scan.
                raise ValueError(f"threshold for {severity} must be >= 1, got {count!r}")
            resolved[severity] = count
        object.__setattr__(
            self,
            "thresholds",
            MappingProxyType({s: resolved[s] for s in Severity if s in resolved}),
        )

    @property
    def repositories_dir(self) -> Path:
        """Where per-repository reports go (FR-020)."""
        return self.output_dir / "repositories"
