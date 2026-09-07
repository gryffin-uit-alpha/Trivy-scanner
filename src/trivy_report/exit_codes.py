"""Exit codes and the precedence ladder that resolves them.

The pipeline branches on the exit code alone — no log parsing, no report
inspection (FR-024, SC-006a). That makes this module a public contract surface:
the numbers are fixed and changing one is a breaking change.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Process exit statuses, per contracts/cli.md.

    Codes 2 and 3 both guarantee the reports exist and are complete for the data
    that was processable (FR-024b). Only 1 means nothing was written.
    """

    SUCCESS = 0
    FATAL = 1
    PARTIAL = 2
    THRESHOLD = 3


def resolve(*, fatal: bool, threshold_breached: bool, had_failures: bool) -> ExitCode:
    """Apply the precedence ladder ``1 > 3 > 2 > 0`` (FR-024a, D13).

    THRESHOLD outranks PARTIAL deliberately: a security gate firing must never be
    masked by a data-quality problem. If some images failed to parse *and* the
    ones that did parse breached a threshold, the build must fail on the
    threshold — the vulnerabilities found are real regardless of what else went
    wrong.

    FATAL outranks everything because it means no reports were written at all, so
    there is nothing for the pipeline to publish or gate on.
    """
    if fatal:
        return ExitCode.FATAL
    if threshold_breached:
        return ExitCode.THRESHOLD
    if had_failures:
        return ExitCode.PARTIAL
    return ExitCode.SUCCESS
