"""Exception types, split along the line constitution Principle IV draws.

The distinction is not stylistic. It decides whether a run stops or continues,
and getting it wrong in either direction is harmful: stopping on a recoverable
problem loses a report the reader could have used, while continuing past a fatal
one publishes a report that is quietly wrong.
"""

from __future__ import annotations


class TrivyReportError(Exception):
    """Base for every error this application raises deliberately."""


class FatalError(TrivyReportError):
    """The run cannot proceed and nothing may be written (exit 1).

    Raised only when continuing would produce a report that misrepresents the
    truth: an unreadable or schema-invalid manifest, no resolvable scan date, a
    result path escaping the input directory, two repositories colliding on one
    output filename, an unwritable output directory.

    Ambiguity about *what the data means* is always fatal rather than guessed —
    a vulnerability report that silently attributes findings to the wrong
    repository is worse than no report (Principle IV).
    """


class RecoverableError(TrivyReportError):
    """One input is unusable; the run records it and continues (exit 2).

    A single malformed Trivy file must not deny the reader every other
    repository's report. The failure is recorded as a ``ParseFailure``, surfaced
    in the summary section of every report, and reflected in the exit code — so
    it is degraded, never hidden.
    """
