"""Logging configuration (D14, FR-025).

Two handlers, split by level: progress to stdout, problems to stderr. Azure
DevOps colours stderr and folds stdout, so an operator scanning a failed build
sees the warnings without reading the whole log.

No timestamps by default — the CI agent stamps every line itself, and a second
timestamp is noise. Log content is deliberately outside the byte-identical
guarantee, which covers report files only.
"""

from __future__ import annotations

import logging
import sys

LOGGER_NAME = "trivy_report"


class _MaxLevelFilter(logging.Filter):
    """Passes records at or below ``level``, so stdout does not duplicate stderr."""

    def __init__(self, level: int) -> None:
        super().__init__()
        self.level = level

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno <= self.level


def configure(*, verbose: bool = False, stream_out=None, stream_err=None) -> logging.Logger:
    """Install the two handlers and return the application logger.

    Idempotent: existing handlers are replaced, so calling it twice in one
    process (as tests do) cannot double every line.

    The streams are injectable so tests can capture output without touching
    global state.
    """
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Never hand records to the root logger: a consuming application's own
    # configuration must not double-print ours.
    logger.propagate = False

    formatter = logging.Formatter("%(message)s")

    out = logging.StreamHandler(sys.stdout if stream_out is None else stream_out)
    out.setLevel(logging.DEBUG if verbose else logging.INFO)
    out.addFilter(_MaxLevelFilter(logging.INFO))
    out.setFormatter(formatter)
    logger.addHandler(out)

    err = logging.StreamHandler(sys.stderr if stream_err is None else stream_err)
    err.setLevel(logging.WARNING)
    # Warnings carry their level so a reader can tell a skipped history file
    # (degraded) from a parse failure (incomplete data).
    err.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(err)

    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Child logger under the application logger, so configuration applies."""
    if name is None:
        return logging.getLogger(LOGGER_NAME)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")
