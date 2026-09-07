"""Turning rendered text into files (FR-020, FR-020a/b/c, D11).

This module owns every filesystem decision the reports involve, and three of them
are safety properties rather than conveniences:

- **A sanitisation collision is fatal.** Two repositories whose names reduce to
  one filename would mean one report silently overwriting the other, and the
  survivor would look complete. Refusing the run is the only honest outcome
  (FR-020a).
- **Only ``repositories/*.md`` is cleared.** The output root may hold files the
  pipeline staged there; this application does not own them and does not get to
  delete them (FR-020c).
- **Nothing is written until every name is known to be safe.** A half-written
  output directory can be published as a complete report, so validation happens
  before the first write (FR-024b).

Sanitisation also means a repository name can never steer a write: every path
separator is removed, so ``../../etc/passwd`` becomes an ordinary filename inside
``repositories/``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from trivy_report.errors import FatalError
from trivy_report.logging_setup import get_logger

log = get_logger("writer")

REPORTS_SUBDIR = "repositories"
OVERALL_REPORT = "overall.md"
NAME_CAP = 100
"""Filenames are capped well inside every filesystem's limit, leaving room for the
``.md`` suffix and for a long output path above it (D11)."""

_ALLOWED = re.compile(r"[^a-z0-9._-]")
_RUNS = re.compile(r"-{2,}")
_EDGE_SEPARATORS = "-._"


def sanitise_repository_name(raw: str) -> str:
    """Reduce a repository name to a safe filename stem (D11).

    Lowercased, every character outside ``[a-z0-9._-]`` replaced with ``-``, runs
    collapsed, edges trimmed, capped at ``NAME_CAP``.

    Non-ASCII is replaced rather than transliterated: a transliteration table
    would make the filename depend on a locale, and two runs on two agents could
    then disagree about where a report lives (Principle III).

    Raises ``FatalError`` when nothing survives. An empty filename cannot be
    written, and inventing one would attribute a report to a repository nobody
    named.
    """
    lowered = str(raw).lower()
    replaced = _ALLOWED.sub("-", lowered)
    collapsed = _RUNS.sub("-", replaced)
    trimmed = collapsed.strip(_EDGE_SEPARATORS)
    capped = _cap(trimmed, NAME_CAP)
    if not capped:
        raise FatalError(
            f"repository name {raw!r} sanitises to an empty filename; "
            "it cannot be written and a substitute would be invented"
        )
    return capped


def _cap(text: str, limit: int) -> str:
    """Truncate to ``limit`` characters without ending on a separator.

    A cut that happens to land on a ``-`` would produce ``some-long-name-.md``,
    which reads as an accident rather than as a deliberate cap. The separator run
    is dropped and the following characters refill the budget, so the cap stays
    exact and the name stays legible.
    """
    if len(text) <= limit:
        return text
    head, rest = text[:limit], text[limit:]
    if not head.endswith(tuple(_EDGE_SEPARATORS)):
        return head
    kept = head.rstrip(_EDGE_SEPARATORS)
    refill = rest.lstrip(_EDGE_SEPARATORS)[: limit - len(kept)]
    return kept + refill


def _resolve_names(bodies: Mapping[str, str]) -> dict[str, str]:
    """Map each repository name to its filename stem, or fail on a collision.

    Every name is resolved before anything is written, so a collision discovered
    on the last repository still leaves no output behind (FR-024b).
    """
    by_stem: dict[str, str] = {}
    resolved: dict[str, str] = {}
    for name in sorted(bodies):
        stem = sanitise_repository_name(name)
        first = by_stem.get(stem)
        if first is not None:
            raise FatalError(
                f"repositories {first!r} and {name!r} both sanitise to {stem!r}; "
                "writing either report would hide the other"
            )
        by_stem[stem] = name
        resolved[name] = stem
    return resolved


def ensure_output_dirs(output_dir: Path) -> Path:
    """Create ``<output-dir>`` and ``<output-dir>/repositories`` when absent.

    A first run has nowhere to write, and failing for that reason would make the
    tool unusable on a fresh agent (FR-020b). An unwritable target is fatal
    instead: there is no report to publish, so the run must say so rather than
    finish quietly with exit ``0``.
    """
    output_dir = Path(output_dir)
    reports = output_dir / REPORTS_SUBDIR
    try:
        reports.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise FatalError(
            f"output directory {output_dir} could not be created: {exc.strerror}"
        ) from exc
    return output_dir


def clear_repository_reports(output_dir: Path) -> int:
    """Delete ``<output-dir>/repositories/*.md`` and return how many went.

    Scoped deliberately narrow (FR-020c, D11):

    - Only inside ``repositories/`` — the output root may hold pipeline-owned
      files, and this application never deletes what it did not write.
    - Only ``*.md`` — a notes file someone left beside the reports is not ours.
    - Not recursive — a nested directory is not something this tool creates, so
      it is not something this tool removes.

    Clearing happens even when nothing will be written, so a repository that has
    dropped out of the scan cannot leave yesterday's report behind looking
    current.
    """
    reports = Path(output_dir) / REPORTS_SUBDIR
    if not reports.is_dir():
        return 0
    removed = 0
    for path in sorted(reports.glob("*.md")):
        if not path.is_file():
            continue
        try:
            path.unlink()
        except OSError as exc:
            raise FatalError(
                f"stale report {path.name} could not be removed: {exc.strerror}"
            ) from exc
        removed += 1
    if removed:
        log.debug("cleared %d stale repository report(s)", removed)
    return removed


def _write_text(path: Path, body: str) -> None:
    """Write one document with ``\\n`` newlines and exactly one trailing newline.

    Normalising the trailing newline here rather than in each renderer means two
    renderers cannot disagree about it, which would show up as a spurious diff
    between two byte-identical reports (Principle III).
    """
    payload = body.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
    try:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
    except OSError as exc:
        raise FatalError(f"report {path} could not be written: {exc.strerror}") from exc


def write_report(
    output_dir: Path,
    bodies: Mapping[str, str],
    overall: str | None = None,
) -> dict[str, Path]:
    """Write every per-repository report and, when given, the overall report.

    ``bodies`` is keyed by unsanitised repository name — the caller renders with
    the human-readable name and this function decides where it lands, so the name
    in the title and the name in the filename can never be derived by two
    different rules.

    Returns the written paths keyed by repository name; the overall report is
    keyed by ``None``.
    """
    resolved = _resolve_names(bodies)  # before any write: a collision writes nothing
    output_dir = ensure_output_dirs(output_dir)
    clear_repository_reports(output_dir)

    written: dict[str, Path] = {}
    for name, stem in sorted(resolved.items()):
        path = output_dir / REPORTS_SUBDIR / f"{stem}.md"
        _write_text(path, bodies[name])
        written[name] = path
    if overall is not None:
        path = output_dir / OVERALL_REPORT
        _write_text(path, overall)
        written[None] = path  # type: ignore[index]
    return written
