"""The scan-history archive: serialise, write atomically, select a baseline.

This is the only persisted state the application owns, and it is read back days
after it was written by a different process on a different machine. Three rules
follow from that and are enforced here rather than left to callers:

1. **Validation is symmetric with the contract.** ``deserialise`` rejects exactly
   what ``contracts/history.schema.json`` rejects. Validation is hand-written
   because the application carries zero runtime dependencies (Principle II) — a
   test-only ``jsonschema`` would be validating something production never runs.
2. **A write cannot corrupt a valid file.** Temp file in the same directory then
   ``os.replace``, so an interrupted or killed run leaves either the old entry or
   the new one, never a truncated document (D8, FR-009a).
3. **A file that cannot be trusted is skipped and preserved, never repaired or
   deleted** (FR-010a, FR-011a). Trends degrade by one day; the archive stays
   intact for a human to inspect.

Malformed *history* is recoverable, unlike a malformed manifest: the archive is
supporting evidence, so a bad entry costs a comparison, while a bad manifest
would mean every count in the report is attributed on a guess.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

from trivy_report.logging_setup import get_logger
from trivy_report.models import (
    HISTORY_SCHEMA_VERSION,
    HistoryEntry,
    HistoryImage,
    HistoryRepo,
    ScanRun,
    SeverityCounts,
)

log = get_logger("history")

_FILE_NAME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\.json$")
"""Zero-padded only. ``2026-8-4.json`` is not history: accepting a second naming
form would make "the most recent entry" depend on how a file happened to be
written (FR-010a)."""

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_COUNT_FIELDS = ("critical", "high", "medium", "low", "unknown")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "scan_date",
        "images",
        "repositories",
        "unique_image_total",
        "sum_of_subtotals_total",
        "shared_image_count",
    }
)
_IMAGE_FIELDS = frozenset({"repository", "image_name", "counts"})
_REPO_FIELDS = frozenset({"name", "subtotal"})


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def _counts_to_json(counts: SeverityCounts) -> dict[str, int]:
    """All five fields, always. A zero is written, never omitted, so a reader
    never has to distinguish "absent" from "none found"."""
    return {name: getattr(counts, name) for name in _COUNT_FIELDS}


def entry_to_document(entry: HistoryEntry) -> dict[str, object]:
    """The JSON-ready mapping for an entry, ordering left to ``sort_keys``."""
    return {
        "schema_version": entry.schema_version,
        "scan_date": entry.scan_date.isoformat(),
        "images": [
            {
                "repository": image.repository,
                "image_name": image.image_name,
                "counts": _counts_to_json(image.counts),
            }
            for image in entry.images
        ],
        "repositories": [
            {"name": repo.name, "subtotal": _counts_to_json(repo.subtotal)}
            for repo in entry.repositories
        ],
        "unique_image_total": _counts_to_json(entry.unique_image_total),
        "sum_of_subtotals_total": _counts_to_json(entry.sum_of_subtotals_total),
        "shared_image_count": entry.shared_image_count,
    }


def entry_from_run(run: ScanRun) -> HistoryEntry:
    """The archive entry describing one run.

    Two exclusions carry the correctness of every future trend:

    - **An image whose file failed to parse is omitted**, never persisted as zero.
      A zero would compare as a large improvement the moment the file parses
      again, and tomorrow's report would show remediation that never happened.
    - **A repository marked unscanned is omitted.** It is in the run only so the
      report can say nobody looked; persisting a zero subtotal would assert
      evidence this run does not have.

    Counts are folded onto the trend key ``(repository, image_name)`` (D6), so two
    tags of one name become the single subject the comparison expects.
    """
    folded: dict[tuple[str, str], SeverityCounts] = {}
    for repository in run.repositories:
        for image in repository.images:
            if image.parse_failed:
                continue
            key = (repository.name, image.image.name)
            folded[key] = folded.get(key, SeverityCounts()) + image.counts

    return HistoryEntry(
        schema_version=HISTORY_SCHEMA_VERSION,
        scan_date=run.scan_date,
        images=tuple(
            HistoryImage(repository=repository, image_name=name, counts=counts)
            for (repository, name), counts in folded.items()
        ),
        repositories=tuple(
            HistoryRepo(name=repository.name, subtotal=repository.subtotal)
            for repository in run.repositories
            if repository.scanned
        ),
        unique_image_total=run.unique_image_total,
        sum_of_subtotals_total=run.sum_of_subtotals_total,
        shared_image_count=run.shared_image_count,
    )


def serialise(entry: HistoryEntry) -> str:
    """Render an entry as the exact bytes to persist.

    ``sort_keys`` plus the model's own sorting of ``images`` and ``repositories``
    make the output a function of the data alone, so two runs over identical
    input produce identical files and a diff of two days shows only real change
    (Principle III).
    """
    document = entry_to_document(entry)
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# Deserialisation — the mirror of contracts/history.schema.json
# ---------------------------------------------------------------------------


def _reject(message: str) -> ValueError:
    return ValueError(f"history entry is invalid: {message}")


def _read_counts(raw: object, where: str) -> SeverityCounts:
    if not isinstance(raw, Mapping):
        raise _reject(f"{where} must be an object, got {type(raw).__name__}")
    unknown = set(raw) - set(_COUNT_FIELDS)
    if unknown:
        raise _reject(f"{where} has unknown field(s): {sorted(unknown)}")
    values: dict[str, int] = {}
    for name in _COUNT_FIELDS:
        if name not in raw:
            raise _reject(f"{where}.{name} is required")
        value = raw[name]
        # bool is an int subclass; `true` must not be read as 1 in a count.
        if not isinstance(value, int) or isinstance(value, bool):
            raise _reject(f"{where}.{name} must be an integer, got {value!r}")
        if value < 0:
            raise _reject(f"{where}.{name} must be >= 0, got {value}")
        values[name] = value
    return SeverityCounts(**values)


def _read_name(raw: Mapping[str, object], field: str, where: str) -> str:
    value = raw.get(field)
    if not isinstance(value, str) or not value.strip():
        raise _reject(f"{where}.{field} must be a non-empty string, got {value!r}")
    return value


def deserialise(document: object) -> HistoryEntry:
    """Parse a history document, or raise ``ValueError``.

    Every rejection the schema makes is made here too. Callers treat the
    exception as "skip this file and keep looking" — see ``load_baseline`` — which
    is only safe because an invalid document never becomes a partly-populated
    entry.
    """
    if not isinstance(document, Mapping):
        raise _reject(f"top level must be an object, got {type(document).__name__}")

    unknown = set(document) - _TOP_LEVEL_FIELDS
    if unknown:
        raise _reject(f"unknown top-level field(s): {sorted(unknown)}")
    for field in sorted(_TOP_LEVEL_FIELDS):
        if field not in document:
            raise _reject(f"{field} is required")

    version = document["schema_version"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise _reject(f"schema_version must be an integer, got {version!r}")
    if version != HISTORY_SCHEMA_VERSION:
        # Recoverable, unlike the manifest equivalent: an old archive costs one
        # comparison, so it must never break a current run.
        raise _reject(
            f"unsupported schema_version {version} (this build reads {HISTORY_SCHEMA_VERSION} only)"
        )

    raw_date = document["scan_date"]
    if not isinstance(raw_date, str) or not _DATE_RE.match(raw_date):
        raise _reject(f"scan_date must be YYYY-MM-DD, got {raw_date!r}")
    try:
        scan_date = date.fromisoformat(raw_date)
    except ValueError as exc:
        raise _reject(f"scan_date is not a real date: {raw_date!r}") from exc

    raw_images = document["images"]
    if not isinstance(raw_images, list):
        raise _reject(f"images must be an array, got {type(raw_images).__name__}")
    images = []
    for index, raw in enumerate(raw_images):
        where = f"images[{index}]"
        if not isinstance(raw, Mapping):
            raise _reject(f"{where} must be an object, got {type(raw).__name__}")
        extra = set(raw) - _IMAGE_FIELDS
        if extra:
            raise _reject(f"{where} has unknown field(s): {sorted(extra)}")
        if "counts" not in raw:
            raise _reject(f"{where}.counts is required")
        images.append(
            HistoryImage(
                repository=_read_name(raw, "repository", where),
                image_name=_read_name(raw, "image_name", where),
                counts=_read_counts(raw["counts"], f"{where}.counts"),
            )
        )

    raw_repos = document["repositories"]
    if not isinstance(raw_repos, list):
        raise _reject(f"repositories must be an array, got {type(raw_repos).__name__}")
    repositories = []
    for index, raw in enumerate(raw_repos):
        where = f"repositories[{index}]"
        if not isinstance(raw, Mapping):
            raise _reject(f"{where} must be an object, got {type(raw).__name__}")
        extra = set(raw) - _REPO_FIELDS
        if extra:
            raise _reject(f"{where} has unknown field(s): {sorted(extra)}")
        if "subtotal" not in raw:
            raise _reject(f"{where}.subtotal is required")
        repositories.append(
            HistoryRepo(
                name=_read_name(raw, "name", where),
                subtotal=_read_counts(raw["subtotal"], f"{where}.subtotal"),
            )
        )

    shared = document["shared_image_count"]
    if not isinstance(shared, int) or isinstance(shared, bool) or shared < 0:
        raise _reject(f"shared_image_count must be a non-negative integer, got {shared!r}")

    return HistoryEntry(
        schema_version=version,
        scan_date=scan_date,
        images=tuple(images),
        repositories=tuple(repositories),
        unique_image_total=_read_counts(document["unique_image_total"], "unique_image_total"),
        sum_of_subtotals_total=_read_counts(
            document["sum_of_subtotals_total"], "sum_of_subtotals_total"
        ),
        shared_image_count=shared,
    )


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def ensure_dir(directory: Path) -> Path:
    """Create the history directory when absent (FR-008a).

    A first run has nowhere to persist to, and failing for that reason would make
    the archive impossible to bootstrap.
    """
    directory = Path(directory)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OSError(
            f"history directory could not be created: {directory} ({exc.strerror})"
        ) from exc
    return directory


def entry_path(directory: Path, entry_date: date) -> Path:
    """The one path an entry for this date may occupy.

    One file per date, named for the date (FR-007a), so a same-date re-run
    replaces rather than accumulates (FR-009) and selection needs no index.
    """
    return Path(directory) / f"{entry_date.isoformat()}.json"


def write_entry(directory: Path, entry: HistoryEntry) -> Path:
    """Persist an entry atomically and return its path.

    Written to a temp file in the *same* directory — a rename is only atomic
    within one filesystem — then moved into place with ``Path.replace``. A crash
    mid-write therefore leaves yesterday's readable entry rather than a truncated
    file that would silently drop tomorrow's baseline (D8, FR-009a).
    """
    directory = ensure_dir(Path(directory))
    target = entry_path(directory, entry.scan_date)
    payload = serialise(entry)

    # Bound outside the try so the cleanup path can tell "no temp file yet" from
    # "temp file exists and must go". ``delete=False`` because the file has to
    # outlive the handle in order to be renamed.
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=directory,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(target)
    except BaseException:
        # Includes KeyboardInterrupt: leaving a dotfile behind would be reported
        # as an orphan by a later run of the pipeline over the same directory.
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise
    log.debug("wrote history entry %s", target.name)
    return target


# ---------------------------------------------------------------------------
# Reading and baseline selection
# ---------------------------------------------------------------------------


def dated_files(directory: Path) -> tuple[tuple[date, Path], ...]:
    """Every recognised history file, ascending by encoded date.

    Only ``YYYY-MM-DD.json`` counts. Anything else in the directory — notes,
    backups, a mis-padded date — is not history and is never opened, so an
    unrelated file cannot become a baseline (D8).
    """
    directory = Path(directory)
    if not directory.is_dir():
        return ()
    found: list[tuple[date, Path]] = []
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        match = _FILE_NAME_RE.match(path.name)
        if match is None:
            continue
        try:
            encoded = date(int(match[1]), int(match[2]), int(match[3]))
        except ValueError:
            # A name-shaped non-date such as 2026-02-30.json.
            log.warning("skipping history file with an impossible date: %s", path.name)
            continue
        found.append((encoded, path))
    return tuple(sorted(found, key=lambda pair: pair[0]))


def load_entry(path: Path) -> HistoryEntry | None:
    """Read one entry, or ``None`` if it cannot be trusted.

    The file is left exactly as found in every case, including failure: unreadable
    persisted data is never deleted or overwritten (constitution, Security & Data
    Handling), so a human can still see what went wrong.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("skipping unreadable history file %s (%s)", path.name, exc.strerror)
        return None
    except UnicodeDecodeError:
        log.warning("skipping history file %s (not valid UTF-8)", path.name)
        return None

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        log.warning(
            "skipping malformed history file %s (line %d, column %d)",
            path.name,
            exc.lineno,
            exc.colno,
        )
        return None

    try:
        entry = deserialise(document)
    except ValueError as exc:
        log.warning("skipping history file %s (%s)", path.name, exc)
        return None

    match = _FILE_NAME_RE.match(path.name)
    if match is not None and entry.scan_date.isoformat() != f"{match[1]}-{match[2]}-{match[3]}":
        # The schema requires name and body to agree. A disagreement means the
        # file cannot be trusted to be the day it claims — and the day is the
        # entire basis of selection and of every delta computed from it.
        log.warning(
            "skipping history file %s: body is dated %s",
            path.name,
            entry.scan_date.isoformat(),
        )
        return None
    return entry


@dataclass(frozen=True, slots=True)
class BaselineSelection:
    """The chosen baseline plus the names of the files skipped to reach it.

    The skipped list is carried out of this module rather than being left in the
    log because a preserved file is only actionable if a human can find it: "some
    history could not be read" sends an operator through ninety files by hand
    (FR-011a, FR-019).
    """

    entry: HistoryEntry | None
    skipped: tuple[str, ...] = ()


def select_baseline(directory: Path, *, before: date) -> BaselineSelection:
    """The most recent trustworthy entry dated strictly before ``before``.

    Strictly: an entry dated *on* the scan date is never its own baseline. A
    same-date re-run replaces that file (FR-009), so comparing against it would
    render every trend flat and hide exactly the change the re-run captured.

    Entries dated after ``before`` are ignored so a replayed historical date
    compares against its own past rather than against the future.

    Walking backwards past unreadable entries (FR-011a) rather than giving up on
    the first one keeps one corrupt file from silently converting a normal run
    into a baseline run — which would print ``(new)`` beside every count and read
    as a fleet with no history at all. Each skipped file has already been warned
    about by ``load_entry`` and left exactly as found; none is deleted, repaired or
    overwritten, which is the archive's single safety invariant.

    Only files actually examined are reported as skipped. Entries older than the
    selected baseline are never opened, so claiming them as skipped would describe
    a problem nobody has looked for.
    """
    skipped: list[str] = []
    for encoded, path in reversed(dated_files(directory)):
        if encoded >= before:
            continue
        entry = load_entry(path)
        if entry is not None:
            return BaselineSelection(entry=entry, skipped=tuple(skipped))
        skipped.append(path.name)
    if skipped:
        log.warning(
            "no readable history entry: %d file(s) skipped and preserved (%s); "
            "treating this as a baseline run",
            len(skipped),
            ", ".join(skipped),
        )
    return BaselineSelection(entry=None, skipped=tuple(skipped))


def load_baseline(directory: Path, *, before: date) -> HistoryEntry | None:
    """``select_baseline`` for callers that need only the entry."""
    return select_baseline(directory, before=before).entry


def known_repositories(entry: HistoryEntry | None) -> tuple[str, ...]:
    """Repository names the baseline knew about, sorted.

    Used to detect a repository that has dropped out of the scan: it must be
    reported as unscanned rather than silently omitted, since a missing section
    reads as "nothing to report".
    """
    if entry is None:
        return ()
    return tuple(sorted({repo.name for repo in entry.repositories}))


def iter_entries(directory: Path) -> Iterator[HistoryEntry]:
    """Every trustworthy entry, ascending by date. Untrusted files are skipped."""
    for _, path in dated_files(directory):
        entry = load_entry(path)
        if entry is not None:
            yield entry


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


def prune(directory: Path, *, retention_days: int, scan_date: date) -> int:
    """Delete dated entries outside the retention window; return how many.

    This is the only code in the application that removes anything from the
    archive, so its scope is deliberately narrow on three axes:

    - **By name.** Only ``YYYY-MM-DD.json`` is a candidate (FR-010a). The archive
      directory belongs to the pipeline and may hold notes, backups or a
      mis-padded date; deleting one of those is data loss, not housekeeping.
    - **By date, never by content.** The file is not opened. Reading it first would
      make a corrupt entry deletable, and preserving unreadable data is the
      archive's single safety invariant (FR-011a).
    - **Backwards only.** A file dated *after* ``scan_date`` is left alone: a
      replayed historical date is re-running one old day, not authorising the
      destruction of everything recorded since.

    The window is inclusive and ``retention_days`` days wide, counting
    ``scan_date`` itself — ``retention_days=7`` keeps a week, so the cutoff is six
    days back. ``retention_days=1`` therefore keeps exactly the entry this run
    wrote, which is why ``0`` is rejected at the argument boundary rather than
    clamped here.

    ``scan_date`` is passed in rather than read from the clock (D7): a prune whose
    window moved with wall-clock time would make two runs over one input set
    disagree about which files exist.
    """
    if retention_days < 1:
        raise ValueError(f"retention_days must be >= 1, got {retention_days}")

    cutoff = scan_date - timedelta(days=retention_days - 1)
    pruned = 0
    for encoded, path in dated_files(directory):
        if encoded >= cutoff:
            continue
        try:
            path.unlink()
        except OSError as exc:
            # A file that cannot be removed is a housekeeping failure, not a
            # reporting one: the run's numbers are unaffected, so warn and carry on
            # rather than failing a build over disk permissions.
            log.warning("could not prune history file %s (%s)", path.name, exc.strerror)
            continue
        pruned += 1
        log.debug("pruned history file %s (outside %d-day window)", path.name, retention_days)
    return pruned
