"""Manifest loading and validation (contracts/manifest.schema.json, FR-001a/b/c).

The manifest is the sole authority for the result-file → (repository, image)
mapping. This module never infers that mapping from directory names, file names,
or fields inside the Trivy JSON: a report that attributes findings to the wrong
repository sends the wrong team to fix them.

Validation is hand-written rather than delegated to ``jsonschema`` because the
application carries zero runtime dependencies (Principle II). The schema file
remains the normative contract; this module is its executable form, and the two
must be changed together.

Every violation here is fatal (FR-001b): if the index cannot be trusted, no
report built from it can be either. Absent *referenced files* are the one
exception — those are recorded and the run continues (FR-001c).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from trivy_report.errors import FatalError
from trivy_report.logging_setup import get_logger
from trivy_report.models import FailureKind, ImageRef, ParseFailure

log = get_logger("manifest")

SUPPORTED_SCHEMA_VERSION = 1

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DIGEST_RE = re.compile(r"^[a-zA-Z0-9]+:[a-fA-F0-9]{32,}$")

_TOP_LEVEL_FIELDS = frozenset({"schema_version", "scan_date", "generator", "entries"})
_ENTRY_FIELDS = frozenset({"repository", "image_name", "image_tag", "image_digest", "result_file"})
_ENTRY_REQUIRED = ("repository", "image_name", "result_file")

_MAX_LENGTHS = {
    "generator": 200,
    "repository": 200,
    "image_name": 500,
    "image_tag": 200,
    "result_file": 1000,
}


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """One scanned image, as declared by the pipeline."""

    repository: str
    image_name: str
    image_tag: str | None
    image_digest: str | None
    result_file: str
    """Path relative to ``--input``. Validated as relative and non-escaping before
    this object exists, so no consumer has to re-check it."""

    @property
    def image(self) -> ImageRef:
        """The image identity this entry describes."""
        return ImageRef(name=self.image_name, tag=self.image_tag, digest=self.image_digest)


@dataclass(frozen=True, slots=True)
class Manifest:
    """A validated manifest."""

    schema_version: int
    scan_date: str | None
    """Kept as a string. Turning it into a ``date`` is the CLI's job, because the
    CLI owns the precedence rule (argument, then this, then fatal) and should
    report a bad value against whichever source supplied it (D7)."""

    generator: str | None
    entries: tuple[ManifestEntry, ...]

    def repositories(self) -> tuple[str, ...]:
        """Distinct repository names, sorted (FR-022)."""
        return tuple(sorted({e.repository for e in self.entries}))

    def unique_image_refs(self) -> tuple[str, ...]:
        """Distinct unique-image keys, sorted."""
        return tuple(sorted({e.image.ref for e in self.entries}))


def _fatal(message: str) -> FatalError:
    return FatalError(f"manifest is invalid: {message}")


def _require_str(value: object, field: str, *, where: str) -> str:
    if not isinstance(value, str):
        raise _fatal(f"{where}{field} must be a string, got {type(value).__name__}")
    if not value.strip():
        raise _fatal(f"{where}{field} must not be empty")
    limit = _MAX_LENGTHS.get(field)
    if limit is not None and len(value) > limit:
        raise _fatal(f"{where}{field} exceeds {limit} characters")
    return value


def _validate_result_file(raw: object, *, where: str) -> str:
    """Reject absolute paths and any component escaping the input directory.

    This is the security-relevant check in this module. A manifest is an input
    the application does not control, so an unchecked ``result_file`` of
    ``../../etc/passwd`` would let it read arbitrary files (constitution,
    Security & Data Handling). Rejection is fatal, never a skip, because a
    manifest attempting it is not a manifest to trust the rest of.
    """
    value = _require_str(raw, "result_file", where=where)

    # Reject POSIX and Windows absolute forms, plus drive-relative paths, before
    # looking at components at all.
    if value.startswith("/") or value.startswith("\\"):
        raise _fatal(f"{where}result_file must be relative, got {value!r}")
    if PurePosixPath(value).is_absolute() or Path(value).is_absolute():
        raise _fatal(f"{where}result_file must be relative, got {value!r}")
    if re.match(r"^[A-Za-z]:", value):
        raise _fatal(f"{where}result_file must be relative, got {value!r}")

    # Check components, not substrings: 'a..b.json' and '..hidden.json' are
    # ordinary file names, while a bare '..' component is an escape. Backslash is
    # treated as a separator too, so a Windows-style path cannot smuggle one past.
    parts = re.split(r"[/\\]", value)
    if any(part == ".." for part in parts):
        raise _fatal(f"{where}result_file must not escape --input via '..', got {value!r}")
    if not parts[-1]:
        raise _fatal(f"{where}result_file must name a file, got {value!r}")

    return value


def _parse_entry(raw: object, index: int) -> ManifestEntry:
    where = f"entries[{index}]."
    if not isinstance(raw, dict):
        raise _fatal(f"entries[{index}] must be an object, got {type(raw).__name__}")

    unknown = set(raw) - _ENTRY_FIELDS
    if unknown:
        # additionalProperties: false. An unrecognised key means a format this
        # build does not understand, and guessing at it risks misattribution.
        raise _fatal(f"entries[{index}] has unknown field(s): {sorted(unknown)}")

    for field in _ENTRY_REQUIRED:
        if field not in raw:
            raise _fatal(f"{where}{field} is required")

    repository = _require_str(raw["repository"], "repository", where=where)
    image_name = _require_str(raw["image_name"], "image_name", where=where)
    result_file = _validate_result_file(raw["result_file"], where=where)

    tag = raw.get("image_tag")
    if tag is not None:
        tag = _require_str(tag, "image_tag", where=where)

    digest = raw.get("image_digest")
    if digest is not None:
        digest = _require_str(digest, "image_digest", where=where)
        if not _DIGEST_RE.match(digest):
            raise _fatal(f"{where}image_digest is not a valid digest: {digest!r}")

    if tag is None and digest is None:
        # anyOf [image_tag, image_digest]. Without either, two builds of one name
        # are indistinguishable and the unique-image total collapses them (D4).
        raise _fatal(f"{where}requires at least one of image_tag or image_digest")

    return ManifestEntry(
        # Registries are case-insensitive, so the name is lowercased on ingest to
        # keep two spellings of one image from counting twice. Tags are
        # case-sensitive and preserved verbatim.
        repository=repository,
        image_name=image_name.strip().lower(),
        image_tag=tag,
        image_digest=digest.lower() if digest else None,
        result_file=result_file,
    )


def load_manifest(path: Path) -> Manifest:
    """Load and fully validate the manifest, or raise ``FatalError``.

    The manifest file itself is never modified — it is an input (constitution,
    Security & Data Handling).
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FatalError(f"manifest not found: {path}") from exc
    except OSError as exc:
        raise FatalError(f"manifest could not be read: {path} ({exc.strerror})") from exc

    try:
        body = json.loads(text)
    except json.JSONDecodeError as exc:
        # Line and column, not a traceback: the reader is looking at a CI log.
        raise FatalError(
            f"manifest is not valid JSON: {path} (line {exc.lineno}, column {exc.colno})"
        ) from exc

    if not isinstance(body, dict):
        raise _fatal(f"top level must be an object, got {type(body).__name__}")

    unknown = set(body) - _TOP_LEVEL_FIELDS
    if unknown:
        raise _fatal(f"unknown top-level field(s): {sorted(unknown)}")

    if "schema_version" not in body:
        raise _fatal("schema_version is required")
    version = body["schema_version"]
    # bool is an int subclass in Python; True must not pass as version 1.
    if not isinstance(version, int) or isinstance(version, bool):
        raise _fatal(f"schema_version must be an integer, got {version!r}")
    if version != SUPPORTED_SCHEMA_VERSION:
        # Fatal rather than best-effort: a format change must never be silently
        # misread into a plausible-looking but wrong report.
        raise _fatal(
            f"unsupported schema_version {version} (this build supports "
            f"{SUPPORTED_SCHEMA_VERSION} only)"
        )

    if "entries" not in body:
        raise _fatal("entries is required")
    raw_entries = body["entries"]
    if not isinstance(raw_entries, list):
        raise _fatal(f"entries must be an array, got {type(raw_entries).__name__}")

    scan_date = body.get("scan_date")
    if scan_date is not None:
        scan_date = _require_str(scan_date, "scan_date", where="")
        if not _DATE_RE.match(scan_date):
            raise _fatal(f"scan_date must be YYYY-MM-DD, got {scan_date!r}")

    generator = body.get("generator")
    if generator is not None:
        if not isinstance(generator, str):
            raise _fatal(f"generator must be a string, got {type(generator).__name__}")
        if len(generator) > _MAX_LENGTHS["generator"]:
            raise _fatal("generator exceeds 200 characters")

    entries = tuple(_parse_entry(raw, i) for i, raw in enumerate(raw_entries))

    # An empty manifest is valid and produces the explicit 'no results' report
    # (FR-021) — silence would be indistinguishable from a broken pipeline.
    if not entries:
        log.info("manifest declares zero entries")

    return Manifest(
        schema_version=version,
        scan_date=scan_date,
        generator=generator,
        entries=entries,
    )


def find_missing_files(manifest: Manifest, input_dir: Path) -> tuple[ParseFailure, ...]:
    """Manifest entries whose result file is absent.

    Recorded as ``FILE_MISSING`` failures, not raised (FR-001c): one image the
    pipeline failed to scan must not deny the reader every other repository's
    report.
    """
    failures = [
        ParseFailure(
            file=entry.result_file,
            kind=FailureKind.FILE_MISSING,
            reason="listed in the manifest but not present in the input directory",
            repository=entry.repository,
        )
        for entry in manifest.entries
        if not (input_dir / entry.result_file).is_file()
    ]
    return tuple(sorted(failures, key=lambda f: f.file))


def find_orphan_files(manifest: Manifest, input_dir: Path) -> tuple[ParseFailure, ...]:
    """JSON files in the input directory that the manifest does not list.

    An orphan means the pipeline scanned something it did not declare, so its
    findings would go unreported entirely. That is a coverage gap worth an exit
    code, which is why it is a recorded failure rather than a log line — but its
    repository is genuinely unknown, so ``repository`` is None (FR-001c).
    """
    listed = {entry.result_file for entry in manifest.entries}
    manifest_names = {Path(p).name for p in listed}
    orphans = []
    for candidate in _json_files(input_dir):
        relative = candidate.relative_to(input_dir).as_posix()
        if relative in listed:
            continue
        # The manifest is the authority on paths, but a pipeline writing to a
        # different subdirectory than it declared is a manifest bug, not an
        # orphan; comparing names keeps that from being reported twice.
        if candidate.name in manifest_names:
            continue
        orphans.append(
            ParseFailure(
                file=relative,
                kind=FailureKind.ORPHAN_FILE,
                reason="present in the input directory but not listed in the manifest",
                repository=None,
            )
        )
    return tuple(sorted(orphans, key=lambda f: f.file))


def _json_files(input_dir: Path) -> Iterator[Path]:
    """Every ``*.json`` under the input directory, sorted for determinism.

    The manifest itself is commonly written into the input directory by the
    pipeline; it is not a result file and must not be reported as an orphan.
    """
    for path in sorted(input_dir.rglob("*.json")):
        if path.is_file() and path.name != "manifest.json":
            yield path


def entries_by_repository(entries: Iterable[ManifestEntry]) -> dict[str, list[ManifestEntry]]:
    """Group entries by repository, preserving deterministic order."""
    grouped: dict[str, list[ManifestEntry]] = {}
    for entry in sorted(entries, key=lambda e: (e.repository, e.image_name, e.result_file)):
        grouped.setdefault(entry.repository, []).append(entry)
    return grouped
