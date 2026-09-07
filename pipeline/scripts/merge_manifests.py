"""Merge per-repository manifest fragments into the one manifest the app reads.

The fan-out jobs each produce a fragment; this runs once in the fan-in job and
concatenates them, stamping the single scan date the whole run shares.

Three rules here exist because of what the application does downstream:

* **At least one fragment is required.** Zero fragments means every scanning job
  failed. Writing an empty manifest would be *valid* — the application would emit
  its "no results" report and exit ``0`` — and would then persist a history entry
  with no images, so tomorrow every image reads as new. Failing here leaves
  yesterday's history as the newest, which is the honest state.
* **Conflicting duplicates are fatal.** Two entries with the same repository and
  image identity but different result files would attribute one image to two
  scans. The same image in two *different* repositories is expected and fine.
* **The scan date is stamped once, here.** Fragments carry none, so no fan-out job
  can disagree about what day it is.

Missing repositories are a warning, not an error: the application already reports a
repository absent from the manifest but present in history as unscanned, so the
coverage gap is visible in the report itself. This step just names it for the log.

Usage::

    python3 -m pipeline.scripts.merge_manifests \\
        --fragments-dir scans --scan-date 2026-08-17 \\
        --expect gitops-payments,gitops-platform \\
        --missing-out missing.txt --out input/manifest.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from datetime import date
from pathlib import Path

SCHEMA_VERSION = 1
FRAGMENT_GLOB = "**/manifest-fragment.json"
DEFAULT_GENERATOR = "azure-pipelines/trivy-scan"

_IDENTITY_FIELDS = ("repository", "image_name", "image_tag", "image_digest")


class MergeError(Exception):
    """The merged manifest cannot be produced. Always fatal to the run."""


def _identity(entry: dict) -> tuple:
    return tuple(entry.get(field) for field in _IDENTITY_FIELDS)


def _sort_key(entry: dict) -> tuple:
    return (
        entry.get("repository") or "",
        entry.get("image_name") or "",
        entry.get("image_tag") or "",
        entry.get("image_digest") or "",
        entry.get("result_file") or "",
    )


def parse_scan_date(raw: str) -> str:
    """Validate ``YYYY-MM-DD`` and that it is a real calendar date."""
    try:
        parsed = date.fromisoformat(raw)
    except ValueError as exc:
        raise MergeError(f"--scan-date must be a real YYYY-MM-DD date, got {raw!r}") from exc
    if parsed.isoformat() != raw:
        raise MergeError(f"--scan-date must be zero-padded YYYY-MM-DD, got {raw!r}")
    return raw


def load_fragment(path: Path) -> list[dict]:
    """Read one fragment and return its entries, or raise ``MergeError``."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise MergeError(f"cannot read fragment {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise MergeError(f"fragment {path} is not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise MergeError(f"fragment {path} must contain an object")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise MergeError(
            f"fragment {path} declares schema_version "
            f"{document.get('schema_version')!r}; this merger produces {SCHEMA_VERSION}"
        )
    entries = document.get("entries")
    if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
        raise MergeError(f"fragment {path} must carry an 'entries' array of objects")
    return entries


def merge_entries(fragments: dict[str, list[dict]]) -> list[dict]:
    """Concatenate entries, rejecting anything that would double-count an image."""
    by_identity: dict[tuple, tuple[str, dict]] = {}
    by_result_file: dict[str, tuple[str, dict]] = {}
    merged: list[dict] = []

    for source in sorted(fragments):
        for entry in fragments[source]:
            identity = _identity(entry)
            result_file = entry.get("result_file")

            seen = by_identity.get(identity)
            if seen is not None:
                previous_source, previous = seen
                if previous.get("result_file") == result_file:
                    print(
                        f"warning: {source} repeats an entry already declared by "
                        f"{previous_source}: {identity}; keeping one copy",
                        file=sys.stderr,
                    )
                    continue
                raise MergeError(
                    f"conflicting entries for {identity}: {previous_source} points at "
                    f"{previous.get('result_file')!r} and {source} at {result_file!r}"
                )

            collision = by_result_file.get(result_file) if isinstance(result_file, str) else None
            if collision is not None:
                collision_source, other = collision
                raise MergeError(
                    f"result_file {result_file!r} is claimed by two different images: "
                    f"{_identity(other)} from {collision_source} and {identity} from {source}"
                )

            by_identity[identity] = (source, entry)
            if isinstance(result_file, str):
                by_result_file[result_file] = (source, entry)
            merged.append(entry)

    merged.sort(key=_sort_key)
    return merged


def build_manifest(
    entries: list[dict], *, scan_date: str, generator: str = DEFAULT_GENERATOR
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "scan_date": scan_date,
        "generator": generator,
        "entries": entries,
    }


def missing_repositories(expected: Iterable[str], entries: Iterable[dict]) -> list[str]:
    present = {entry.get("repository") for entry in entries}
    return sorted(
        name for name in {n.strip() for n in expected if n.strip()} if name not in present
    )


def _collect_fragment_paths(args: argparse.Namespace) -> list[Path]:
    paths: list[Path] = list(args.fragment)
    if args.fragments_dir is not None:
        paths.extend(sorted(args.fragments_dir.glob(FRAGMENT_GLOB)))
    # Deduplicate while preserving deterministic order.
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def _split_expected(values: list[str]) -> list[str]:
    names: list[str] = []
    for value in values:
        names.extend(part for part in value.replace("\n", ",").split(",") if part.strip())
    return names


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="merge_manifests",
        description="Merge per-repository manifest fragments into one manifest.",
    )
    parser.add_argument(
        "--fragment",
        action="append",
        default=[],
        type=Path,
        metavar="FILE",
        help="A fragment to merge. Repeatable.",
    )
    parser.add_argument(
        "--fragments-dir",
        type=Path,
        metavar="DIR",
        help=f"Directory searched for {FRAGMENT_GLOB}.",
    )
    parser.add_argument("--scan-date", required=True, metavar="YYYY-MM-DD")
    parser.add_argument("--out", required=True, type=Path, metavar="FILE")
    parser.add_argument(
        "--expect",
        action="append",
        default=[],
        metavar="REPOS",
        help="Repository names this run should cover. Comma-separated or repeated. "
        "Absent ones are warned about, not failed.",
    )
    parser.add_argument(
        "--missing-out",
        type=Path,
        metavar="FILE",
        help="Write expected-but-absent repository names here, one per line.",
    )
    parser.add_argument("--generator", default=DEFAULT_GENERATOR)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        scan_date = parse_scan_date(args.scan_date)
        paths = _collect_fragment_paths(args)
        if not paths:
            raise MergeError(
                "no manifest fragments found. Every scanning job must have failed; "
                "refusing to write an empty manifest, which would persist a history "
                "entry with no images and destroy tomorrow's trends"
            )
        fragments = {path.as_posix(): load_fragment(path) for path in paths}
        entries = merge_entries(fragments)
        manifest = build_manifest(entries, scan_date=scan_date, generator=args.generator)
    except MergeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    missing = missing_repositories(_split_expected(args.expect), entries)
    if args.missing_out is not None:
        args.missing_out.parent.mkdir(parents=True, exist_ok=True)
        args.missing_out.write_text("".join(f"{name}\n" for name in missing), encoding="utf-8")
    for name in missing:
        print(
            f"warning: repository {name!r} produced no manifest fragment; its images "
            f"will be absent from this scan",
            file=sys.stderr,
        )

    repositories = sorted({entry.get("repository") for entry in entries})
    print(
        f"merged {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} from "
        f"{len(fragments)} fragment(s) across {len(repositories)} repositor"
        f"{'y' if len(repositories) == 1 else 'ies'}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    sys.exit(main())
