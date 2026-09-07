"""Turn one repository's discovered images into a manifest fragment and scan plan.

This is the producing half of ``specs/001-trivy-vuln-reports/contracts/manifest.schema.json``.
It runs once per GitOps repository, inside that repository's fan-out job, and emits
two files derived from a single in-memory list so they cannot disagree:

* **the fragment** — manifest entries for this repository, merged later by
  ``merge_manifests.py`` into the one manifest the application reads;
* **the scan plan** — a tab-separated ``reference<TAB>result_file`` list that the
  Trivy loop consumes.

The plan exists because the fragment already knows where every result file must
land, and letting the scanner invent its own paths is how a result ends up
attributed to the wrong image. One producer, one mapping.

Schema limits are enforced here rather than left to the application. Both would
reject an over-long repository name, but only this job knows which overlay it came
from; failing in the fan-in job would report the symptom a long way from the cause.

Usage::

    python3 -m pipeline.scripts.make_manifest \\
        --repository gitops-payments \\
        --images-json images.json \\
        --fragment-out fragment.json \\
        --plan-out plan.tsv
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from pipeline.scripts.image_ref import ImageRef, InvalidImageRef, parse, result_file_name, slug

SCHEMA_VERSION = 1

MAX_REPOSITORY = 200
MAX_IMAGE_NAME = 500
MAX_IMAGE_TAG = 200
MAX_RESULT_FILE = 1000

DEFAULT_GENERATOR = "azure-pipelines/trivy-scan"


class ProducerError(Exception):
    """The fragment cannot be produced. Always fatal to the producing job."""


@dataclass(frozen=True)
class PlannedScan:
    """One image to scan, and the file its Trivy JSON must be written to."""

    ref: ImageRef
    result_file: str

    def entry(self, repository: str) -> dict[str, str]:
        """The manifest entry, with only the fields the schema allows."""
        entry = {
            "repository": repository,
            "image_name": self.ref.name,
            "result_file": self.result_file,
        }
        if self.ref.tag:
            entry["image_tag"] = self.ref.tag
        if self.ref.digest:
            entry["image_digest"] = self.ref.digest
        return entry


def _check_repository(repository: str) -> str:
    name = repository.strip()
    if not name:
        raise ProducerError("--repository must not be empty")
    if len(name) > MAX_REPOSITORY:
        raise ProducerError(
            f"repository name is {len(name)} characters; the manifest schema allows "
            f"{MAX_REPOSITORY}"
        )
    if not slug(name):
        raise ProducerError(
            f"repository name {name!r} sanitises to nothing, so it cannot name a report file"
        )
    return name


def plan_scans(
    repository: str, images: list[str], *, results_prefix: str | None = None
) -> tuple[PlannedScan, ...]:
    """Map references to result files, rejecting anything the schema forbids.

    ``results_prefix`` defaults to the slugged repository name, so every result
    file is namespaced by repository and two repositories scanning the same image
    cannot overwrite each other's JSON.
    """
    repository = _check_repository(repository)
    prefix = results_prefix if results_prefix is not None else slug(repository)

    refs: dict[str, ImageRef] = {}
    for raw in images:
        try:
            ref = parse(raw)
        except InvalidImageRef as exc:
            raise ProducerError(str(exc)) from exc

        if ref.tag is None and ref.digest is None:
            # The schema requires one of them, and defaulting to ``latest`` would
            # make a trend line compare two different artefacts on two days.
            raise ProducerError(
                f"image {ref.name!r} has neither a tag nor a digest; pin it in the "
                f"overlay so scans are reproducible"
            )
        if len(ref.name) > MAX_IMAGE_NAME:
            raise ProducerError(f"image name exceeds {MAX_IMAGE_NAME} characters: {ref.name!r}")
        if ref.tag is not None and len(ref.tag) > MAX_IMAGE_TAG:
            raise ProducerError(f"image tag exceeds {MAX_IMAGE_TAG} characters: {ref.tag!r}")

        refs.setdefault(ref.ref, ref)

    planned: list[PlannedScan] = []
    for ref in sorted(refs.values(), key=lambda r: r.sort_key):
        name = result_file_name(ref)
        result_file = f"{prefix}/{name}" if prefix else name
        if len(result_file) > MAX_RESULT_FILE:
            raise ProducerError(
                f"result_file path exceeds {MAX_RESULT_FILE} characters: {result_file}"
            )
        planned.append(PlannedScan(ref=ref, result_file=result_file))

    # ``result_file_name`` fingerprints the full reference, so a collision here
    # would mean a hash collision — assert it rather than trust it, because the
    # failure mode is one image's findings reported as another's.
    files = [scan.result_file for scan in planned]
    if len(set(files)) != len(files):
        raise ProducerError("two distinct images produced the same result_file path")

    return tuple(planned)


def build_fragment(
    repository: str,
    planned: tuple[PlannedScan, ...],
    *,
    generator: str = DEFAULT_GENERATOR,
) -> dict[str, object]:
    """The fragment document: a manifest with this repository's entries only."""
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": generator,
        "entries": [scan.entry(repository) for scan in planned],
    }


def render_plan(planned: tuple[PlannedScan, ...]) -> str:
    """The scan plan as TSV. Tabs are safe: no image reference can contain one."""
    return "".join(f"{scan.ref.ref}\t{scan.result_file}\n" for scan in planned)


def _load_images(args: argparse.Namespace) -> list[str]:
    images: list[str] = list(args.image)
    if args.images_json is not None:
        try:
            document = json.loads(args.images_json.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ProducerError(f"cannot read {args.images_json}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ProducerError(f"{args.images_json} is not valid JSON: {exc}") from exc
        if not isinstance(document, dict) or not isinstance(document.get("images"), list):
            raise ProducerError(f"{args.images_json} must be an object with an 'images' array")
        for item in document["images"]:
            if not isinstance(item, str):
                raise ProducerError(f"{args.images_json}: every image must be a string")
            images.append(item)
    return images


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="make_manifest",
        description="Produce a manifest fragment and Trivy scan plan for one repository.",
    )
    parser.add_argument("--repository", required=True, help="GitOps repository name.")
    parser.add_argument(
        "--images-json",
        type=Path,
        metavar="FILE",
        help="Output of discover_images: an object with an 'images' array.",
    )
    parser.add_argument(
        "--image",
        action="append",
        default=[],
        metavar="REF",
        help="An image reference. Repeatable; combined with --images-json.",
    )
    parser.add_argument(
        "--fragment-out",
        required=True,
        type=Path,
        metavar="FILE",
        help="Where to write the manifest fragment.",
    )
    parser.add_argument(
        "--plan-out",
        type=Path,
        metavar="FILE",
        help="Where to write the TSV scan plan.",
    )
    parser.add_argument(
        "--results-prefix",
        metavar="DIR",
        help="Directory prefix for result files, relative to --input. Defaults to the "
        "slugged repository name.",
    )
    parser.add_argument(
        "--generator",
        default=DEFAULT_GENERATOR,
        help=f"Recorded in the manifest for diagnostics. Default: {DEFAULT_GENERATOR}",
    )
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="Permit a repository that declares no images. Off by default: an overlay "
        "that renders no workloads is far more often a wrong path than an empty repo.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        images = _load_images(args)
        planned = plan_scans(args.repository, images, results_prefix=args.results_prefix)
        if not planned and not args.allow_empty:
            raise ProducerError(
                f"no images discovered for {args.repository!r}; check the overlay paths "
                f"(pass --allow-empty if this repository genuinely deploys none)"
            )
        fragment = build_fragment(args.repository, planned, generator=args.generator)
    except ProducerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    args.fragment_out.parent.mkdir(parents=True, exist_ok=True)
    args.fragment_out.write_text(
        json.dumps(fragment, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if args.plan_out is not None:
        args.plan_out.parent.mkdir(parents=True, exist_ok=True)
        args.plan_out.write_text(render_plan(planned), encoding="utf-8")

    print(
        f"planned {len(planned)} image(s) for {args.repository}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    sys.exit(main())
