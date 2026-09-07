"""Extract container image references from rendered Kubernetes YAML.

Input is whatever ``kubectl kustomize <overlay>`` printed — a multi-document YAML
stream. Output is the sorted, de-duplicated set of image references it declares.

**Why a line scanner and not a YAML parser.** The standard library has no YAML
parser, and this step runs on the same locked-down agent as everything else, so
adding PyYAML would trade a hard dependency for convenience on a task with a
narrow shape: rendered Kustomize output is block-style, machine-generated, and
regular. The scanner tracks indentation well enough to know which keys are
ancestors of an ``image:`` key, which is all that is needed to tell a container
image from an annotation that happens to mention one.

**Where it deliberately fails loudly.** A value under an ``image:`` key that cannot
be parsed as a reference is an error, not a warning (Principle IV). Dropping it
would produce a report that looks complete while an image went unscanned, and a
silently unscanned image is exactly the failure this whole application exists to
prevent.

Usage::

    python3 -m pipeline.scripts.discover_images --rendered rendered.yaml --out images.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from pipeline.scripts.image_ref import ImageRef, InvalidImageRef, parse

IMAGE_KEY = "image"

DENIED_ANCESTORS = frozenset(
    {
        "annotations",
        "labels",
        "matchLabels",
        "data",
        "stringData",
        "binaryData",
    }
)
"""Keys whose subtrees hold free-form text, not workload specifications.

``metadata.annotations`` in particular routinely carries a serialised copy of a
whole manifest (``last-applied-configuration``), and counting an image mentioned
there would scan something that is not deployed.
"""

_DOC_BOUNDARY_RE = re.compile(r"^(---|\.\.\.)(\s.*)?$")
_KEY_RE = re.compile(r"^(?P<key>[A-Za-z0-9_][A-Za-z0-9_.\-/]*)\s*:(?P<rest>\s.*|)$")
_BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?\d*$")


@dataclass(frozen=True)
class Discovery:
    """One ``image:`` key found in the stream, with enough context to explain it."""

    value: str
    line: int
    path: str
    source: str

    def where(self) -> str:
        return f"{self.source}:{self.line} ({self.path})"


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_inline_comment(value: str) -> str:
    """Remove a trailing ``# comment`` from an unquoted scalar.

    Quote-aware because ``image: "foo#bar"`` is a legal (if odd) scalar, while
    ``image: foo # pinned`` is a comment. Image references cannot contain ``#``,
    so the only risk being managed here is a quoted value.
    """
    quote: str | None = None
    for index, char in enumerate(value):
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            continue
        if char == "#" and (index == 0 or value[index - 1] in " \t"):
            return value[:index]
    return value


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _scalar(rest: str) -> str:
    return _unquote(_strip_inline_comment(rest).strip()).strip()


def iter_discoveries(text: str, *, source: str = "<stdin>") -> Iterator[Discovery]:
    """Yield every ``image:`` key in the stream that is not under a denied ancestor.

    The indentation stack is reset at each ``---`` so one document's structure
    cannot leak into the next.
    """
    stack: list[tuple[int, str]] = []
    block_scalar_indent: int | None = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()

        if block_scalar_indent is not None:
            # Inside a literal/folded block: content is text, not structure. Blank
            # lines belong to the block regardless of their indentation.
            if not stripped or _indent_of(raw_line) > block_scalar_indent:
                continue
            block_scalar_indent = None

        if not stripped or stripped.startswith("#"):
            continue

        if _DOC_BOUNDARY_RE.match(stripped):
            stack.clear()
            continue

        indent = _indent_of(raw_line)
        content = raw_line[indent:]

        # A sequence item's key sits two columns right of the dash, whether or not
        # the key shares the dash's line.
        while content.startswith("- "):
            content = content[2:]
            indent += 2
        if content == "-":
            continue

        match = _KEY_RE.match(content)
        if match is None:
            continue

        key = match["key"]
        rest = match["rest"]

        while stack and stack[-1][0] >= indent:
            stack.pop()
        ancestors = [name for _, name in stack]
        stack.append((indent, key))

        if _BLOCK_SCALAR_RE.match(rest.strip()):
            block_scalar_indent = indent
            continue

        if key != IMAGE_KEY:
            continue
        if DENIED_ANCESTORS.intersection(ancestors):
            continue

        value = _scalar(rest)
        if not value:
            continue

        yield Discovery(
            value=value,
            line=line_number,
            path=".".join([*ancestors, key]),
            source=source,
        )


def discover(sources: dict[str, str]) -> tuple[tuple[ImageRef, ...], tuple[str, ...]]:
    """Parse every source, returning sorted unique refs and per-value errors.

    Errors are returned rather than raised so the caller can report *all* of them
    in one pass. A pipeline operator fixing overlays wants the whole list, not the
    first offender.
    """
    refs: dict[str, ImageRef] = {}
    errors: list[str] = []

    for source in sorted(sources):
        for discovery in iter_discoveries(sources[source], source=source):
            try:
                ref = parse(discovery.value)
            except InvalidImageRef as exc:
                errors.append(f"{discovery.where()}: {exc}")
                continue
            refs.setdefault(ref.ref, ref)

    ordered = tuple(sorted(refs.values(), key=lambda r: r.sort_key))
    return ordered, tuple(errors)


def _read_sources(paths: list[Path]) -> dict[str, str]:
    if not paths:
        return {"<stdin>": sys.stdin.read()}
    return {path.as_posix(): path.read_text(encoding="utf-8") for path in paths}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="discover_images",
        description="Extract container image references from rendered Kubernetes YAML.",
    )
    parser.add_argument(
        "--rendered",
        action="append",
        default=[],
        metavar="FILE",
        type=Path,
        help="Rendered YAML to scan. Repeatable. Reads stdin when omitted.",
    )
    parser.add_argument(
        "--out",
        metavar="FILE",
        type=Path,
        help="Write the image list here as JSON. Defaults to stdout.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        sources = _read_sources(args.rendered)
    except OSError as exc:
        print(f"error: cannot read rendered YAML: {exc}", file=sys.stderr)
        return 1

    refs, errors = discover(sources)

    for message in errors:
        print(f"error: {message}", file=sys.stderr)
    if errors:
        print(
            f"error: {len(errors)} image reference(s) could not be parsed; refusing to "
            f"continue rather than leave them unscanned",
            file=sys.stderr,
        )
        return 1

    document = {"images": [ref.ref for ref in refs]}
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"

    if args.out is None:
        sys.stdout.write(payload)
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")

    print(
        f"discovered {len(refs)} unique image(s) in {len(sources)} rendered file(s)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    sys.exit(main())
