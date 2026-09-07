"""Parsing and slugging of container image references.

One owner for the ref grammar. Both image discovery and the manifest producer need
to split ``registry/name:tag@digest`` into its parts, and they must agree exactly:
discovery decides whether a string is an image at all, while the producer decides
what ``image_name`` / ``image_tag`` / ``image_digest`` the manifest carries. Two
regexes would drift and the disagreement would surface as an image silently
dropped from a report.

Grammar (a pragmatic subset of the OCI reference spec, sufficient for what
``kubectl kustomize`` emits):

    [host[:port]/]path[/path...][:tag][@algo:hex]

The registry-port and tag colons are genuinely ambiguous — ``reg:5000/app`` and
``app:1.2`` differ only in what follows. The pattern resolves it the way registries
do: a colon before a ``/`` is a port, a colon after the last ``/`` is a tag.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

_COMPONENT = r"[A-Za-z0-9][A-Za-z0-9._-]*"

_REF_RE = re.compile(
    rf"""
    ^
    (?P<name>
        {_COMPONENT}
        (?::\d+)?                 # registry port, only meaningful before a '/'
        (?:/{_COMPONENT})*
    )
    (?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9._-]{{0,127}}))?
    (?:@(?P<digest>[A-Za-z0-9]+:[A-Fa-f0-9]{{32,}}))?
    $
    """,
    re.VERBOSE,
)

# Anything a template engine left behind. Scanning rendered output that still
# contains a placeholder means the render was incomplete, which is worth a loud
# skip rather than handing Trivy a string it cannot pull.
_UNRESOLVED_RE = re.compile(r"\{\{|\$\{|\$\(")

_SLUG_ILLEGAL_RE = re.compile(r"[^a-z0-9._-]+")
_SLUG_RUNS_RE = re.compile(r"-{2,}")

MAX_SLUG_LENGTH = 100
"""Matches the report writer's cap (``contracts/cli.md``, filename sanitisation).
Result file names are not report names, but keeping one number means a path that
survives here survives there."""


class InvalidImageRef(ValueError):
    """The string is not a usable image reference."""


@dataclass(frozen=True)
class ImageRef:
    """A parsed reference. ``name`` never carries the tag or digest.

    Mirrors the manifest entry fields deliberately: ``name`` → ``image_name``,
    ``tag`` → ``image_tag``, ``digest`` → ``image_digest``.
    """

    name: str
    tag: str | None
    digest: str | None

    @property
    def ref(self) -> str:
        """The canonical string form, round-tripping ``parse``."""
        out = self.name
        if self.tag:
            out += f":{self.tag}"
        if self.digest:
            out += f"@{self.digest}"
        return out

    @property
    def sort_key(self) -> tuple[str, str, str]:
        """Deterministic ordering. Every emitted list is sorted by this."""
        return (self.name, self.tag or "", self.digest or "")


def parse(raw: str) -> ImageRef:
    """Parse a reference, or raise ``InvalidImageRef`` explaining why not.

    An untagged, undigested reference is accepted and means ``:latest`` to a
    registry — but it is *not* rewritten to ``latest`` here. The manifest schema
    requires a tag or a digest, so the producer rejects it with a message naming
    the image; guessing ``latest`` would report yesterday's counts against
    whatever the tag points at today.
    """
    value = raw.strip()
    if not value:
        raise InvalidImageRef("empty image reference")
    if _UNRESOLVED_RE.search(value):
        raise InvalidImageRef(f"unresolved template placeholder in {value!r}")

    match = _REF_RE.match(value)
    if match is None:
        raise InvalidImageRef(f"not a valid image reference: {value!r}")

    return ImageRef(
        name=match["name"],
        tag=match["tag"],
        digest=match["digest"],
    )


def slug(text: str) -> str:
    """Filesystem-safe form of ``text``: lowercase, ``[a-z0-9._-]`` only.

    Same rules as the report writer's repository-name sanitisation, so operators
    only ever learn one convention.
    """
    lowered = _SLUG_ILLEGAL_RE.sub("-", text.lower())
    collapsed = _SLUG_RUNS_RE.sub("-", lowered).strip("-")
    return collapsed[:MAX_SLUG_LENGTH].strip("-")


def result_file_name(ref: ImageRef) -> str:
    """A stable, collision-resistant file name for one image's Trivy JSON.

    The slug alone is not enough: two distinct references can slug identically
    once the 100-character cap bites, and two images sharing one result file would
    attribute one image's findings to another. A short digest of the *full*
    reference is appended so distinct inputs always produce distinct names, while
    identical input always produces the same name (determinism, Principle III).
    """
    fingerprint = hashlib.sha256(ref.ref.encode("utf-8")).hexdigest()[:8]
    body = slug(ref.ref)
    # Reserve room for the fingerprint so the cap cannot truncate it away.
    body = body[: MAX_SLUG_LENGTH - len(fingerprint) - 1].strip("-")
    return f"{body}-{fingerprint}.json"
