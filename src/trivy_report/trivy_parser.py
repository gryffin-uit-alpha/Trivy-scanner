"""Trivy JSON parsing (contracts/trivy-input.md).

**Every Trivy-shaped assumption in this application lives here** (research D12).
Nothing downstream of ``normalize.py`` knows Trivy's field names, so if a name
below turns out to be wrong, the cost is this module plus a fixture refresh —
not a rewrite.

Two behaviours in this module matter more than the rest:

1. A file that could not be understood is a **failure**, never an image with zero
   vulnerabilities. Reporting a clean bill of health for an unparseable file is
   the worst failure mode a security report has.
2. ``Vulnerabilities`` being absent **is** zero findings, because that is what
   Trivy emits for a clean image (FR-006). The difference between the two is the
   difference between "Trivy said nothing is wrong" and "we could not tell what
   Trivy said".

Recoverable failures are returned as data, never raised (Principle IV): one bad
file must not deny the reader every other repository's report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from trivy_report.models import FailureKind, Finding, ParseFailure, Severity

# Classes carrying CVEs. Anything not in either set is counted WITH a warning
# (fail open), so a future CVE-bearing class is never silently dropped.
COUNTED_CLASSES = frozenset({"os-pkgs", "lang-pkgs"})

# Known non-CVE classes. Counting these would inflate severity totals with
# secrets, misconfigurations, and licence findings, which are real problems but
# not vulnerabilities and not what these reports measure.
EXCLUDED_CLASSES = frozenset({"secret", "config", "license"})

# Observed firsthand in Phase B against Trivy 0.73.0 (`trivy image --format json`
# over alpine:3.20 and node:18-slim, plus a secret-bearing image). Recorded rather
# than enforced: an unobserved version warns and is still parsed, because Trivy
# bumping this number is far more likely than Trivy renaming every field beneath
# it, and refusing valid production output is the worse error. The field-level
# checks below are what actually decide whether a document is understood.
OBSERVED_SCHEMA_VERSIONS = frozenset({2})


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Outcome of parsing one Trivy result file.

    ``failure`` and ``findings`` are mutually exclusive in practice: a failed
    parse yields no findings, because partial data from a file whose shape is not
    understood cannot be trusted to be partial in a safe direction.
    """

    findings: tuple[Finding, ...] = ()
    failure: ParseFailure | None = None
    warnings: tuple[str, ...] = field(default=())


def _failed(
    relative_name: str,
    kind: FailureKind,
    reason: str,
    repository: str | None,
    warnings: tuple[str, ...] = (),
) -> ParseResult:
    return ParseResult(
        findings=(),
        failure=ParseFailure(file=relative_name, kind=kind, reason=reason, repository=repository),
        warnings=warnings,
    )


def parse_result_file(
    path: Path,
    *,
    relative_name: str | None = None,
    repository: str | None = None,
) -> ParseResult:
    """Parse one Trivy JSON file into findings, or classify why it could not be.

    ``relative_name`` is what appears in reports and logs — a path relative to
    ``--input``, so the message is identical on every agent regardless of where
    the workspace was checked out.

    The file is only ever read; inputs are never modified (constitution,
    Security & Data Handling).
    """
    path = Path(path)
    name = relative_name if relative_name is not None else path.name

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return _failed(name, FailureKind.FILE_MISSING, "file does not exist", repository)
    except IsADirectoryError:
        return _failed(
            name, FailureKind.UNREADABLE, "expected a file but found a directory", repository
        )
    except PermissionError:
        return _failed(name, FailureKind.UNREADABLE, "permission denied", repository)
    except UnicodeDecodeError:
        # Not valid UTF-8, so it cannot be valid JSON either.
        return _failed(name, FailureKind.MALFORMED_JSON, "file is not valid UTF-8 text", repository)
    except OSError as exc:
        return _failed(
            name, FailureKind.UNREADABLE, f"could not be read ({exc.strerror})", repository
        )

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        # Position, not a traceback: the reader is scanning a CI log.
        return _failed(
            name,
            FailureKind.MALFORMED_JSON,
            f"not valid JSON: {exc.msg} at line {exc.lineno}, column {exc.colno}",
            repository,
        )

    return _parse_document(document, name, repository)


def _parse_document(document: object, name: str, repository: str | None) -> ParseResult:
    warnings: list[str] = []

    if not isinstance(document, dict):
        return _failed(
            name,
            FailureKind.SCHEMA_MISMATCH,
            f"top level is {type(document).__name__}, expected a Trivy report object",
            repository,
        )

    # SchemaVersion is checked for presence and numeric type, then compared
    # against OBSERVED_SCHEMA_VERSIONS for a warning only — never rejected on
    # value. Phase B confirmed 2 is what Trivy 0.73.0 emits; a future 3 should
    # produce a report plus a visible warning, not a failed run.
    if "SchemaVersion" not in document:
        return _failed(
            name,
            FailureKind.SCHEMA_MISMATCH,
            "SchemaVersion is absent — this does not look like a Trivy report",
            repository,
        )
    version = document["SchemaVersion"]
    if isinstance(version, bool) or not isinstance(version, (int, float)):
        return _failed(
            name,
            FailureKind.SCHEMA_MISMATCH,
            f"SchemaVersion is {type(version).__name__}, expected a number",
            repository,
        )
    if version not in OBSERVED_SCHEMA_VERSIONS:
        expected = ", ".join(str(v) for v in sorted(OBSERVED_SCHEMA_VERSIONS))
        warnings.append(
            f"SchemaVersion {version} has not been verified against this parser "
            f"(observed: {expected}); parsing anyway, so check the counts"
        )

    if "Results" not in document:
        # Trivy omits Results entirely when it completed the scan but found nothing
        # to scan — an image with no OS package database and no language manifests,
        # such as a static binary or a distroless base. Verified against Trivy 0.73.0
        # with `busybox:1.36`, which yields SchemaVersion, ArtifactName, Metadata
        # without OS, and no Results key.
        #
        # That is a real zero, so treating it as a failure would drop the image out
        # of coverage every single night. But absent Results in a document that is
        # *not* recognisably a finished Trivy report must still never read as clean —
        # ArtifactName is what separates the two, since SchemaVersion is validated
        # above and a truncated file would not have parsed as JSON at all.
        artifact_name = document.get("ArtifactName")
        if not (isinstance(artifact_name, str) and artifact_name):
            return _failed(
                name,
                FailureKind.SCHEMA_MISMATCH,
                "Results is absent and so is ArtifactName — cannot distinguish a clean "
                "image from an unreadable report",
                repository,
            )
        warnings.append(
            "no Results — Trivy found no package database or language manifest in "
            "this image, so it is counted as zero findings"
        )
        results: object = []
    else:
        results = document["Results"]
        if not isinstance(results, list):
            return _failed(
                name,
                FailureKind.SCHEMA_MISMATCH,
                f"Results is {type(results).__name__}, expected an array",
                repository,
            )

    # Diagnostics only. The manifest is always the authority on which image this
    # file describes (FR-001a), so a disagreement is logged and ignored rather
    # than acted on.
    artifact_type = document.get("ArtifactType")
    if isinstance(artifact_type, str) and artifact_type and artifact_type != "container_image":
        warnings.append(
            f"{name}: ArtifactType is {artifact_type!r}, expected 'container_image' — "
            f"parsing anyway"
        )

    findings: list[Finding] = []
    for index, block in enumerate(results):
        if not isinstance(block, dict):
            return _failed(
                name,
                FailureKind.SCHEMA_MISMATCH,
                f"Results[{index}] is {type(block).__name__}, expected an object",
                repository,
                tuple(warnings),
            )

        raw_class = block.get("Class")
        class_name = raw_class.strip().lower() if isinstance(raw_class, str) else ""
        if class_name in EXCLUDED_CLASSES:
            # A documented exclusion is not a surprise, so it must not generate
            # log noise on every run.
            continue
        if class_name and class_name not in COUNTED_CLASSES:
            # Fail open, and say so. Silently dropping an unrecognised class would
            # hide real vulnerabilities if Trivy adds a CVE-bearing one.
            warnings.append(
                f"{name}: unrecognised result Class {raw_class!r} — counting its findings; "
                f"review whether it belongs in the report"
            )

        vulnerabilities = block.get("Vulnerabilities")
        if vulnerabilities is None:
            # Absent or null is what Trivy emits for a clean result (FR-006).
            continue
        if not isinstance(vulnerabilities, list):
            return _failed(
                name,
                FailureKind.SCHEMA_MISMATCH,
                f"Results[{index}].Vulnerabilities is {type(vulnerabilities).__name__}, "
                f"expected an array",
                repository,
                tuple(warnings),
            )

        for vuln_index, raw in enumerate(vulnerabilities):
            where = f"Results[{index}].Vulnerabilities[{vuln_index}]"
            if not isinstance(raw, dict):
                return _failed(
                    name,
                    FailureKind.SCHEMA_MISMATCH,
                    f"{where} is {type(raw).__name__}, expected an object",
                    repository,
                    tuple(warnings),
                )

            vulnerability_id = raw.get("VulnerabilityID")
            if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
                # Without an ID the finding cannot be deduplicated or reported, and
                # its absence means the document is not shaped as expected. Failing
                # the whole file is deliberate: silently dropping one finding would
                # under-report vulnerabilities.
                return _failed(
                    name,
                    FailureKind.SCHEMA_MISMATCH,
                    f"{where}.VulnerabilityID is absent or not a non-empty string",
                    repository,
                    tuple(warnings),
                )

            pkg_name = raw.get("PkgName")
            if not isinstance(pkg_name, str) or not pkg_name.strip():
                return _failed(
                    name,
                    FailureKind.SCHEMA_MISMATCH,
                    f"{where}.PkgName is absent or not a non-empty string",
                    repository,
                    tuple(warnings),
                )

            # Optional fields default rather than fail: their absence is normal.
            # PkgPath is empty for OS packages; InstalledVersion is informational.
            pkg_path = raw.get("PkgPath")
            installed_version = raw.get("InstalledVersion")

            findings.append(
                Finding(
                    vulnerability_id=vulnerability_id.strip(),
                    pkg_name=pkg_name.strip(),
                    pkg_path=pkg_path if isinstance(pkg_path, str) else "",
                    installed_version=(
                        installed_version if isinstance(installed_version, str) else ""
                    ),
                    # Absent, empty, null, or unrecognised all land in UNKNOWN —
                    # never folded into LOW, never discarded (FR-003).
                    severity=Severity.from_trivy(raw.get("Severity")),
                )
            )

    return ParseResult(findings=tuple(findings), failure=None, warnings=tuple(warnings))
