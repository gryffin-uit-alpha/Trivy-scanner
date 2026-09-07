"""Markdown primitives shared by both reports (contracts/report-format.md).

Pure functions from values to text: no filesystem, no clock, no state. Both
renderers build every table through these so the two reports cannot drift apart —
a column order or trend glyph defined twice would eventually be defined
differently, and a reader comparing the fleet report against a repository report
would silently be comparing different things.

Three rules are enforced here rather than left to each renderer:

- **Column order is the ``Severity`` declaration order** (FR-022). Never
  alphabetical, never input-derived.
- **A trend cell always carries the signed number, not only the glyph** (FR-018).
  Terminals, plain-text mail and some diff viewers drop the arrow; the delta must
  survive that.
- **Names are escaped before they reach a table.** A repository literally named
  ``repo|a`` would otherwise split one row into two cells and shift every count
  one column left — a corruption that looks like a rendering quirk and reads as
  real data.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import date

from trivy_report.models import Severity, SeverityCounts, Trend, TrendDirection, TrendSet

SEVERITY_COLUMNS: tuple[Severity, ...] = tuple(Severity)
"""The five severity columns in report order. Derived from the enum so the order
has exactly one definition (FR-022)."""

SEVERITY_HEADERS: tuple[str, ...] = tuple(s.value for s in SEVERITY_COLUMNS)

UNKNOWN_CELL = "?"
"""Rendered when counts are untrustworthy. Deliberately not ``0``: reading "could
not parse" as "clean" is the most dangerous mistake this report could make."""

_GLYPHS = {
    TrendDirection.UP: "↑",
    TrendDirection.DOWN: "↓",
    TrendDirection.FLAT: "→",
}

COUNTING_SEMANTICS_NOTE = (
    "> Counts are finding instances, not distinct CVEs: one count per "
    "(image, CVE, package, package path).\n"
    "> The same CVE affecting two packages in one image counts twice."
)
"""Mandatory in every report. A reader comparing these numbers against Trivy's own
summary sees a larger figure here and would otherwise conclude the report is
broken (D5)."""

NO_BASELINE_HEADER = "none (baseline run)"
NO_BASELINE_SUMMARY = "none (first run)"


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------


def escape(text: str) -> str:
    """Make arbitrary text safe as a table cell.

    ``|`` becomes ``\\|`` so a name cannot end a cell early. Newlines and carriage
    returns collapse to a space: a literal newline inside a row would end the row
    mid-table, and every subsequent row would be parsed against the wrong header.
    """
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def code(text: str) -> str:
    """A code span containing ``text``.

    Backticks are stripped rather than escaped: an inner backtick closes the span
    early, after which the rest of the name renders as prose and any ``|`` in it
    stops being escaped by the span at all. Nothing else needs escaping inside a
    span except ``|``, which the table syntax still honours.
    """
    return f"`{escape(text.replace('`', ''))}`"


def bold(text: str) -> str:
    return f"**{text}**"


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------


def row(cells: Iterable[str]) -> str:
    """One table row. Cells are used verbatim — escape before calling."""
    return "| " + " | ".join(cells) + " |"


def header(cells: Sequence[str]) -> list[str]:
    """A header row plus its separator, as two lines."""
    return [row(cells), row("---" for _ in cells)]


def table(head: Sequence[str], body: Iterable[Iterable[str]]) -> list[str]:
    """A complete table. Column count comes from the header, so a body row of the
    wrong width shows up as a malformed table rather than silently shifting
    columns."""
    return [*header(head), *(row(cells) for cells in body)]


# ---------------------------------------------------------------------------
# Count cells
# ---------------------------------------------------------------------------


def trend_cell(count: int, trend: Trend) -> str:
    """One count paired with its trend, in one of the three permitted shapes.

    ``(new)`` carries no glyph on purpose: an arrow would assert a comparison
    against a baseline that does not exist, and ``→ 0`` in particular would state
    "unchanged" about a subject nobody has seen before (FR-015).
    """
    if trend.direction is TrendDirection.BASELINE:
        return f"{count} (new)"
    if trend.direction is TrendDirection.FLAT:
        # Plain ``0``, not ``+0``: a sign on zero suggests a direction, and the
        # arrow beside it already says there was none.
        return f"{count} {_GLYPHS[trend.direction]} 0"
    return f"{count} {_GLYPHS[trend.direction]} {trend.delta:+d}"


def count_cells(
    counts: SeverityCounts,
    trends: TrendSet,
    *,
    unknown: bool = False,
    strong: bool = False,
) -> list[str]:
    """The five severity cells plus the Total cell, in report order.

    ``unknown=True`` renders every cell as ``?`` — used for a row whose source
    file could not be parsed. The Total is ``?`` as well: a total of untrustworthy
    numbers is not a trustworthy number.

    The Total carries no trend. A delta on a sum across severities mixes a
    CRITICAL improvement with a LOW regression into one figure that supports no
    conclusion.
    """
    if unknown:
        cells = [UNKNOWN_CELL] * 6
    else:
        cells = [
            trend_cell(counts.get(severity), trends.get(severity)) for severity in SEVERITY_COLUMNS
        ]
        cells.append(str(counts.total))
    return [bold(c) for c in cells] if strong else cells


def plain_count_cells(counts: SeverityCounts) -> list[str]:
    """The five severity counts with no trends, for last-known figures.

    Removed images and unscanned repositories are reported without trends: their
    counts are a record of the last time anyone looked, and a delta against them
    would describe a change in *coverage* as a change in *risk*.
    """
    return [str(counts.get(severity)) for severity in SEVERITY_COLUMNS]


# ---------------------------------------------------------------------------
# Shared document blocks
# ---------------------------------------------------------------------------


def header_block(*, scan_date: date, baseline_date: date | None, version: str) -> list[str]:
    """Scan date, baseline date, and tool version — all three, every report.

    The tool version is present because the report format is versioned alongside
    the code: a reader diffing two reports needs to know whether a layout change
    means the data changed or the renderer did (FR-019).
    """
    compared = NO_BASELINE_HEADER if baseline_date is None else baseline_date.isoformat()
    return [
        f"**Scan date**: {scan_date.isoformat()}",
        f"**Compared against**: {compared}",
        f"**Generated by**: trivy-report {version}",
    ]


def baseline_summary_line(baseline_date: date | None) -> str:
    """The Run Summary's baseline line.

    Worded differently from the header on purpose: the header answers "what is
    this compared against", the summary answers "was there anything to compare
    against at all".
    """
    value = NO_BASELINE_SUMMARY if baseline_date is None else baseline_date.isoformat()
    return f"- **Baseline**: {value}"


def bullet(label: str, value: object) -> str:
    return f"- **{label}**: {value}"


def history_lines(*, pruned: int, skipped: Sequence[str]) -> list[str]:
    """The archive-housekeeping lines of the Run Summary, when there are any.

    Both lines are omitted when their figure is zero or empty, unlike the coverage
    lines above them which are always present. The difference is deliberate: the
    coverage figures are what a reader came for, while these two describe events
    that do not happen on an ordinary day. Rendered as ``0`` every day, they become
    lines readers learn to skip — precisely on the day one of them is non-zero.

    Both are shared by the two reports so a reader reconciling them cannot find two
    different accounts of the same housekeeping (FR-019).

    ``skipped`` names each file rather than counting them. A preserved file is only
    actionable if it can be found, and "1 file skipped" sends an operator through
    the whole archive by hand (FR-011a).
    """
    lines: list[str] = []
    if pruned:
        lines.append(bullet("History files pruned", pruned))
    if skipped:
        lines.append(bullet("History files skipped", ", ".join(code(name) for name in skipped)))
    return lines


def failures_table(failures: Sequence[object]) -> list[str]:
    """The Failures table, or nothing at all when there are no failures.

    Omitted rather than rendered empty: a table with a header and no rows reads as
    "failures were not checked" on a skim, when in fact none occurred.
    """
    if not failures:
        return []
    body = [
        [code(failure.file), failure.kind.value, escape(failure.reason)]  # type: ignore[attr-defined]
        for failure in failures
    ]
    return ["### Failures", "", *table(["File", "Kind", "Reason"], body)]


def document(blocks: Iterable[Sequence[str] | str]) -> str:
    """Join blocks into one document with exactly one trailing newline.

    Blank lines between blocks come from here rather than from each renderer, so
    two documents built from the same data cannot differ by whitespace — which
    would break the byte-identical guarantee without changing a single number
    (Principle III).
    """
    parts: list[str] = []
    for block in blocks:
        lines = [block] if isinstance(block, str) else [line for line in block]
        if not lines:
            continue
        parts.append("\n".join(lines))
    return "\n\n".join(parts) + "\n"
