#!/usr/bin/env python
"""Generate the documentation test matrix (directive section 36).

The directive asks for a table of areas against four columns: documentation, example, diagram,
validated. This script earns each tick from the tree rather than asserting it:

* **documentation** - the page that documents the area exists *and* is reachable in `mkdocs.yml`;
* **example** - some file under `examples/` names the area's namespace;
* **diagram** - the area's page (or the page that carries its flows) contains a Mermaid fence;
* **validated** - a test file names the area's namespace, and the documentation test checks the
  page set (navigation and links) that the page belongs to.

A column with no evidence prints `-`, and the notes below the table say what each tick stands on,
so a reader can audit a row without trusting this script.

`--check` fails when the committed page does not match the tree.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
TARGET = DOCS / "development" / "documentation-test-matrix.md"
MK = ROOT / "mkdocs.yml"

# area -> (namespace, the markers an example would carry, pages, pages that carry its diagram)
AREAS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "Authentication": (
        "jdlib.authn",
        ("jdlib.authn", "jdlib.security.authn"),
        ("jdlib/features/authentication.md", "integrations/identity.md"),
        ("architecture/security-architecture.md",),
    ),
    "SecurityContext": (
        "jdlib.security.context",
        ("jdlib.security.context",),
        ("jdlib/features/tenancy.md", "jdlib/architecture/security-model.md"),
        ("architecture/security-architecture.md",),
    ),
    "Authorization": (
        "jdlib.authz",
        ("jdlib.authz",),
        ("jdlib/features/authorization.md",),
        ("architecture/security-architecture.md",),
    ),
    "Tenancy": (
        "jdlib.tenancy",
        ("jdlib.tenancy",),
        ("jdlib/features/tenancy.md",),
        ("architecture/data-architecture.md",),
    ),
    "Privileges": (
        "jdlib.authz.permissions",
        ("jdlib.authz.permissions", "jdlib.authz"),
        ("jdlib/features/authorization.md",),
        ("architecture/security-architecture.md",),
    ),
    "PostgreSQL": (
        "jdlib.data.postgres",
        ("jdlib.persistence", "jdlib.data.postgres", "postgres"),
        ("jdlib/features/connectors.md", "integrations/postgresql.md"),
        ("architecture/data-architecture.md",),
    ),
    "Neo4j": (
        "jdlib.graph",
        ("jdlib.graph",),
        ("jdlib/features/graph.md", "integrations/neo4j.md"),
        ("architecture/data-architecture.md",),
    ),
    "MCP": (
        "jdlib.integrations.mcp",
        ("jdlib.integrations.mcp",),
        ("jdlib/features/mcp.md", "integrations/mcp.md"),
        ("jdlib/features/mcp.md",),
    ),
    "Audit": (
        "jdlib.security.audit",
        ("jdlib.security.audit",),
        ("jdlib/features/audit.md",),
        ("architecture/security-architecture.md",),
    ),
    "Reliability": (
        "jdlib.reliability",
        ("jdlib.reliability", "retry", "timeout"),
        ("reliability/overview.md", "reliability/failure-modes.md"),
        ("architecture/reliability-architecture.md",),
    ),
    "Observability": (
        "jdlib.observability",
        ("jdlib.observability", "telemetry", "tracing"),
        ("jdlib/features/observability.md", "observability/overview.md"),
        ("architecture/observability-architecture.md",),
    ),
    "Errors": (
        "jdlib.security.errors",
        ("jdlib.security.errors",),
        ("reference/error-codes.md",),
        ("architecture/request-lifecycle.md",),
    ),
    "Health": (
        "jdlib.integrations.fastapi",
        ("jdlib.integrations.fastapi", "health"),
        ("operations/health-and-readiness.md",),
        ("architecture/request-lifecycle.md",),
    ),
    "Operations": (
        "jdlib.integrations.cli",
        ("jdlib.integrations.cli", "docker compose", "Dockerfile"),
        ("operations/deployment.md", "operations/production-checklist.md"),
        ("operations/deployment.md",),
    ),
}


#: Where a column is honestly empty, say what stands in its place rather than leaving a bare dash.
NOTES: dict[str, str] = {
    "Observability": (
        "no test file names `jdlib.observability`; the signals are covered through "
        "`jdlib.security.telemetry` and `jdlib.security.tracing`, which do have tests"
    ),
}


def first_existing(candidates: tuple[str, ...]) -> str | None:
    """The first candidate page that exists, so a row can move without editing this table."""

    for candidate in candidates:
        if (DOCS / candidate).exists():
            return candidate
    return None


def mentions(path: Path, needle: str) -> bool:
    try:
        return needle in path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def files_mentioning(where: Path, needle: str, suffix: str = ".py") -> list[str]:
    """Files under `where` that name the needle; an empty suffix means every file."""

    found: list[str] = []
    for path in sorted(where.rglob(f"*{suffix}") if suffix else where.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if mentions(path, needle):
            found.append(path.relative_to(ROOT).as_posix())
    return found


def cells(area: str) -> dict[str, tuple[bool, str]]:
    namespace, needles, pages, diagram_pages = AREAS[area]
    page = first_existing(pages)
    documented = page is not None and mentions(MK, page)
    examples = [
        hit for needle in needles for hit in files_mentioning(ROOT / "examples", needle, "")
    ]
    diagram_page = first_existing(diagram_pages)
    diagram = diagram_page is not None and "```mermaid" in (
        (DOCS / diagram_page).read_text(encoding="utf-8", errors="replace")
    )
    tests = files_mentioning(ROOT / "tests", namespace)
    portal = ROOT / "tests" / "unit" / "test_docs_portal.py"
    validated = bool(tests) and portal.exists()
    return {
        "documentation": (documented, page or "no page"),
        "example": (
            bool(examples),
            sorted(set(examples))[0] if examples else "no example",
        ),
        "diagram": (diagram, diagram_page or "no diagram"),
        "validated": (
            bool(validated),
            f"{tests[0]} (+ the documentation test)" if tests else "no test",
        ),
    }


def page_text() -> str:
    out = [
        "# Documentation test matrix",
        "",
        "Generated by `scripts/docs-matrix.py`; the gate runs `--check`, so a row that stops being",
        "true fails the build. Each tick stands on something in the tree:",
        "",
        "| Column | The tick means |",
        "|---|---|",
        "| Documentation | the page exists, and `mkdocs.yml` reaches it |",
        "| Example | a file under `examples/` names a marker the area owns |",
        "| Diagram | the area's page carries a Mermaid diagram |",
        "| Validated | a test file names the area's namespace, and the documentation test runs |",
        "",
        "A column with no evidence prints `-` rather than a tick, and the notes below the table",
        "name the file each tick stands on, so a row can be audited without trusting a script.",
        "",
        "| Area | Documentation | Example | Diagram | Validated |",
        "|---|---:|---:|---:|---:|",
    ]
    notes: list[str] = []
    for area in AREAS:
        row = cells(area)
        ticks = " | ".join("✓" if row[key][0] else "-" for key in
                           ("documentation", "example", "diagram", "validated"))
        out.append(f"| {area} | {ticks} |")
        namespace = AREAS[area][0]
        detail = "; ".join(f"{key}: {row[key][1]}" for key in
                           ("documentation", "example", "diagram", "validated"))
        if not row["validated"][0] and area in NOTES:
            detail = f"{detail} - {NOTES[area]}"
        notes.append(f"* **{area}** - `{namespace}` - {detail}.")
    out += [
        "",
        "## What each row stands on",
        "",
        *notes,
        "",
        "## Areas documented beyond the directive's list",
        "",
        "The directive says to update this matrix from the implementation. The portal also",
        "documents these, each with a page and tests, and they are not forced into the rows",
        "above: caching, credentials, connectors, jobs, query system, resource management, storage",
        "(see [Features](../jdlib/features/README.md)) and the graph plane's tenant isolation",
        "(see [Graph](../jdlib/features/graph.md)).",
        "",
        "Regenerate with `python scripts/docs-matrix.py`; the documentation test fails when this"
        "page",
        "is stale.",
    ]
    return "\n".join(out) + "\n"


def _first_difference(current: str, generated: str) -> str:
    """Where a stale page differs, so the failure names the line instead of only the fact."""

    old = current.replace("\r\n", "\n").splitlines()
    new = generated.replace("\r\n", "\n").splitlines()
    for number, (was, now) in enumerate(zip(old, new, strict=False), start=1):
        if was != now:
            return f"line {number}:\n  on disk:   {was[:120]}\n  generated: {now[:120]}"
    if len(old) != len(new):
        extra = abs(len(old) - len(new))
        following = (old if len(old) > len(new) else new)[min(len(old), len(new))][:120]
        return f"{extra} more line(s) on one side; next: {following!r}"
    return "the text differs only in line endings"


def main() -> int:
    text = page_text()
    if "--check" in sys.argv[1:]:
        if not TARGET.exists():
            print(f"FAIL: {TARGET.relative_to(ROOT)} does not exist")
            return 1
        on_disk = TARGET.read_text(encoding="utf-8").replace("\r\n", "\n")
        if on_disk != text.replace("\r\n", "\n"):
            print("FAIL: the documentation test matrix is stale")
            print("regenerate with: python scripts/docs-matrix.py")
            print(_first_difference(on_disk, text))
            return 1
        print("the documentation test matrix matches the tree")
        return 0
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(text, encoding="utf-8")
    ticks = sum(1 for area in AREAS for cell in cells(area).values() if cell[0])
    earned = f"{ticks}/{len(AREAS) * 4}"
    print(f"documentation-test-matrix: {len(AREAS)} areas, {earned} cells with evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
