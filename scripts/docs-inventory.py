"""Generate the documentation inventory - the audit the documentation directive asks for first.

The audit answers one question per public namespace: *is this documented, and where is the
evidence?* It is generated rather than written because the mechanical half of that question has a
mechanical answer (which namespaces exist, which pages mention them, which tests hold them), and a
hand-written table of counts is wrong the first time someone adds an export.

What the generator decides mechanically:

* **DOCUMENTED** - a capability page or a feature guide exists for the namespace *and* at least one
  test file imports it;
* **PARTIALLY DOCUMENTED** - the namespace is mentioned in ``docs/`` but has neither a capability
  page nor a feature guide, or has one but no test;
* **UNDOCUMENTED** - nothing under ``docs/`` mentions it.

What it does not decide, and therefore states in a table of its own: the rows that need judgement -
EXPERIMENTAL, DEPRECATED, IMPLEMENTED BUT INTERNAL, and NOT IMPLEMENTED. Each of those carries a
reason and a citation, and the citations are paths the documentation test checks for existence. A
generator cannot tell whether a deferred connector engine is a gap or a decision; the roadmap can,
and that is where the row points.

Run it from the repository root:

    .venv/Scripts/python scripts/docs-inventory.py            # write the page
    .venv/Scripts/python scripts/docs-inventory.py --check     # fail if the page is stale
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "jdlib"
DOCS = ROOT / "docs"
TARGET = DOCS / "development" / "documentation-inventory.md"

#: Rows the mechanics cannot decide. Each one names the reason and where the evidence is, and the
#: documentation test checks that the cited path exists - so a stale citation fails the gate.
JUDGEMENT: tuple[tuple[str, str, str, str], ...] = (
    (
        "jdlib.data",
        "PARTIALLY DOCUMENTED",
        "PostgreSQL is the only connector with an implementation; the other four engines are "
        "deferred "
        "by decision, not by omission.",
        "docs/jdlib/successor/05-roadmap.md",
    ),
    (
        "jdlib.query",
        "PARTIALLY DOCUMENTED",
        "Two dialects exist (`PostgresDialect`, `MysqlDialect`) and only PostgreSQL is executed by "
        "any test: the MySQL dialect is implemented and unverified.",
        "docs/jdlib/examples/coverage-matrix.md",
    ),
    (
        "jdlib.storage",
        "PARTIALLY DOCUMENTED",
        "S3 is verified against real MinIO. Google Cloud Storage and Azure Blob have **no module "
        "and "
        "no export** - a provider class in the public surface is a claim that it works, and a test "
        "asserts they are absent.",
        "docs/jdlib/successor/05-roadmap.md",
    ),
    (
        "jdlib.graph",
        "DOCUMENTED",
        "One backend (Neo4j) and one live suite against a real instance; no second graph vendor is "
        "claimed anywhere.",
        "docs/jdlib/capabilities/graph.md",
    ),
    (
        "jdlib.tenancy",
        "DOCUMENTED",
        "Tenant resolution, the lifecycle and the job envelope are covered; the queue itself is the"
        ""
        "deployment's choice and is deliberately not implemented here.",
        "docs/jdlib/capabilities/jobs.md",
    ),
    (
        "jdlib.integrations.mcp",
        "DOCUMENTED",
        "The tool surface is implemented and live-tested. `graph_search` is deliberately absent - a"
        ""
        "free-text search over a graph is a statement the closed vocabulary cannot express.",
        "docs/jdlib/capabilities/mcp.md",
    ),
    (
        "jdlib.authn",
        "PARTIALLY DOCUMENTED",
        "API keys and OIDC are implemented. Other identity methods (SAML, Kerberos, mTLS) are **not"
        ""
        "implemented**: `build_authenticator` wires what exists and refuses a method it does not "
        "have.",
        "docs/jdlib/features/authentication.md",
    ),
    (
        "jdlib.caching",
        "DOCUMENTED",
        "Two providers (in-process and Redis) with the credential guard that refuses to cache a "
        "secret at all.",
        "docs/jdlib/capabilities/caching.md",
    ),
    (
        "jdlib.reliability",
        "DOCUMENTED",
        "Breaker, retry budget, concurrency gate, shutdown coordinator and dead letter, each with "
        "its own test file.",
        "docs/jdlib/capabilities/README.md",
    ),
    (
        "jdlib.control",
        "IMPLEMENTED BUT INTERNAL",
        "The control plane (tenant registry, platform audit, lifecycle) is public API for an "
        "operator, not for a request path; the operations page is its authority.",
        "docs/operations/README.md",
    ),
)


def public_namespaces() -> list[str]:
    """Every package under ``src/jdlib``, whether or not it declares ``__all__``.

    Filtering on ``__all__`` would audit two thirds of the surface and report the rest as absent:
    ``jdlib.tenancy``, ``jdlib.persistence``, ``jdlib.authn``, ``jdlib.authz`` and
    ``jdlib.migrations`` have empty ``__init__.py`` files, and their public API lives in their
    submodules. Those packages are audited here too, and the *surface* column says which kind each
    one is.
    """

    found = ["jdlib"]
    for module in pkgutil.walk_packages([str(SRC)], prefix="jdlib."):
        if module.ispkg:
            found.append(module.name)
    return sorted(set(found))


def surface_of(namespace: str) -> str:
    """What the namespace exports, and where the exports are declared.

    `__all__` at the package level is a declared surface. A package without one is not empty - its
    API is per-module - so the submodules that carry `__all__` are counted instead of guessed at.
    """

    try:
        imported = importlib.import_module(namespace)
    except Exception:  # a namespace whose optional extra is missing is still a namespace
        return "not importable here"
    declared = getattr(imported, "__all__", None)
    if declared:
        return f"`__all__` ({len(declared)})"
    package_dir = SRC.joinpath(*namespace.split(".")[1:])
    modules = []
    for path in sorted(package_dir.glob("*.py")):
        if path.stem == "__init__":
            continue
        try:
            module = importlib.import_module(f"{namespace}.{path.stem}")
        except Exception:
            modules.append(path.stem)
            continue
        if getattr(module, "__all__", None):
            modules.append(f"{path.stem} ({len(module.__all__)})")
    if modules:
        return "per-module: " + ", ".join(modules)
    return "no declared exports"


def documented_pages() -> dict[str, list[str]]:
    """Which pages mention each namespace, and whether the two page kinds exist."""

    pages = {
        path.relative_to(DOCS).as_posix(): path.read_text(encoding="utf-8")
        for path in DOCS.rglob("*.md")
    }
    return pages


def test_files_for(namespace: str) -> list[str]:
    """The test files that exercise the namespace.

    The pattern is the full dotted namespace, not its last component: a submodule import is evidence
    for its parent (`jdlib.integrations.mcp.server` counts for `jdlib.integrations.mcp`), and
    matching only the last component misses every nested namespace - which is how an audit reports
    "no tests" for a surface that has nine test files.
    """

    pattern = re.compile(rf"\b{re.escape(namespace)}\b")
    hits = []
    for path in sorted((ROOT / "tests").rglob("*.py")):
        if pattern.search(path.read_text(encoding="utf-8")):
            hits.append(path.relative_to(ROOT).as_posix())
    return hits


#: Namespaces that are documented under a page named after the *capability* rather than the package.
#: Without this, a mechanical audit reports "PARTIALLY DOCUMENTED" for a surface that has three
#: pages and sixty test files, and a false gap is worse than no audit: it sends someone to write a
#: page that already exists.
PAGE_ALIASES: dict[str, tuple[str, ...]] = {
    "jdlib.data": ("docs/jdlib/capabilities/connectors.md", "docs/jdlib/features/connectors.md"),
    "jdlib.security": ("docs/jdlib/security-model.md", "docs/security/security-core.md"),
    "jdlib.security.authn": ("docs/security/authentication-hardening.md",),
    "jdlib.security.authz": ("docs/security/authorization-hardening.md",),
    "jdlib.security.audit": ("docs/security/audit-hardening.md",),
    "jdlib.security.compliance": ("docs/compliance/README.md",),
    "jdlib.security.gateway": ("docs/security/gateway-hardening.md",),
    "jdlib.tenancy": ("docs/jdlib/tenancy.md", "docs/jdlib/features/tenancy.md"),
    "jdlib.authn": ("docs/jdlib/authentication.md", "docs/jdlib/features/authentication.md"),
    "jdlib.authz": ("docs/jdlib/authorization.md", "docs/jdlib/features/authorization.md"),
    "jdlib.persistence": (
        "docs/jdlib/03-isolation-invariants.md",
        "docs/jdlib/06-strategy-matrix.md",
    ),
    "jdlib.persistence.strategies": (
        "docs/jdlib/06-strategy-matrix.md",
        "docs/jdlib/03-isolation-invariants.md",
    ),
    "jdlib.migrations": ("docs/jdlib/production-readiness.md",),
    "jdlib.integrations": ("docs/jdlib/architecture.md",),
    "jdlib.resources": (
        "docs/jdlib/capabilities/resources.md",
        "docs/jdlib/features/resource-management.md",
    ),
    "jdlib.query": ("docs/jdlib/capabilities/query.md", "docs/jdlib/features/query-system.md"),
}

#: The pages that document the root namespace itself - the public surface (configuration, the
#: context types, `current_tenant()`, the error model) rather than one mechanism.
ROOT_SURFACE_PAGES = (
    "docs/jdlib/architecture.md",
    "docs/getting-started/configuration.md",
    "docs/jdlib/security-model.md",
)


def classify(namespace: str, pages: dict[str, list[str]]) -> tuple[str, str]:
    short = namespace.split(".")[-1] if namespace != "jdlib" else ""
    capability = (DOCS / "jdlib" / "capabilities" / f"{short}.md").exists() if short else True
    guide = (DOCS / "jdlib" / "features" / f"{short}.md").exists() if short else True
    pattern = re.compile(rf"\b{re.escape(namespace)}\b")
    mentions = [name for name, text in pages.items() if pattern.search(text)]
    tests = test_files_for(namespace)
    aliases = PAGE_ALIASES.get(namespace, ())
    if (capability or guide or aliases) and tests:
        kind = "DOCUMENTED"
    elif mentions:
        kind = "PARTIALLY DOCUMENTED"
    else:
        kind = "UNDOCUMENTED"
    where = []
    if short and capability:
        where.append(f"`docs/jdlib/capabilities/{short}.md`")
    if short and guide:
        where.append(f"`docs/jdlib/features/{short}.md`")
    if not where:
        fallback = ROOT_SURFACE_PAGES if not short else (aliases or mentions[:3])
        where = [f"`{name}`" for name in fallback] or ["—"]
    return kind, ", ".join(where)


def page_text() -> str:
    pages = documented_pages()
    namespaces = public_namespaces()
    counts = {"DOCUMENTED": 0, "PARTIALLY DOCUMENTED": 0, "UNDOCUMENTED": 0}
    rows = []
    for namespace in namespaces:
        kind, where = classify(namespace, pages)
        counts[kind] = counts.get(kind, 0) + 1
        tests = len(test_files_for(namespace))
        rows.append((namespace, surface_of(namespace), kind, where, tests))

    out = [
        "# Documentation inventory",
        "",
        "The audit the documentation directive asks for before anything is written: every public",
        "namespace, whether it is documented, where the evidence is, and how many test files hold "
        "it.",
        "",
        "**Generated** by `scripts/docs-inventory.py` - the counts are read from the tree, so this "
        "page",
        "cannot drift from it. The rows that need judgement (experimental, deferred, internal, "
        "absent)",
        "are in the second table, each with its reason and a citation the documentation test "
        "checks.",
        "",
        "## How a row is classified",
        "",
        "| Classification | The mechanical rule |",
        "|---|---|",
        "| **DOCUMENTED** | a capability page, a feature guide or an alias page exists **and** at "
        "least one test file names the namespace |",
        "| **PARTIALLY DOCUMENTED** | the namespace is mentioned in `docs/` but lacks a capability "
        "page, a feature guide, or a test |",
        "| **UNDOCUMENTED** | nothing under `docs/` mentions it |",
        "",
        "The directive's other classifications - EXPERIMENTAL, DEPRECATED, IMPLEMENTED BUT "
        "INTERNAL,",
        "NOT IMPLEMENTED - are judgements, so they are recorded as judgements in the table below",
        "rather than inferred from a grep.",
        "",
        "## The public surface",
        "",
        "| Namespace | Public surface | Classification | Where it is documented | Test files |",
        "|---|---|---|---|---:|",
    ]
    for namespace, surface, kind, where, tests in rows:
        out.append(f"| `{namespace}` | {surface} | {kind} | {where} | {tests} |")
    out += [
        "",
        f"**{counts['DOCUMENTED']} namespaces are DOCUMENTED, {counts['PARTIALLY DOCUMENTED']} are "
        f"PARTIALLY DOCUMENTED, and {counts['UNDOCUMENTED']} are UNDOCUMENTED** "
        f"(of {len(rows)} public namespaces).",
        "",
        "## The rows that need judgement",
        "",
        "| Namespace | Classification | Why | Evidence |",
        "|---|---|---|---|",
    ]
    for namespace, kind, reason, citation in JUDGEMENT:
        out.append(f"| `{namespace}` | **{kind}** | {reason} | `{citation}` |")
    out += [
        "",
        "## What is deliberately absent",
        "",
        "* **Google Cloud Storage and Azure Blob backends.** No module, no export, and a test that",
        "  asserts their absence: a provider class in the public surface is a claim that it works.",
        "* **A job queue.** `jdlib.tenancy.job_envelope` gives work an authority and a lifetime; "
        "the",
        "  queue, its retries and its dead-letter store are the deployment's.",
        "* **A free-text graph search tool.** The MCP surface exposes the closed vocabulary "
        "instead.",
        "* **SAML, Kerberos and mTLS authentication.** API keys and OIDC are what exists.",
        "* **A second database vendor in the test suite.** The dialect seam exists; PostgreSQL is "
        "what",
        "  is run, and no page claims otherwise.",
        "",
        "## Pages that are archived rather than published",
        "",
        "| Where | What | Why it is not in the portal |",
        "|---|---|---|",
        "| `knowledge_base/` | a source-derived knowledge base written at commit `a30601d` | it "
        "describes an earlier revision; the portal publishes current behaviour |",
        "| `.recon/` | reconnaissance notes from the successor programme | working notes, not "
        "reference material |",
        "| `docs/superpowers/plans/` | the phase plans the programme was executed from | working "
        "documents against earlier revisions; kept in the repository for the audit trail |",
        "",
        "Regenerate with `python scripts/docs-inventory.py`; the documentation test fails when a",
        "page is stale.",
    ]
    return "\n".join(out)


def _first_difference(current: str, generated: str) -> str:
    """Where a stale page differs, so the failure names the line instead of only the fact."""

    old = current.replace("\r\n", "\n").splitlines()
    new = generated.replace("\r\n", "\n").splitlines()
    for number, (was, now) in enumerate(zip(old, new, strict=False), start=1):
        if was != now:
            return (
                f"line {number}:\n"
                f"  on disk:   {was[:120]}\n"
                f"  generated: {now[:120]}"
            )
    if len(old) != len(new):
        longer = old if len(old) > len(new) else new
        label = "on disk" if len(old) > len(new) else "generated"
        extra = abs(len(old) - len(new))
        following = longer[min(len(old), len(new))][:120]
        return f"{label} has {extra} more line(s); next: {following!r}"
    return "the text differs only in line endings"


def main() -> int:
    text = page_text()
    if "--check" in sys.argv[1:]:
        if not TARGET.exists():
            print(f"FAIL: {TARGET.relative_to(ROOT)} does not exist")
            return 1
        on_disk = TARGET.read_text(encoding="utf-8").replace("\r\n", "\n")
        if on_disk != text.replace("\r\n", "\n"):
            print("FAIL: the documentation inventory is stale")
            print("regenerate with: python scripts/docs-inventory.py")
            print(_first_difference(on_disk, text))
            return 1
        print("the documentation inventory matches the tree")
        return 0
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(text, encoding="utf-8")
    print(f"documentation-inventory: {text.count('| `jdlib')} namespaces")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
