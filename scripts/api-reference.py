#!/usr/bin/env python
"""Generate the public API reference from the source, and check it against it.

The reference is generated rather than written for the same reason the feature matrix is: a
hand-written table of signatures is wrong the first time someone adds an argument. This walks the
public namespaces, reads each exported name's own docstring, and writes one page - and `--check`
fails when the page on disk no longer matches the tree.

    python scripts/api-reference.py            # write docs/reference/public-api.md
    python scripts/api-reference.py --check    # fail if the page is stale (the gate runs this)
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "jdlib"
DOCS = ROOT / "docs"
PAGE = DOCS / "reference" / "public-api.md"

#: Namespaces that are public but whose surface is per-module: their ``__init__`` declares nothing,
#: so the reference lists the submodules that do.
PER_MODULE_PACKAGES = (
    "jdlib.authn",
    "jdlib.authz",
    "jdlib.integrations",
    "jdlib.migrations",
    "jdlib.persistence",
    "jdlib.persistence.strategies",
    "jdlib.tenancy",
)


def namespaces() -> list[str]:
    """Every package under ``src/jdlib``, in a stable order."""

    found = ["jdlib"]
    for module in pkgutil.walk_packages([str(SRC)], prefix="jdlib."):
        if module.ispkg:
            found.append(module.name)
    return sorted(set(found))


def exported(namespace: str) -> list[tuple[str, Any]]:
    """The names a namespace exports: its own ``__all__``, or its submodules'."""

    module = importlib.import_module(namespace)
    names = list(getattr(module, "__all__", ()) or ())
    if names:
        return [(name, getattr(module, name)) for name in names if hasattr(module, name)]

    package_dir = SRC.joinpath(*namespace.split(".")[1:])
    pairs: list[tuple[str, Any]] = []
    for path in sorted(package_dir.glob("*.py")):
        if path.stem == "__init__":
            continue
        try:
            submodule = importlib.import_module(f"{namespace}.{path.stem}")
        except Exception:  # an optional extra that is not installed
            continue
        for name in getattr(submodule, "__all__", ()) or ():
            if hasattr(submodule, name):
                pairs.append((f"{path.stem}.{name}", getattr(submodule, name)))
    return pairs


def signature_of(obj: Any) -> str:
    """A one-line signature, or an empty string for something that is not callable."""

    if inspect.isclass(obj):
        try:
            rendered = f"{obj.__name__}{inspect.signature(obj.__init__)}"
            return rendered.replace("(self, ", "(").replace("(self)", "()")
        except (TypeError, ValueError):
            return obj.__name__
    if callable(obj):
        try:
            return f"{getattr(obj, '__name__', 'callable')}{inspect.signature(obj)}"
        except (TypeError, ValueError):
            return getattr(obj, "__name__", "callable")
    return ""


def summary_of(obj: Any) -> str:
    """The first line of the object's *own* docstring, or a dash.

    `inspect.getdoc` is deliberately not used: it walks the MRO, so a class with no docstring of its
    own inherits its base's, and a reference that credits a class with `Exception`'s summary is
    telling the reader something untrue.
    """

    text = obj.__doc__ or ""
    first = text.strip().splitlines()[0].strip() if text.strip() else ""
    return first.replace("|", "\\|") or "—"


def pages_for(namespace: str) -> str:
    """The portal pages that document a namespace, by the naming rule the inventory uses."""

    short = namespace.split(".")[-1]
    candidates = [
        f"../jdlib/capabilities/{short}.md",
        f"../jdlib/features/{short}.md",
    ]
    def documented(candidate: str) -> bool:
        return (DOCS / "jdlib" / Path(candidate).parent.name / f"{short}.md").exists()

    found = [candidate for candidate in candidates if documented(candidate)]
    return ", ".join(f"[{Path(p).stem}]({p})" for p in found)


def page_text() -> str:
    out = [
        "# Public API reference",
        "",
        "**Generated** by `scripts/api-reference.py` from the source at this commit: the names",
        "each namespace exports, their signatures, and the first line of their own docstring.",
        "The gate runs `--check`, so a page that no longer matches the tree fails the build",
        "rather than mislead a reader.",
        "",
        "The library's public surface is declared, not implied. `jdlib.__all__` and the",
        "subpackages' `__all__` are the declaration; the packages listed as *per-module* have",
        "no package-level `__all__` and their surface is the submodules' exports. The",
        "[documentation inventory](../development/documentation-inventory.md) audits the same",
        "surface per namespace, with the test files that hold it.",
        "",
    ]
    for namespace in namespaces():
        pairs = exported(namespace)
        if not pairs:
            continue
        per_module = namespace in PER_MODULE_PACKAGES
        kind = "per-module surface" if per_module else f"`__all__` ({len(pairs)} names)"
        docs = pages_for(namespace)
        out += [
            f"## `{namespace}`",
            "",
            f"{kind}" + (f" · documented in {docs}" if docs else ""),
            "",
            "| Name | Signature | Summary |",
            "|---|---|---|",
        ]
        for name, obj in pairs:
            signature = signature_of(obj)
            out.append(f"| `{name}` | `{signature}` | {summary_of(obj)} |" if signature
                       else f"| `{name}` | | {summary_of(obj)} |")
        out.append("")
    out += [
        "## Regenerating",
        "",
        "```bash",
        "python scripts/api-reference.py            # write the page",
        "python scripts/api-reference.py --check    # fail when it is stale",
        "```",
        "",
    ]
    return "\n".join(out)


def main() -> int:
    text = page_text()
    if "--check" in sys.argv:
        current = PAGE.read_text(encoding="utf-8") if PAGE.exists() else ""
        if current.replace("\r\n", "\n") != text.replace("\r\n", "\n"):
            print("FAIL: docs/reference/public-api.md is stale")
            print("regenerate with: python scripts/api-reference.py")
            return 1
        print("the public API reference matches the tree")
        return 0
    PAGE.parent.mkdir(parents=True, exist_ok=True)
    PAGE.write_text(text, encoding="utf-8")
    print(f"api-reference: {len(namespaces())} namespaces -> {PAGE.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
