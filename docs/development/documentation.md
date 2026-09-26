# How this documentation works

This page is the rule the rest of the site follows. It exists because documentation rots in a
predictable way - a second page about the same topic, written from memory, that reads exactly as
convincingly as the true one - and the only durable answer is to say which page is the authority and
to make the build check it.

## One authority per topic

Every topic has exactly one **design authority**: the page that the code and the tests are written
against. Portal pages link to authorities; where a portal page and an authority disagree, the
authority wins, and the portal page says so at the top.

| Authority | Covers |
|---|---|
| `docs/jdlib/0N-*.md` | the approved design documents: relational schema, isolation invariants, authorization model, tenant lifecycle, strategy matrix, implementation design |
| `docs/jdlib/*.md` | per-area reference: architecture, authentication, authorization, tenancy, privileged access, resource management, query system, credentials, connectors, security model, production readiness |
| `docs/jdlib/features/*.md` | one developer guide per feature, in a fixed template |
| `docs/jdlib/capabilities/*.md` | one page per delivered capability, with machine-read front-matter checked by `tests/unit/test_successor_docs.py` |
| `docs/jdlib/architecture/*.md` | the flows: security, tenancy, graph, MCP, observability, and the example application's architecture |
| `docs/jdlib/examples/*.md` | the two runnable applications, their matrices, and the security review |
| `docs/security/*.md` | the hardening programme, one document per phase, plus the adversarial review and the CI gates |
| `docs/threat-model/`, `docs/compliance/` | the threat model and the technical-control register, with its own gaps |
| `docs/operations/` | the operational entry point: readiness, skips, evidence, and the operator's own job |
| `docs/jdlib/successor/` | the programme's own record: capability matrix, target architecture, adoption decisions, roadmap, per-phase status |

The portal adds **entry points** - getting started, concepts, architecture, integrations, guides,
reliability, observability, operations, reference and development pages - and each of those either
*is* the authority for its topic (when nothing else covers it) or routes to the one that is.

## What is published, and what is not

| Where | Published? | Why |
|---|---|---|
| `docs/**` | yes, except the exclusions below | it is the reference surface |
| `docs/superpowers/plans/` | **no** - `exclude_docs` | the phase plans the programme was executed from: working documents written against earlier revisions, kept in the repository for the audit trail |
| `knowledge_base/` | **no** - outside `docs/` | a source-derived knowledge base written at commit `a30601d`; it describes an earlier revision, and the portal publishes current behaviour |
| `.recon/` | **no** - outside `docs/` | reconnaissance notes from the successor programme |
| `../../architecture/long-form-reference.md` | yes, as [`architecture/long-form-reference.md`](../architecture/long-form-reference.md) | it is the long-form technical reference, and it carries a status banner saying which revision it describes |
| `README.md`, `CONTRIBUTING.md`, `SECURITY.md` | linked from the portal, not duplicated | they are the repository's own entry points; the portal links them by URL rather than copying text that would then drift |

The [documentation inventory](documentation-inventory.md) records the same decisions, and the
per-namespace audit that goes with them.

## The rules a page follows

**Style.** Precise, technically accurate, example-driven, security-aware, operationally useful. No
marketing language, and no vague claims: "JDLib makes your application enterprise-ready" is a
sentence this site does not contain, because it cannot be checked. "A denied call executes nothing,
measured at the row, read as the owner" is the kind of sentence it does - the test is named next to
it.

**Code examples.** Every example uses the current public API. Examples that are illustrative rather
than runnable say so in the first line of the block - `# ILLUSTRATIVE, NOT RUNNABLE` - and a test
asserts that the with-and-without comparison marks every one of its snippets, because unmarked
illustrative code is indistinguishable from recommended code. Where a snippet can be executed, the
page says where it comes from (an example application, a test, or the README's quickstart).

**Diagrams.** Mermaid, and only where a diagram explains something a sentence cannot: a flow, a
state machine, a relationship. The diagram types the renderer supports are listed in
`tests/unit/test_docs_portal.py`, which fails on a fence the site cannot draw. One enormous diagram
that nobody can read is worse than three that each answer one question.

**Claims.** Every page that describes behaviour either cites the test that holds it or says plainly
that it is describing a design rather than an executed fact. The distinction is the point of the
whole site: a reader has to be able to tell "this was run" from "this was written".

## How the site is validated

```bash
# the whole gate, including the documentation build
bash scripts/ci-local.sh

# just the documentation
.venv/Scripts/python.exe -m mkdocs build --strict
.venv/Scripts/python.exe scripts/docs-inventory.py --check
.venv/Scripts/python.exe -m pytest tests/unit/test_docs_portal.py -q
```

`mkdocs build --strict` fails on a broken link, a missing page, a page that is not in the
navigation, and an anchor that does not exist. The test module checks what MkDocs cannot: that every
published page is reachable, that every diagram fence is a type the renderer supports, that the
inventory is regenerated rather than edited, and that the citations the inventory's judgement rows
carry point at files that exist.

The documentation build is part of CI, in the same job as the tests, so a page that breaks the site
breaks the build.

## Writing a page

1. **Check the inventory first.** If the topic has an authority, link it instead of restating it.
2. **Read the source and the tests.** The directive's rule is the site's rule: do not document a
   feature before verifying it exists, and never document a function that is not in `__all__`.
3. **Say what was run.** Name the test file and line, or the command and its output.
4. **Mark what is illustrative.** A snippet that nobody executes is labelled as such.
5. **Build it.** `mkdocs build --strict`, then the test module.
