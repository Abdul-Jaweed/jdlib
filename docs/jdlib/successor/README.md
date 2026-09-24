# JDLib successor programme — Phase 0

Phase 0 (Successor Architecture) is the gate this programme's directive places before any
implementation: a capability inventory, a gap analysis, an adoption matrix, a target architecture,
a public naming model and a roadmap, each committed before code is written.

**Status: COMPLETE, committed.** Implementation phases (roadmap §1 onward) have not begun.

## The documents

| # | Document | What it decides |
|---|---|---|
| 00 | [current-state.md](00-current-state.md) | JDLib's verified baseline at `15a7058`: structure, public surface, the 34 ports, test counts, the pinned-surface constraint, and the limitations carried forward |
| 01 | [capability-matrix.md](01-capability-matrix.md) | every capability classified once — KEEP 37, ADOPT 33, IMPROVE 11, REDESIGN 5, DEFER 17, REJECT 13 |
| 02 | [target-architecture.md](02-target-architecture.md) | five new subpackages attached to the existing ports, the enforcement-point rules they must obey, and what does not change |
| 03 | [api-naming.md](03-api-naming.md) | the directive's proposed names reconciled against JDLib's existing vocabulary; 4 rejected in favour of existing types |
| 04 | [adoption-decisions.md](04-adoption-decisions.md) | fifteen ADRs, including two conflicts between the directive and the approved design documents |
| 05 | [roadmap.md](05-roadmap.md) | dependency-ordered phases with per-phase gates, a risk register, and the open product questions |

## Gate check (§9 of the directive)

| Condition | Evidence |
|---|---|
| Every capability has a classification | `01-capability-matrix.md` — 116 classified rows covering all thirteen capability areas; the per-capability record (133 capabilities, with implementation states and file:line) is the reconnaissance file, kept untracked because it names the archived library |
| Every new subsystem has an owner boundary | `02-target-architecture.md` §2 and §4 — layer, responsibility, and the authority rule per component |
| No duplicate JDLib responsibility is introduced | `03-api-naming.md` §2 — four proposed names rejected in favour of existing types (`PrivilegeContext`, `SecurityContext`, `SecretProvider`, `ResourceTypeRegistry`) |
| Public API names are defined | `03-api-naming.md` §2–§4 — new namespaces, new names, error taxonomy membership |
| Security boundaries are explicit | `02-target-architecture.md` §4 — two enforcement points, unchanged; every new component's relationship to authority stated |

## Publication rule honoured

This programme's directive forbids naming the archived library in JDLib's implementation,
documentation, examples, docstrings, diagrams, package API or tests. Nothing under `docs/` names it:
these documents discuss capabilities generically and cite them to the untracked reconnaissance file.
Verify with:

```
grep -rin "<archived-library-name>" docs/ src/ tests/   # expected: no output
```

## Self-evaluation

- **What could bypass the stated controls?** Nothing yet — Phase 0 writes no code. The controls
  this document set constrains are the *later* phases', and the binding ones (ADR-1, ADR-2, ADR-3)
  each name the test that makes them load-bearing.
- **What assumption was introduced?** That the directive's phase *names* can keep their numbering
  while executing in dependency order (§2 credentials before §4 hydration). Stated openly in
  `05-roadmap.md` rather than hidden in the ordering.
- **Which documentation is now stale?** None authored here, but two pre-existing gaps are recorded
  rather than fixed: JDLib has no coverage measurement, and the phase documents under
  `docs/security/` state counts measured at older revisions. Both are named in
  `00-current-state.md` §8 and scheduled in `05-roadmap.md` §1.
