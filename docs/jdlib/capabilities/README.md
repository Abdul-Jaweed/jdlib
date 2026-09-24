# Capability pages

One page per capability the successor programme delivered, written after the phase it documents
and checked against the working tree rather than trusted.

| Capability | Namespace | What it answers |
|---|---|---|
| [credentials](credentials.md) | `jdlib.credentials` | How is a secret addressed, versioned and rotated? |
| [caching](caching.md) | `jdlib.caching` | What may be cached, under which key, and what may never be? |
| [resources](resources.md) | `jdlib.resources` | How does a handle become a target, and why can a target not go stale? |
| [connectors](connectors.md) | `jdlib.data` | What does a connector guarantee, and what does its policy do? |
| [query](query.md) | `jdlib.query` | How does a specification become a statement with no text a caller controls? |
| [storage](storage.md) | `jdlib.storage` | Which storage backends exist, and how are keys scoped? |
| [jobs](jobs.md) | `jdlib.tenancy` | What authority does a queued job carry, and when is it re-checked? |

## Every claim above is machine-checked

Each page carries front-matter naming its modules, exports, refusals, test files and test-function
count. `tests/unit/test_successor_docs.py` verifies all of it - that the named modules and test
files exist, that the exports resolve, that each refusal is a real attribute of the module
declared to define it, and that the stated test-function count matches the files:

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_successor_docs.py -q
```

Counts are test **functions**, not parametrized cases, and the pages say so; a function count is a
deterministic property of a file, whereas a case count depends on how the suite was invoked.

## Related documentation

- `docs/jdlib/production-readiness.md` - the certification answers, each with the command behind it.
- `docs/jdlib/successor/` - Phase 0's design record: current state, capability matrix, target
  architecture, naming decisions, adoption decisions, the reliability inventory and the roadmap
  with per-phase status.
- `docs/jdlib/02-relational-schema.md` … `07-implementation-design.md` - the pre-existing design
  documents, which these pages do not duplicate.
