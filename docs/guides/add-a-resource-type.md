# Add a resource type

A resource type says what a thing is, how it is scoped, and how a reference to it resolves. It is what
lets an authorization question name *which* invoice, rather than "invoices in general".

## 1. Register the type

```python
from jdlib.authz.resource_types import ResourceTypeRegistry

registry = ResourceTypeRegistry()
registry.register(
    "invoice",
    scope=...,          # how a reference is scoped: the tenant, an owner, a hierarchy
    resolver=...,       # how an identifier becomes a resource the engine can reason about
)
```

## 2. Resolve a reference

The resolver turns a reference from a request into the resource the decision is about. Two rules:

* a reference that crosses the tenant boundary is a **refusal** (`409 INVALID_REFERENCE`), not an
  empty result — an empty result would confirm that the identifier exists elsewhere;
* a reference that does not resolve is a refusal too: an authorization question about a resource that
  does not exist is not a question the engine should be asked.

## 3. Use it in a declaration

```python
@require("invoice:read", resource="invoice")
```

The guard resolves the reference and asks the engine about the resolved resource, so the decision is
about the object the caller named rather than about the class of objects.

## 4. Test it

| Test | What it proves |
|---|---|
| a reference in the caller's tenant | resolves, and the decision is about that object |
| a reference in another tenant | `409`, and no data is returned |
| a reference that does not exist | a refusal, not a 500 and not an empty page |

## What goes wrong

| Symptom | The cause |
|---|---|
| a cross-tenant read returns nothing instead of refusing | the resolver filters by tenant instead of asserting it |
| the engine is asked about "invoice" rather than this invoice | the resource type is registered but the declaration does not name it |
| a stale reference grants access to a re-created object | the resolver keys on a mutable attribute rather than the identity |
