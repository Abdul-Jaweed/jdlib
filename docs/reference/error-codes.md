# Error codes

One envelope, one vocabulary. Every surface — HTTP, MCP, the CLI — answers with the same shape and
the same stable codes, so a client does not need per-surface handling and a dashboard can key on a
code rather than a message.

## The envelope

```json
{
  "error": {
    "code": "AUTHORIZATION_DENIED",
    "message": "the request was refused",
    "request_id": "01J…"
  }
}
```

The `code` is stable; the `message` is not a contract; the `request_id` is what ties the answer to the
audit event, the span and the log line. A 5xx never echoes its own exception text: the detail is in
the evidence, not in the response.

## The codes a client will see

| Code | Status | What it means | What to do |
|---|---|---|---|
| `AUTHENTICATION_REQUIRED` | 401 | no credential was presented | send one |
| `INVALID_TOKEN` | 401 | the credential did not verify | check the audience, the issuer and the clock |
| `EXPIRED_TOKEN` | 401 | the credential was valid and is not | refresh it |
| `PERMISSION_DENIED` / `POLICY_DENIED` | 403 | the decision was deny | this is the policy working |
| `POLICY_UNAVAILABLE` | 403 | the decision was degraded — treated as a refusal | an outage, not a permission problem |
| `TENANT_NOT_FOUND` | 404 | the tenant does not exist | check the slug or the claim |
| `TENANT_SUSPENDED` | 403 | the tenant's lifecycle state refuses the request | the gate working; an operator resolves it |
| `MISSING_TENANT_CONTEXT` | 403 | no tenant could be resolved | check the resolver configuration |
| `CROSS_TENANT_ACCESS` | 409 | a reference pointed outside the tenant | a refusal by design |
| `INVALID_REFERENCE` | 409 | a reference did not resolve inside the boundary | check the identifier |
| `VALIDATION_FAILED` | 422 | the request did not match its schema | fix the request |
| `TOO_MANY_REQUESTS` | 429 | the concurrency gate refused the work | retry with backoff |
| `DEPENDENCY_UNAVAILABLE` | 503 | a dependency could not answer | check `/readyz`, then the dependency |
| `MIGRATION_ERROR` | 500 | a migration step failed | an operator problem, not a request problem |
| `INTERNAL_ERROR` | 500 | something failed that the library does not classify | the request id is how it is traced |

## The full vocabulary

The enum is `jdlib.security.errors.SecurityCode` — 38 members, grouped by the domain they belong to
(authentication, authorization, tenancy, the data boundary, configuration, availability, validation
and the internal cases). The codes above are the ones an external client is expected to handle; the
rest exist so an operator can distinguish causes without parsing a message.

## Why stable codes

* a dashboard can alert on `POLICY_UNAVAILABLE` without matching prose;
* a client can decide whether to retry without guessing from a status alone;
* a postmortem can compare two incidents, because the code means the same thing in both.

## Where the codes are tested

`tests/unit/security/` pins the vocabulary, and the example suites assert the codes for the paths they
exercise — including the cross-tenant case, which is `409 INVALID_REFERENCE` rather than an empty
page.
