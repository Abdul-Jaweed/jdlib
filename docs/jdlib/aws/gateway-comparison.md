---
guide: aws
authority: docs/security/gateway-hardening.md
modules: []
exports: []
test_files: []
---

# Gateway comparison: Kong, Tyk and API Gateway

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and the library's
> [gateway hardening](../../security/gateway-hardening.md)
> page, which is the authority for the header contract the first two implement.

## The invariant, stated first

A gateway is an **edge control**. It can reject a request before it reaches the application, and it
can inject identity a backend verifies. It does not decide application authorization in any of the
three products, and nothing in this library moves a decision to it.

## The comparison

| | Kong | Tyk | Amazon API Gateway |
| --- | --- | --- | --- |
| JDLib adapter | `KongGatewayAdapter` | `TykGatewayAdapter` | **none, and none is warranted** |
| Identity mechanism | signed identity headers (configurable via `request-transformer` / `pre-function`; `X-Consumer-*` can be used by overriding the header names) | signed identity headers | JWT authorizer (validates, forwards), Lambda authorizer context (plain map), or IAM/SigV4 |
| What the backend verifies | the signature over `subject, tenant, scopes, issued, expires` | the same | the JWT itself, independently |
| Authorization model | plugins, ACLs, consumer groups | policies, quotas, key expiry | authorizer allow/deny, usage plans, WAF rules |
| Rate limiting | yes, rich plugin ecosystem | yes, quota and rate-limit policies | yes, usage plans and per-method throttling |
| Request validation | plugins | schema validation | native request validators |
| WAF | via plugin or upstream | via plugin or upstream | native integration |
| Operational model | self-hosted or Kong Konnect | self-hosted or Tyk Cloud | fully managed |
| Where it fails | plugin sprawl and config drift across environments | policy semantics that look like application permissions but are not | no signed identity envelope; authorizer caching; 29-second REST integration timeout |

## Reading the table honestly

**Kong and Tyk are the same shape.** Both inject identity headers a backend can *verify*, which is
why both have adapters here: the library's contract is the signature, not the product. The
per-product work is header names and defaults, which is what the adapters configure.

**API Gateway is a different shape.** It validates a token at the edge and forwards it; it does not
sign an identity envelope for the backend. So the integration is
[JDLib validating the token itself](api-gateway.md), and a third adapter would be a fiction.

**None of the three is a policy decision point.** Kong ACLs and Tyk policies are coarse gates —
is this consumer allowed to call this route at all — and they do not know what a JDLib tenant is,
which resource is being touched, or what a derived role would mean. The library's own gates run in
the frozen precedence order (principal active, tenant active, membership active, binding validity,
then permission), and no gateway has the information to run them.

**Rate limiting is not authorization.** A quota says how often; it never says whether. A deployment
that relies on a gateway quota to bound data access has confused load control with access control.

## Choosing between them

* Already on AWS, and the API is public: **API Gateway** — managed, WAF and throttling included, and
  the JWT authorizer is a useful fast reject.
* Already running Kong for internal routing: keep it, and configure the identity headers the adapter
  already verifies.
* Need quota and policy management as a product with a portal: **Tyk**.
* Need a policy decision point for application data: **none of them** — that is Cerbos or
  [Verified Permissions](authorization-verified-permissions.md), behind the library's PEP.

## What would change this page

A future API Gateway feature that injects a *verifiable* signed identity envelope would make a third
adapter meaningful. As of the research date, no such contract exists, and this page says so rather
than assuming one.
