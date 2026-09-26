---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# MCP on AWS: validating the reference architecture against what the library already does

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md),
> [the research sources](research-sources.md), and the library's own
> [MCP integration](../../integrations/mcp.md) page. Directive sections 21 and 22.

## What the library already has

`jdlib.integrations.mcp` exposes the same chain to a model-facing client as it does to HTTP routes —
tools and resources instead of routes, with the same authentication, the same tenant rule, the same
policy decision and the same audit vocabulary. `McpSecurityBoundary` establishes the credential,
context and tenant for a call; `invocation` runs the tool body behind the PEP, inside both the
security context and the tenant context; a refused call writes three audit events (call, decision,
outcome) where the HTTP path writes one, so an MCP denial is reconstructable from the audit plane
alone.

That matters for this page because the AWS reference architecture for MCP servers spends much of its
diagram on an "auth service" — and the question worth asking is which parts of it are a *library*
concern and which are deployment infrastructure.

## The reference architecture, part by part

The supplied AWS architecture (MCP servers on ECS, an ALB, Cognito, a DynamoDB-backed token/session
store, API Gateway, WAF, CloudFront) is **documented guidance, not a service contract**. Read as
guidance, it decomposes cleanly:

| Part of the architecture | Where it belongs for a JDLib deployment |
| --- | --- |
| Cognito as the identity provider | [the Cognito adapter](authentication-cognito.md) — the library validates the tokens itself |
| The "auth service" that validates tokens and manages sessions | **split**: token validation is the library's (`McpSecurityBoundary` plus the JWT validator); session and token *storage* is a deployment concern the library does not implement |
| DynamoDB for session/token state | deployment infrastructure — the library holds no session store and should not: an MCP server that scales horizontally wants its session state outside the process, and that is a choice about which store, not a library feature |
| API Gateway and WAF in front | [the edge](api-gateway.md) — a fast reject, never the decision |
| ALB in front of the MCP servers | load balancing; note that streamable HTTP and long-lived streams interact with idle timeouts, which is an infrastructure tuning problem |
| CloudFront | TLS termination and caching at the edge; caching must not apply to authenticated MCP responses |
| ECS/Fargate for the servers | deployment, with the caveats below |

## FastMCP on AWS: what actually needs attention

* **Transport.** MCP over streamable HTTP behind an ALB or API Gateway means long-lived responses.
  Idle timeouts on both the load balancer and the API integration must be raised to match, or
  sessions die mid-stream — and the symptom looks like an application bug.
* **Statelessness.** A horizontally scaled MCP server cannot keep per-connection state in memory if
  any instance may serve the next request. The library's boundary is per-request by design, which
  helps; anything a deployment adds on top must be too.
* **Token validation is the server's job.** The MCP authorization model forbids accepting a token
  that was not issued for this server (see [the MCP authorization page](mcp-authorization.md)), so an
  MCP server behind a gateway that already checked the token must still check it — the audience
  check is the point, and it is exactly what the [Cognito adapter](authentication-cognito.md) does.
* **Payload limits.** API Gateway's 10 MB limit and Lambda's response limits interact badly with
  tool results that return large documents; the library's tools return scoped, paginated results,
  which is the right shape for this reason among others.
* **Cold starts and timeouts.** A tool that runs a graph query can exceed a synchronous integration
  timeout; long work belongs behind a queue, and the library's tools are deliberately bounded.

## What the architecture does not change

Nothing about the library's model. A tool call still authenticates, still resolves a tenant, still
runs the frozen gate order, still asks the policy decision point, and still audits. The AWS services
in the diagram decide how the server is reached and how its sessions are stored — not what a caller
may do once reached.

## Testing

The library's MCP surface is exercised by its own tests and by the enterprise example. A live
AgentCore or ECS deployment is `NOT RUN — AWS credentials unavailable`, and this page does not claim
otherwise.
