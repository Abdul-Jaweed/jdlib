---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# Bedrock AgentCore: the gateway authenticates, JDLib decides

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). Directive sections 23 and 24. Classified
> **OPTIONAL**: a deployment choice, and the interesting part is where it leaves the decision.

## What AgentCore is

Four services that matter here:

* **Gateway** — turns existing APIs, Lambda functions and MCP servers into MCP tools with inbound and
  outbound authorization.
* **Runtime** — hosts MCP servers and agents with session isolation.
* **Identity** — workload and agent identities, with credential exchange for outbound calls.
* **Observability** — OpenTelemetry-based telemetry into CloudWatch.

## The finding that matters

AgentCore Gateway's inbound authorization can **authenticate only**: it validates the caller's token
and passes the request through without making an authorization decision. That is precisely where a
JDLib deployment wants the boundary to sit.

```text
client --token--> AgentCore Gateway (inbound auth: validates the token)
                        |  forwards, with the identity
                        v
                   JDLib MCP server (McpSecurityBoundary -> tenant -> PEP -> PDP)
                        |
                        v
                   the actual data plane, tenant-scoped
```

The gateway answers "is this a valid caller?". The library answers "may this caller read this
tenant's document?". Moving the second question into the gateway is not possible — it has no
knowledge of tenants, resources or the permission model — and this programme's rule holds: the
decision point does not move.

## Inbound authorization

| Mode | What it does | What it leaves to the application |
| --- | --- | --- |
| IAM (`AWS_IAM`) | SigV4 authentication of the AWS principal | everything: an AWS identity is a workload, not a user |
| JWT (`CUSTOM_JWT`) | validates the token against a configured issuer | everything, if configured to authenticate only — which is the mode to choose |

Either way, the MCP server behind the gateway still validates the token itself, because the MCP
authorization model requires an audience-bound token issued *for that server* and forbids
passthrough.

## Outbound authorization, and the confused deputy

When a tool calls another service, AgentCore Identity can exchange credentials for the outbound
call — a workload identity acting for an agent. This is a genuine improvement over embedding
credentials in a tool, and it introduces the problem every delegation scheme has: **the confused
deputy**. If a tool acts with its own broad identity, a caller who can invoke the tool may be able to
make it act on resources the caller could never reach.

The library's answer is structural rather than cryptographic: the tenant context is established per
request and every data-plane call is scoped to it, so a tool cannot reach another tenant's data even
if its outbound credential technically could. The outbound credential should still be least-privilege
— defence in depth, not the only defence.

## Identity: agent identity is not user identity

An agent acting on behalf of a user is a delegation chain: user → agent → tool → resource. AgentCore
Identity models the agent end; the library models the user end. A deployment needs to decide, and
document, which principal a given tool call is authorized *as* — the library's principal is whoever
the validated token names, and if that is the agent rather than the user, then the agent's
permissions are what the policy engine sees. That is a design decision with security consequences,
and it belongs in the deployment's documentation, not in a default.

## Observability

AgentCore Observability is OpenTelemetry-based, which is why [the observability page](observability.md)
is the right integration point: the library emits OTLP, the collector or AgentCore consumes it, and
nothing in the core speaks an AWS-specific telemetry API.

## The verdict

**OPTIONAL.** Nothing in the library changes to sit behind AgentCore, and nothing should: the value
of the Gateway here is operational (tool registration, credential exchange, telemetry), not
authorization. A deployment that already runs its own MCP servers behind an ALB gets the same
architecture without it; a deployment that wants managed tool registration gets it without moving the
decision point.
