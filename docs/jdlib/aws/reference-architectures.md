---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# Reference architectures

> **Design authority:** [the capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). Directive section 33: the AWS deployment shapes this
> programme validated, drawn so the boundaries are visible rather than described.

## The full deployment

```mermaid
flowchart TB
    subgraph Edge
        CF[CloudFront] --> WAF[WAF]
        WAF --> APIGW[API Gateway<br/>throttling, request validation, JWT authorizer]
    end
    subgraph Compute
        APIGW --> App[ECS/Fargate: JDLib application]
        App --> MCP[MCP server<br/>McpSecurityBoundary]
    end
    subgraph Identity
        Cognito[Cognito user pool] -.->|JWKS| App
        Cognito -.->|JWKS| MCP
        AVP[Verified Permissions<br/>policy store] -->|decision| App
    end
    subgraph Data
        App --> RDS[(RDS/Aurora PostgreSQL)]
        App --> EC[(ElastiCache)]
        App --> S3[(S3)]
        MCP --> Graph[(Neo4j, or Neptune if adopted)]
    end
    subgraph Ops
        SM[Secrets Manager] --> App
        App --> CW[CloudWatch Logs<br/>audit sink]
        App --> OTLP[OTel collector / ADOT] --> CWX[CloudWatch, X-Ray]
        IAM[IAM role] -.->|workload identity| App
    end
```

Read the arrows as trust boundaries: the edge rejects cheaply, the application authenticates and
decides, and no arrow skips the decision point.

## The decision chain for one request

```mermaid
sequenceDiagram
    participant U as Caller
    participant E as Edge (API Gateway)
    participant A as JDLib
    participant P as PDP (Cerbos or AVP)
    participant D as Data plane
    U->>E: request + Bearer token
    E->>E: fast reject (throttle, shape, token sanity)
    E->>A: forwards the request and the token
    A->>A: validate token (issuer, audience, expiry, token_use)
    A->>A: tenant gates in frozen order
    A->>P: permission question
    P-->>A: allow / deny / degraded
    alt allowed
        A->>D: tenant-scoped operation
        D-->>A: result
        A-->>U: 200
    else denied or degraded
        A-->>U: 403, or 503 when the decision could not be taken
    end
    Note over A: audit events for the call, the decision and the outcome
```

## The MCP path

```mermaid
flowchart LR
    Agent[MCP client / agent] --> GW{AgentCore Gateway<br/>authenticate-only}
    GW --> S[JDLib MCP server]
    S --> B[McpSecurityBoundary:<br/>credential, context, tenant]
    B --> PEP[PEP]
    PEP --> PDP[PDP: Cerbos or Verified Permissions]
    PDP --> T[Tool body, tenant-scoped]
    T --> D[(Data plane)]
    S -.->|three audit events| Audit[Audit sink]
```

The gateway authenticates; the library decides. Moving the second step into the gateway is not
possible, because it has no knowledge of tenants, resources or the permission model — which is the
conclusion [the AgentCore page](agentcore.md) reaches from the other direction.

## The tenancy path through the data planes

```mermaid
flowchart TD
    Req[Request] --> Ctx[Tenant context established]
    Ctx --> Gates[Frozen gate order]
    Gates --> Dec[Decision]
    Dec --> RDS2[(PostgreSQL: tenant-scoped rows)]
    Dec --> EC2[(Cache: tenant-scoped keys)]
    Dec --> S32[(S3: tenant-prefixed keys + IAM policy)]
    Dec --> G2[(Graph: client-enforced tenant check)]
```

Each data plane enforces tenancy differently, and the pages say which mechanism each one actually
uses rather than assuming they are equivalent: row scoping and the client's statement check are
enforcement, while an S3 prefix is a convention that IAM turns into a control.
