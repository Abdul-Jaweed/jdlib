---
guide: aws
authority: docs/jdlib/aws/aws-capability-matrix.md
modules: []
---

# AWS research sources

> **What this page is.** The directive's section 45 requirement: the official documentation this
> programme actually read, so a reader can check any claim on any AWS page in this section rather
> than trusting the summary. Every page below was fetched and read; where a claim rests on an AWS
> *integration pattern* rather than a documented service guarantee, the page says so.

## Authentication and authorization

* Cognito: [verifying a JWT](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html),
  [access token claims](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html),
  [ID token claims](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-id-token.html),
  [token endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html),
  [revocation](https://docs.aws.amazon.com/cognito/latest/developerguide/token-revocation.html),
  [refresh tokens](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-refresh-token.html),
  [user groups](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-user-groups.html),
  [federation endpoints](https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html),
  [authorization with Verified Permissions](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-authorization-with-avp.html).
* Verified Permissions: [what it is](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/what-is-avp.html),
  [policy stores](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policy-stores.html),
  [policies](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policies.html),
  [schema](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/schema.html),
  [authorization](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/authorization.html),
  [quotas](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/quotas.html),
  [identity sources](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/identity-sources.html),
  [Cognito identity source](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/identity-sources-cognito.html),
  [mapping token claims to the schema](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/cognito-map-token-to-schema.html),
  [token validation](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/cognito-validation.html).
* Cedar: [authorization semantics](https://docs.cedarpolicy.com/auth/authorization.html),
  [policy syntax](https://docs.cedarpolicy.com/policies/syntax-policy.html),
  [schema](https://docs.cedarpolicy.com/schema/schema.html).
* Cerbos (the provider the adapter must not pretend to be): [resource policies](https://docs.cerbos.dev/cerbos/latest/policies/resource_policies.html),
  [derived roles](https://docs.cerbos.dev/cerbos/latest/policies/derived_roles.html),
  [conditions](https://docs.cerbos.dev/cerbos/latest/policies/conditions.html),
  [evaluation](https://docs.cerbos.dev/cerbos/latest/policies/evaluation.html).

## Edge, secrets and configuration

* API Gateway: [REST vs HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-vs-rest.html),
  [JWT authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html),
  [Cognito authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-integrate-with-cognito.html),
  [IAM authorization](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html),
  [Lambda authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html),
  [request validation](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html),
  [throttling](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html),
  [WAF](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html),
  [private APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-private-apis.html).
* Secrets Manager: [what's in a secret](https://docs.aws.amazon.com/secretsmanager/latest/userguide/whats-in-a-secret.html),
  [rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda.html),
  [rotation strategies](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotation-strategy.html),
  [encryption](https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html),
  [limits](https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html).
* Parameter Store: [parameters](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html),
  [advanced parameters](https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-advanced-parameters.html),
  [SecureString](https://docs.aws.amazon.com/systems-manager/latest/userguide/secure-string-parameter-kms-encryption.html),
  [throughput](https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-throughput.html).

## Data planes

* RDS and Aurora PostgreSQL: [IAM database authentication](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html),
  [SSL/TLS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html),
  [RDS Proxy](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.html),
  [Aurora endpoints](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Overview.Endpoints.html),
  [multi-AZ failover](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.Failover.html),
  [credentials in Secrets Manager](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.html).
* Neptune: [openCypher over Bolt](https://docs.aws.amazon.com/neptune/latest/userguide/access-graph-opencypher-bolt.html),
  [openCypher compliance](https://docs.aws.amazon.com/neptune/latest/userguide/feature-opencypher-compliance.html),
  [Neo4j migration compatibility](https://docs.aws.amazon.com/neptune/latest/userguide/migration-compatibility.html),
  [transactions](https://docs.aws.amazon.com/neptune/latest/userguide/transactions-neptune.html),
  [IAM authentication](https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html),
  [limits](https://docs.aws.amazon.com/neptune/latest/userguide/limits.html),
  [multi-tenancy guidance](https://docs.aws.amazon.com/prescriptive-guidance/latest/multi-tenancy-amazon-neptune/introduction.html),
  [Analytics vs Database](https://docs.aws.amazon.com/neptune-analytics/latest/userguide/neptune-analytics-vs-neptune-database.html).
* ElastiCache: [engines](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/SelectEngine.html),
  [replication and cluster mode](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Replication.html),
  [in-transit encryption](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/in-transit-encryption.html),
  [IAM authentication](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/auth-iam.html).
* S3: [using buckets and prefixes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-prefixes.html),
  [bucket policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html),
  [encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html),
  [presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html),
  [security best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html).

## Operations, observability and MCP

* CloudWatch: [logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html),
  [embedded metric format](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format.html),
  [OpenTelemetry metrics](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/metrics-otel-overview.html),
  [Transaction Search](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Transaction-Search.html).
* X-Ray: [concepts](https://docs.aws.amazon.com/xray/latest/devguide/xray-concepts.html),
  [AWS Distro for OpenTelemetry](https://docs.aws.amazon.com/xray/latest/devguide/xray-services-adot.html).
* CloudTrail: [management events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html),
  [data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html).
* Messaging: [SQS queue types](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-queue-types.html),
  [visibility timeout](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html),
  [dead-letter queues](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html),
  [EventBridge retries and DLQs](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-retry-policy.html),
  [SNS/SQS/EventBridge decision guide](https://docs.aws.amazon.com/decision-guides/latest/decision-guides/sns-or-sqs-or-eventbridge.html).
* AgentCore: [Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html),
  [inbound auth](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-inbound-auth.html),
  [outbound auth](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-outbound-auth.html),
  [Runtime](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp.html),
  [Identity](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-overview.html),
  [Observability](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability.html).
* The supplied AWS MCP architecture:
  [the PDF](https://d1.awsstatic.com/onedam/marketing-channels/website/aws/en_US/solutions/approved/documents/architecture-diagrams/deploying-model-context-protocol-servers-on-aws.pdf),
  [the guidance page](https://docs.aws.amazon.com/solutions/deploying-model-context-protocol-servers-on-aws/),
  [MCP servers on ECS](https://aws.amazon.com/blogs/containers/deploying-model-context-protocol-mcp-servers-on-amazon-ecs/),
  [AgentCore general availability](https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available).

## Service guarantees versus integration patterns

Read this page with that distinction in mind:

* **Documented service behaviour**: Cognito's token issuance and the verification steps AWS tells
  applications to perform; Verified Permissions' decision semantics, quotas and Cedar evaluation
  rules; the limits, protocols and authentication mechanisms of the data services; AgentCore's
  inbound and outbound authorization modes.
* **Documented integration patterns, not guarantees**: the Cognito-to-Verified-Permissions wiring
  (identity source plus Lambda authorizer, whose default decision cache extends the effective
  lifetime of a token); the AWS MCP reference architecture as a whole, which is guidance rather than
  a service contract; and the RS256-only checks some AWS articles describe, which are patterns built
  on the documented fact that Cognito signs RS256 rather than a published reject-list.
