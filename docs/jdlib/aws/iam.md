---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# The IAM boundary: AWS resources versus application data

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). Classified **INFRASTRUCTURE_ONLY**, and the boundary
> is the point of the page.

## Two authorization systems, one request

An AWS-hosted request passes through two independent authorization systems, and confusing them is
the most common architectural mistake in AWS-native applications:

| | IAM | JDLib |
| --- | --- | --- |
| Authorizes | AWS API calls — S3 objects, Secrets Manager secrets, KMS keys, the policy store itself | application data and actions — this tenant's documents, this user's permission |
| Principal | an AWS identity: role, user, federated session | an application principal: a user, a service, with roles and attributes |
| Policy language | IAM policy JSON | the library's permission model, decided by Cerbos, `DefaultPDP` or [Verified Permissions](authorization-verified-permissions.md) |
| Answers | "may this workload read this secret?" | "may this user read this document?" |

A request usually needs both, in this order: IAM lets the *workload* reach the resources it depends
on, and the application then decides what the *user* may do with the data it fetched.

## The mistake to avoid

**An IAM policy is not a tenant permission model.** It is tempting to give each tenant an IAM role
whose policy restricts it to a prefix or a table, and call that multi-tenancy. It works until the
first cross-tenant feature (a shared document, an admin view, a delegation) needs a decision IAM
cannot express, or until the application needs to deny something the tenant's own role allows. IAM
has no notion of the application's permissions, no derived roles, and no request context beyond what
is in the call.

The library's model is the opposite direction: the workload has broad access to the infrastructure it
owns, and every data access is decided per request by the policy decision point with the tenant in
context.

## Where the two meet, concretely

* **The workload's role** authenticates the application to Secrets Manager, S3, CloudWatch and the
  policy store. No static keys anywhere — the SDK's default credential chain picks the role up.
* **Secrets Manager's own policy** decides which secrets the workload may read; the library's
  `SecretProvider` then decides nothing further. A handle it cannot read is a `KeyError`.
* **Verified Permissions' policy store** is itself an AWS resource: IAM controls who may call
  `IsAuthorized`, and the Cedar policies control what the answer is. Both are needed, and neither
  substitutes for the other.
* **S3 prefixes** are enforced by bucket policy and IAM, which is what turns the library's
  tenant-prefix convention into a control (see [the S3 page](s3.md)).
* **The AWS principal is not the application principal.** When a request arrives signed with SigV4,
  the AWS identity says which workload called, not which user it acted for. The application maps one
  to the other, explicitly.

## Least privilege, honestly

The library cannot enforce IAM policy, and it does not pretend to. What it can do is keep its own
credential surface small: no long-lived AWS keys in configuration (the adapters take injected
clients, and the Verified Permissions config has a `credentials` field that accepts only `None`), no
AWS API calls from core modules, and no secret values in logs or decisions. Least privilege for the
rest is an infrastructure-as-code concern, reviewed where IAM policies are reviewed.
