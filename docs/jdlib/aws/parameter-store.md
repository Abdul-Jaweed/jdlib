---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# Parameter Store: evaluated, and deliberately not adapted

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md).

## What it is

AWS Systems Manager Parameter Store: hierarchical, path-addressed configuration with an optional
`SecureString` type backed by KMS. It overlaps Secrets Manager, and the directive asks for the
distinction to be explicit rather than blurred.

## The verdict: DEFER, and the reason is a missing abstraction

The directive's section 12 is conditional: *if* JDLib has a configuration-provider abstraction,
implement a Parameter Store adapter for it. The interface audit for section 29 found that it does
not. What exists is `TenancyConfig`, a pydantic-settings model that reads environment variables —
a typed configuration object, not a provider protocol with implementations that can be swapped.

Section 29 also forbids the obvious shortcut: **do not create interfaces just to make a capability
matrix look complete.** Adding a `ConfigurationProvider` protocol now would mean designing the
library's configuration story around one AWS service, which is the opposite of what this programme
is for.

So Parameter Store is classified `DEFER` with the reason recorded, not silently dropped and not
implemented as a secret provider by another name.

## Why not just implement it as a `SecretProvider`?

Because that is exactly the blur the directive warns against. A `SecureString` parameter *is*
sensitive, so a `ParameterStoreSecretProvider` would work mechanically — and it would teach every
caller that configuration and secrets are the same thing, at which point plaintext parameters start
travelling through secret-handling code and the distinction is gone. The library has one
`SecretProvider` protocol for material that must not be logged; configuration is not that.

## What would change the verdict

A `ConfigurationProvider` abstraction with a justification of its own — for example if the library
gained layered configuration with runtime reload, where a provider protocol would be the natural
seam and Parameter Store would be one implementation among several (environment, files, a config
service). That is a design decision for the library, not a consequence of being on AWS.

## If a deployment needs it today

Read Parameter Store in the application's composition root and pass the values into
`TenancyConfig`-shaped objects. The library does not need to know where configuration came from, and
today it does not pretend to.

## Limits worth knowing

Standard parameters are free and throttled per account per region; advanced parameters support larger
values and policies but are charged per parameter per month. `SecureString` values are encrypted at
rest with a KMS key and are **not** automatically rotated — Secrets Manager's rotation is the reason
to prefer it for credentials, and that is the distinction this page exists to keep.
