---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules:
  - examples/aws_cognito_avp/composition.py
exports:
  - build_cognito_avp_stack
  - CognitoAvpStack
  - http_status_for
test_files:
  - examples/aws_cognito_avp/tests/test_composition.py
---

# Example: Cognito authenticates, Verified Permissions decides

> **Design authority:** [the capability matrix](aws-capability-matrix.md),
> [the Cognito page](authentication-cognito.md) and
> [the Verified Permissions page](authorization-verified-permissions.md). Directive section 8.

## What it is

A runnable example at `examples/aws_cognito_avp/` that composes the two adapters into one chain and
shows what an application does with the result. Its tests run in the gate, because this repository's
testpaths include `examples` — a documented example whose tests nothing runs is a claim, not a
demonstration.

## The composition

```python
stack = build_cognito_avp_stack(
    cognito=CognitoConfig(issuer=COGNITO_ISSUER, audience=APP_CLIENT_ID),
    avp=VerifiedPermissionsConfig(policy_store_id=POLICY_STORE_ID, region=REGION),
    fetch=jwks_fetcher,        # HTTPS in a deployment
    transport=avp_transport,   # SigV4-signed in a deployment
)

decision = await stack.authorize(
    bearer_token,
    tenant_id=tenant_id,
    resource_kind="Document",
    resource_id=document_id,
    actions=("Document:read",),
)
http_status_for(decision)      # 200 allowed, 403 denied, 503 undecided
```

No new abstraction, no new protocol: a validated token becomes a principal, a request becomes a
neutral query, and the answer is a decision.

## The three things it gets right, and why they are worth copying

**`cognito:groups` becomes roles, after validation.** Cedar has no role construct, so group
membership travels as a principal attribute and the policy store's schema decides what it means. The
claim is read only after the token has been validated — `roles_from` documents that it must be called
after `authenticate`, because reading a claim from an unverified token is how a caller ends up
trusting a group the user does not belong to.

**403 and 503 are different answers.** A denied decision and a decision that could not be taken mean
different things to an operator, and the example maps them separately. `AuthorizationPEP.require`
does the same by raising `PermissionDenied` or `AuthorizationUnavailable`; `http_status_for` is for
callers that render their own refusals.

**An invalid token never reaches the decision point.** The example's test asserts the AVP transport
was never called when the token fails validation, so "the policy engine was asked" and "the caller
was authenticated" cannot drift apart.

## Running it

```bash
pip install "jdlib[auth]"
pytest examples/aws_cognito_avp -q
```

Five tests, no AWS account: an RSA key pair is generated locally and the AVP transport is injected.
Pointing it at a real user pool and policy store is a configuration change — a real JWKS fetcher and
a SigV4 transport — and that live path is **`NOT RUN — AWS credentials unavailable`**. The example
says so rather than implying it was tested against AWS.
