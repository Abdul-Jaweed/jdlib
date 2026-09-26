# Cognito + Verified Permissions example

Cognito authenticates, Verified Permissions decides, and the library holds the seam between them.

```python
from examples.aws_cognito_avp.composition import build_cognito_avp_stack, http_status_for

stack = build_cognito_avp_stack(
    cognito=CognitoConfig(issuer=COGNITO_ISSUER, audience=APP_CLIENT_ID),
    avp=VerifiedPermissionsConfig(policy_store_id=POLICY_STORE_ID, region=REGION),
    fetch=jwks_fetcher,          # a real HTTPS fetcher in a deployment
    transport=avp_transport,     # SigV4-signed in a deployment
)

decision = await stack.authorize(
    bearer_token,
    tenant_id=tenant_id,
    resource_kind="Document",
    resource_id=document_id,
    actions=("Document:read",),
)
return http_status_for(decision)   # 200 allowed, 403 denied, 503 undecided
```

## What it demonstrates

* **The chain, with no new abstraction.** A token is validated by the Cognito adapter, the validated
  subject becomes the principal, group membership becomes roles, and the neutral query goes to
  Verified Permissions through the same `PolicyDecisionPoint` protocol Cerbos implements.
* **`cognito:groups` → roles.** Cedar has no role construct, so groups travel as a principal
  attribute and the policy store's schema decides what they mean. The claim is read only *after* the
  token has been validated — reading it earlier is how a caller ends up trusting a group the user
  does not belong to.
* **403 versus 503.** A denied decision and a decision that could not be taken are different answers,
  and an operator needs to see the difference. `AuthorizationPEP.require` raises
  `PermissionDenied` or `AuthorizationUnavailable` inside a request; `http_status_for` is the same
  mapping for callers that render their own refusals.

## Running it

```bash
pip install "jdlib[auth]"
pytest examples/aws_cognito_avp -q
```

The tests need no AWS account: they generate an RSA key pair locally and inject the AVP transport.
Pointing this at a real user pool and a real policy store is a configuration change — supply a real
JWKS fetcher and a SigV4 transport — and that live path is **not run** in this repository, because
there are no AWS credentials here. The example says so rather than implying it was tested against
AWS.
