"""The Cognito + Verified Permissions example (AWS directive §8).

Cognito authenticates and Verified Permissions decides, with the library in between holding the
seam: a validated token becomes a principal, a request becomes a neutral authorization query, and
the answer is a decision the application can act on -- 403 for a denial, 503 for a decision that
could not be taken.

The composition is importable without AWS. `build_cognito_avp_stack` takes a JWKS fetcher and an AVP
transport, which is what makes it testable; a deployment passes a real fetcher and a SigV4 transport
and nothing else changes.
"""
