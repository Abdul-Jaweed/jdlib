"""What the example's test layers share: the lab, and a chain through the real application.

Three layers ask the same questions of the same infrastructure, so the harness lives here rather
than in whichever file happened to need it first:

* `environment` — where the lab is (read once, at import) and what a test *skips* without.
* `lab` — provisioning: tenants, callers, roles, API keys, and the operator steps the README
  documents.
* `chain` — the application's own composition (`build_collaborators` -> `create_app` and the MCP
  server) with an HTTP client and a tool caller over it.

Nothing here decides anything about security. A helper that authenticated on a test's behalf, or
that built its own enforcer, would make every test below it measure the helper instead of the
library.
"""
