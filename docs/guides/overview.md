# Guides

Task-shaped walkthroughs: one job per page, in the order the work actually happens, with the part
that is easy to get wrong called out where it happens rather than in a footnote.

| Guide | The job |
|---|---|
| [Add a tenant-scoped table](add-a-tenant-scoped-table.md) | a new model, its migration, and the isolation that constrains it |
| [Add an endpoint](add-an-endpoint.md) | a route that declares its permission and uses the tenant-bound unit of work |
| [Add a permission](add-a-permission.md) | a name in the catalog, a rule in your policy, a declaration on the route |
| [Add a resource type](add-a-resource-type.md) | what a resource is, how it is scoped, and how a reference resolves |
| [Add an MCP tool](add-an-mcp-tool.md) | a tool over the same chain, with a schema the library enforces |
| [Add a connector](add-a-connector.md) | a data source behind the connector contract |
| [Add a cache](add-a-cache.md) | a provider behind the cache protocol, with the credential guard intact |
| [Add a migration](add-a-migration.md) | a control-plane or tenant-plane revision, applied by an operator |
| [Test your integration](test-your-integration.md) | the layers, the skips, and a denial measured as non-execution |

## The rule every guide follows

A guide shows the change **and the test that proves it**, because in this library a change without a
test is a claim rather than a control. Where a step is easy to skip — a migration that never runs, a
permission that is declared but not in the policy, a denial test that would pass by refusing
everything — the guide says what goes wrong, not just what to type.
