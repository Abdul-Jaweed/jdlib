# Add an MCP tool

An MCP tool is an entry point like a route: same credential, same tenant rule, same policy decision,
same audit vocabulary. The differences are the transport and the shape of a refusal.

## 1. Declare the input model

```python
from pydantic import BaseModel


class InvoiceQuery(BaseModel):
    """The arguments a caller may send. The schema is the contract, not a hint."""

    status: str
```

The model is what the surface *advertises* and what the library *enforces*. The enterprise example
asserts the two are the same, because an advertised schema that is not enforced is a promise the
surface does not keep.

## 2. Declare the permission

```python
@tool(permission="invoice:read")
async def list_invoices(query: InvoiceQuery, ctx=...) -> ...:
    ...
```

The PEP runs before the body. A denied call is an MCP result, not an exception the client cannot
read.

## 3. Bind the tenant from the context

The tool body reads the tenant from the bound context, exactly as a route does. A tool that takes a
tenant argument has created a second source for it, and the tenant-isolation suite will say so.

## 4. Test it

| Test | What it proves |
|---|---|
| the advertised schema equals the enforced one | a client can trust the tool's description |
| a denied call | the body did not run, and the audit trail has the call, the decision and the outcome |
| an argument that does not match the schema | a refusal, not a traceback |
| an unregistered resource URI | a refusal, not a crash |

The MCP denial writes **three** audit events where the HTTP path writes one. That is a real
difference, and it is asserted rather than smoothed over, because it changes what an incident can
reconstruct.

## What goes wrong

| Symptom | The cause |
|---|---|
| a tool is callable without a decision | no `permission=` on the tool |
| the schema in `list_tools` differs from what is enforced | the input model is not the one the invocation validates against |
| a denial is invisible in the audit trail | the boundary is not wired to the audit sink |
