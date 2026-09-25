"""What an MCP surface can refuse, in the library's own error taxonomy (directive §24).

One class per outcome the caller or the operator has to tell apart, and every one of them is a
`JdlibError`, so the canonical envelope and the audit trail treat an MCP failure like any other:
a tool definition that cannot be described safely (a programming error, and the one that must fail
loudly at import), an authorization refusal (the caller may not), and an execution failure (the
caller may, and the operation did not).

The classes are additive to the existing taxonomy rather than a parallel one: `jdlib.errors`
already owns the envelope, and the MCP surface maps its failures into it.
"""

from __future__ import annotations

from jdlib.errors import JdlibError


class McpError(JdlibError):
    """Base for every MCP failure."""


class McpToolDefinitionError(McpError):
    """A tool, or a registration, that cannot be described safely.

    Raised while the surface is being assembled — never while a caller waits — so an incomplete
    tool fails at import or startup rather than becoming a request that quietly does nothing.
    """


class McpToolExecutionError(McpError):
    """A tool ran and did not complete.

    The message is this surface's own, never the failure's: §24 keeps stack traces, SQL, Cypher,
    connection strings and internal paths inside, where the log and the trace can see them. The
    original travels as ``__cause__`` for whoever is diagnosing.
    """


class McpResourceDefinitionError(McpError):
    """A resource that cannot be described safely.

    The same gate the tool registry applies, applied to resources: a resource with no declared
    capability is a resource nobody authorized, and it cannot be constructed rather than being
    rejected later by a reviewer.
    """


class McpTimeoutError(McpError):
    """The call exceeded its deadline.

    Deliberately not a `McpToolExecutionError`: the operation may or may not have completed, and
    that difference is the one the graph's `UNCERTAIN` outcome exists to preserve. A caller must
    not read this as "nothing happened, try again".
    """


class McpServerUnavailableError(McpError):
    """The server factory needs the optional `mcp` extra; importing the library does not.

    Raised by the factory rather than at module import, so a deployment that never builds a
    server never needs fastmcp — and the message names the extra to install.
    """


class McpArgumentsRefusedError(McpError):
    """A call the tool's own declaration does not describe.

    The declarations advertise `additionalProperties: false` with no identity and no statement
    slot anywhere. fastmcp 4.0.10 advertises that schema and does not enforce it, so the
    invocation chain enforces it — an advertised contract the library does not keep is a lie
    told to every client, and an undeclared argument that reaches a handler is a slot the
    declaration says does not exist.
    """
