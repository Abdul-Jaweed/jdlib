"""What bounds a graph call (successor §16; directive §15).

The connector policy established the idiom — a frozen, constructor-validated config handed to an
adapter, with the same field names — and this is that shape for graph calls, so a statement's
deadline is configured where a connector's already is.
"""

from __future__ import annotations

from dataclasses import dataclass

from jdlib.graph.errors import GraphValidationError


@dataclass(frozen=True, slots=True)
class GraphPolicy:
    """The deadline a statement is held to, on both sides.

    Both halves are the same number on purpose: the client stops waiting at the deadline and the
    server is told to stop working at it, so a slow statement is abandoned rather than left
    running behind a caller that has already given up.
    """

    statement_timeout: float = 30.0

    def __post_init__(self) -> None:
        if self.statement_timeout <= 0:
            raise GraphValidationError("statement_timeout must be positive")
