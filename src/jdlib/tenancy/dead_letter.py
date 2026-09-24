"""Dead letters: the jobs this dispatcher decided not to run again, and why.

A retry that gives up silently is indistinguishable from a retry that never happened. This module
is the record: what was left, how many attempts it got, and the *smallest honest* reason - the
dispatcher's own decision and the error's type, never the error's message, because a driver's
message quotes the statement it was given and a handler's message can quote the payload. A job's
payload is not evidence to keep.

Only decisions the dispatcher actually made are recorded. An envelope that fails its signature, a
spent job id, a revoked job: those are refused before any attempt and generate nothing here -
otherwise anything that can put bytes on the queue could fill the store with forged envelopes,
one per request, forever.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True, slots=True)
class DeadLetter:
    """A job that will not run again, in the smallest form that is still honest."""

    job_id: str
    tenant_id: uuid.UUID | None
    attempts: int
    #: Why it stopped: ``permanent`` (its own failure said not to retry), ``exhausted`` (the
    #: attempts ran out), ``budget`` (the shared retry budget was spent), ``refused`` (the
    #: authority was withdrawn, or the lifetime lapsed, between two attempts).
    reason: str
    error_type: str | None
    recorded_at: datetime


class DeadLetterStore(Protocol):
    """Where a deployment keeps them: a table, a queue, the platform's own dead-letter topic."""

    async def record(self, entry: DeadLetter) -> None: ...


class InMemoryDeadLetterStore:
    """The store for a process that has somewhere else to ship them, and for tests."""

    def __init__(self) -> None:
        self._entries: list[DeadLetter] = []

    async def record(self, entry: DeadLetter) -> None:
        self._entries.append(entry)

    def entries(self, *, tenant_id: uuid.UUID | None = None) -> tuple[DeadLetter, ...]:
        """Read them back, optionally under one tenant - the same scoping the data plane uses."""
        if tenant_id is None:
            return tuple(self._entries)
        return tuple(entry for entry in self._entries if entry.tenant_id == tenant_id)

    def __len__(self) -> int:
        return len(self._entries)
