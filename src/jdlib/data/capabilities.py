from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConnectorCapabilities:
    """What an engine can actually do, declared rather than discovered at first use.

    Kept deliberately small: every flag here is one a caller can branch on, and a capability
    nobody branches on is a claim the registry would then be validating for no one.
    """

    name: str
    reads: bool
    writes: bool
    transactions: bool
    dialect: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("a connector must declare a name")
