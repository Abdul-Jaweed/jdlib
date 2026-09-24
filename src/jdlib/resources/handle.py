from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ResourceHandle:
    """An opaque name for a resource, such as ``db-tenant-acme``.

    Never a DSN and never a credential - the design document is explicit that a handle is a
    name and nothing else. It is validated rather than trusted, because a handle is formatted
    into a cache key and a handle containing the separator would let two entries collide.
    """

    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("a resource handle must not be empty")
        if any(character.isspace() for character in self.value):
            raise ValueError("a resource handle must not contain whitespace")
        if ":" in self.value:
            raise ValueError("a resource handle must not contain a colon")

    def __str__(self) -> str:
        return self.value
