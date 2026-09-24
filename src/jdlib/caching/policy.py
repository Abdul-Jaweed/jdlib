from __future__ import annotations

from dataclasses import dataclass

from jdlib.caching.errors import CachePolicyError


@dataclass(frozen=True, slots=True)
class CachePolicy:
    """How long an entry may live, and the ceiling no caller may exceed.

    Per-namespace overrides are deliberately absent until a namespace needs one: a policy
    object that can express anything is a policy nobody can review.
    """

    default_ttl: int = 300
    maximum_ttl: int = 3600

    def __post_init__(self) -> None:
        if self.default_ttl <= 0:
            raise CachePolicyError("default_ttl must be positive")
        if self.maximum_ttl <= 0:
            raise CachePolicyError("maximum_ttl must be positive")
        if self.default_ttl > self.maximum_ttl:
            raise CachePolicyError("default_ttl must not exceed maximum_ttl")

    def ttl_for(self, namespace: str, requested: int | None) -> int:
        ttl = self.default_ttl if requested is None else requested
        if ttl <= 0:
            raise CachePolicyError(f"namespace {namespace}: ttl must be positive, got {ttl}")
        if ttl > self.maximum_ttl:
            raise CachePolicyError(
                f"namespace {namespace}: ttl {ttl}s exceeds the policy maximum {self.maximum_ttl}s"
            )
        return ttl
