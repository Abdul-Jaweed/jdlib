"""JWT algorithm policy (spec #9, #10).

Rules enforced here:

* ``alg: none`` is never acceptable,
* symmetric algorithms (``HS*``) are never acceptable when validating tokens
  against a JWKS public key — a public key must never validate an HMAC token,
  or anyone holding the public key could mint valid tokens,
* the algorithm list must be non-empty and explicitly allow-listed; algorithms
  are never taken from the token itself.

This module is import-safe (no optional dependency).
"""

from __future__ import annotations

from collections.abc import Sequence

from jdlib.security.errors import SecurityConfigurationError

ASYMMETRIC_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)

_SYMMETRIC_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})


def assert_safe_algorithms(algorithms: Sequence[str]) -> None:
    """Fail closed unless every configured algorithm is an asymmetric allow-listed one."""
    if not algorithms:
        raise SecurityConfigurationError(
            "at least one JWT algorithm must be explicitly allowed"
        )
    for algorithm in algorithms:
        if algorithm.lower() == "none":
            raise SecurityConfigurationError(
                "the 'none' algorithm must never be accepted for token validation"
            )
        if algorithm.upper() in _SYMMETRIC_ALGORITHMS:
            raise SecurityConfigurationError(
                f"algorithm {algorithm} cannot be used for JWKS validation: "
                "a published verification key must never validate an HMAC token"
            )
        if algorithm not in ASYMMETRIC_ALGORITHMS:
            raise SecurityConfigurationError(
                f"unknown JWT algorithm {algorithm!r}: only explicitly allow-listed "
                "asymmetric algorithms are accepted"
            )


__all__ = ["ASYMMETRIC_ALGORITHMS", "assert_safe_algorithms"]
