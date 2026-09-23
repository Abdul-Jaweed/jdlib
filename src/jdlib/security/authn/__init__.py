"""Authentication adapters built on the security core (spec #7-#10).

* :mod:`jdlib.security.authn.algorithms` — JWT algorithm allowlist policy.

Later phases add the token validator, token provider and the ZITADEL adapter.
"""

from jdlib.security.authn.algorithms import ASYMMETRIC_ALGORITHMS, assert_safe_algorithms

__all__ = ["ASYMMETRIC_ALGORITHMS", "assert_safe_algorithms"]
