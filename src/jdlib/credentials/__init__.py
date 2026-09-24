"""Credential references, versioned resolution and rotation (successor Phase 2).

Extends the existing ``jdlib.persistence.secrets.SecretProvider`` seam: the protocol itself is
unchanged, and this namespace adds value types (``SecretRef``, ``SecretVersion``,
``ResolvedSecret``), a rotation-aware wrapper and a composite. No credential value is ever
renderable from a reference, a resolved secret's repr, an error message or a log record.
"""

from jdlib.credentials.composite import CompositeSecretProvider
from jdlib.credentials.errors import (
    CredentialUnavailableError,
    CredentialVersionRetiredError,
)
from jdlib.credentials.redaction import REDACTED, redact
from jdlib.credentials.refs import ResolvedSecret, SecretRef, SecretVersion
from jdlib.credentials.rotation import INITIAL_VERSION, VersionedSecretProvider

__all__ = [
    "INITIAL_VERSION",
    "REDACTED",
    "CompositeSecretProvider",
    "CredentialUnavailableError",
    "CredentialVersionRetiredError",
    "ResolvedSecret",
    "SecretRef",
    "SecretVersion",
    "VersionedSecretProvider",
    "redact",
]
