from __future__ import annotations

from jdlib.storage.errors import InvalidObjectKeyError

TENANT_ROOT = "tenants"


def tenant_prefix(tenant_id: str) -> str:
    return f"{TENANT_ROOT}/{tenant_id}"


def object_key(tenant_id: str, key: str) -> str:
    """The only place a stored key is built, so no caller can place an object elsewhere.

    Refusals are deliberately blunt. A key is relative to its tenant, so anything that could
    climb out of the prefix - a parent segment, an absolute path, an empty key, a Windows-style
    separator that a different SDK might normalise - is refused rather than sanitised. Silently
    repairing a key is how one tenant's write lands in another tenant's prefix.
    """
    if not isinstance(key, str) or not key.strip():
        raise InvalidObjectKeyError("an object key must not be empty")
    if ".." in key:
        raise InvalidObjectKeyError(f"object key {key!r} contains a parent segment")
    if key.startswith("/") or key.startswith("\\") or "\\" in key:
        raise InvalidObjectKeyError(f"object key {key!r} must be relative to its tenant")
    if key.startswith(TENANT_ROOT + "/") or key == TENANT_ROOT:
        raise InvalidObjectKeyError(
            f"object key {key!r} names the tenant root directly; keys are relative"
        )
    return f"{tenant_prefix(tenant_id)}/{key}"
