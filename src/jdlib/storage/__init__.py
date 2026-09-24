"""Object storage (successor Phase 9).

Exactly one verified backend (ADR-5): S3-compatible storage, tested against a real server.
Google Cloud Storage and Azure Blob are **not** exported and have no module here - a provider
class in the public surface is a claim that it works, and this library only makes claims it
has a passing contract suite for. ``assert_object_storage_contract`` is that suite's gate: a
backend is exported once it satisfies it, and not before.

Keys are always relative to the caller's tenant and are built in one place, so a key cannot
name another tenant's object; anything that could climb out of the tenant prefix is refused
rather than sanitised.
"""

from jdlib.storage.errors import (
    AuthorizationRefusedError,
    InvalidObjectKeyError,
    ObjectNotFoundError,
    ObjectStorageError,
)
from jdlib.storage.keys import object_key, tenant_prefix
from jdlib.storage.metadata import ObjectMetadata, StoredObject
from jdlib.storage.provider import ObjectStorageProvider, assert_object_storage_contract
from jdlib.storage.s3 import S3ObjectStorage

__all__ = [
    "AuthorizationRefusedError",
    "InvalidObjectKeyError",
    "ObjectMetadata",
    "ObjectNotFoundError",
    "ObjectStorageError",
    "ObjectStorageProvider",
    "S3ObjectStorage",
    "StoredObject",
    "assert_object_storage_contract",
    "object_key",
    "tenant_prefix",
]
