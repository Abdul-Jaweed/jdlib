from __future__ import annotations

from jdlib.errors import JdlibError


class ObjectStorageError(JdlibError):
    """Base for object storage failures."""


class ObjectNotFoundError(ObjectStorageError):
    """The object is not there. Distinct from 'the store is unreachable', which is not a 404."""


class AuthorizationRefusedError(ObjectStorageError):
    """The provider could not verify it was given an authorized context, and refused to open."""


class InvalidObjectKeyError(ObjectStorageError, ValueError):
    """A key was refused before it reached the store.

    Also a ValueError so a caller doing ordinary argument validation catches it either way.
    """
