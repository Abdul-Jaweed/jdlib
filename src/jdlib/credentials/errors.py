from __future__ import annotations

from jdlib.errors import JdlibError


class CredentialUnavailableError(JdlibError):
    """A credential could not be resolved, or the requested version is no longer served.

    Joined to the existing taxonomy by inheriting ``JdlibError``: callers keep one handling
    path. Deliberately not added to ``jdlib.errors.__all__``, which existing tests iterate -
    new API arrives in new namespaces (ADR-4).

    The message names the handle and never the value.
    """


class CredentialVersionRetiredError(CredentialUnavailableError):
    """A pinned version has been rotated away; the caller must re-resolve and rebuild.

    Distinct from plain unavailability because the correct reaction differs: this one means
    re-resolve, not credential-gone.
    """
