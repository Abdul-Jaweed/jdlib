"""How a deployment reaches the graph (successor §16; directive §10).

The config carries a URI, a database name and the pool and timeout bounds — and a *reference* to
a credential, never the credential itself. Two properties are enforced here rather than
documented, because both are the kind that a comment does not hold:

* a URI with embedded credentials is refused, so a password cannot reach a log, a trace or an
  audit record through the object that describes the connection;
* the schemes that skip certificate verification are unreachable unless an operator opted in,
  so an unverified transport is a decision somebody made rather than a default somebody
  inherited.

The database name is validated with an allowlist rather than escaped, because it is interpolated
into a session selector and into audit records, and a name that needs backticks is a name a
caller should not be able to supply.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from jdlib.credentials import SecretRef
from jdlib.graph.errors import GraphValidationError

#: The schemes a graph URI may use. The ``+ssc`` variants are deliberately absent: they disable
#: certificate verification, so they are reachable only through the explicit opt-in below.
SECURE_SCHEMES = frozenset({"neo4j", "neo4j+s", "bolt", "bolt+s"})
UNVERIFIED_SCHEMES = frozenset({"neo4j+ssc", "bolt+ssc"})

#: Neo4j database names: a letter, then letters, digits, dot, dash or underscore. Narrower than
#: the server's own rule on purpose - this value is not data, it is a selector.
_DATABASE_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,62}\Z")

_POSITIVE_TIMEOUTS = (
    "connection_acquisition_timeout",
    "max_connection_lifetime",
    "connection_timeout",
)


@dataclass(frozen=True, slots=True)
class GraphConfig:
    """A validated description of the graph the caller is allowed to reach.

    ``auth`` is a :class:`~jdlib.credentials.SecretRef`; the value behind it is resolved at
    connect time through the credential provider chain and never stored here, so this type
    cannot leak one by rendering.
    """

    uri: str
    auth: SecretRef | None = None
    database: str | None = None
    max_connection_pool_size: int = 100
    connection_acquisition_timeout: float = 60.0
    max_connection_lifetime: float = 3600.0
    connection_timeout: float = 30.0
    max_transaction_retry_time: float = 30.0
    allow_unverified_certificates: bool = False

    def __post_init__(self) -> None:
        self._validate_uri()
        self._validate_auth()
        self._validate_bounds()
        self._validate_database()

    def _validate_uri(self) -> None:
        # Credentials first, and the refusal does not render the URI: a message that echoes a
        # connection string carrying a password is the leak this check exists to prevent.
        parts = urlsplit(self.uri)
        if parts.username is not None or parts.password is not None:
            raise GraphValidationError(
                "a graph URI must not carry credentials; use SecretRef and the provider chain"
            )
        allowed = SECURE_SCHEMES | (
            UNVERIFIED_SCHEMES if self.allow_unverified_certificates else frozenset()
        )
        if parts.scheme not in allowed:
            raise GraphValidationError(
                f"a graph URI must use one of {sorted(SECURE_SCHEMES)} "
                f"(self-signed schemes need allow_unverified_certificates): got {parts.scheme!r}"
            )
        if not parts.hostname:
            raise GraphValidationError("a graph URI must name a host")
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise GraphValidationError("a graph URI must not carry a path, a query or a fragment")

    def _validate_auth(self) -> None:
        if self.auth is not None and not isinstance(self.auth, SecretRef):
            raise GraphValidationError(
                "auth must be a SecretRef: a credential value has nowhere to live in this config"
            )

    def _validate_bounds(self) -> None:
        if self.max_connection_pool_size < 1:
            raise GraphValidationError("max_connection_pool_size must be at least 1")
        for name in _POSITIVE_TIMEOUTS:
            if getattr(self, name) <= 0:
                raise GraphValidationError(f"{name} must be positive")
        if self.max_transaction_retry_time < 0:
            raise GraphValidationError("max_transaction_retry_time must not be negative")

    def _validate_database(self) -> None:
        if self.database is None:
            return
        if not _DATABASE_PATTERN.match(self.database):
            raise GraphValidationError(
                "a database name must start with a letter and hold only letters, digits, "
                "dot, dash or underscore"
            )
