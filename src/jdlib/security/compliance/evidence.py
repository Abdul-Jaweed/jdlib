"""Evidence collection (directive §9.3).

Evidence has to be **structured, timestamped, attributable, safe** and — where
the subject allows it — **reproducible**. Those five properties are the model's,
not a convention:

* *structured* — observations are a flat mapping of JSON scalars, so a report can
  be diffed, stored and queried,
* *timestamped* — ``collected_at`` comes from an injected clock,
* *attributable* — every record names the collector that produced it, and
  ``collected_by`` cannot be blank,
* *safe* — observations pass the **same** sanitiser the audit trail uses
  (``jdlib.security.audit.audit_metadata``): a credential-shaped value is
  redacted, a credential-named key is redacted whatever its value, and a
  structure or an oversized value is refused rather than smuggled into a report.
  There is deliberately no second sanitiser: two redaction paths would be two
  behaviours to keep in step,
* *reproducible* — ``reproducible`` carries the command or procedure that
  regenerates the observation.

The collectors here read the security configuration and the repository, so they
run without a database. Anything that needs a live schema (row-level security
policies, the applied migration revision, policy state) is collected against a
session in a later slice and uses this same record.
"""

from __future__ import annotations

import pathlib
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType

from jdlib._uuid import uuid7
from jdlib.context import Clock, SystemClock
from jdlib.security.audit import audit_metadata
from jdlib.security.config import SecurityConfig

__all__ = [
    "CONFIGURATION_EVIDENCE_KEYS",
    "MIGRATION_BRANCHES",
    "SecurityEvidence",
    "collect_configuration_evidence",
    "collect_migration_evidence",
]

#: The configuration facts that may appear in evidence. A collector cannot start
#: reporting something new without editing this set, which is what keeps a future
#: configuration field from leaking into a report by accident — and a test asserts
#: the collector's output is exactly a subset of it.
CONFIGURATION_EVIDENCE_KEYS = frozenset(
    {
        "authentication_enabled",
        "authentication_required",
        "authorization_enabled",
        "authorization_required",
        "authorization_fail_closed",
        "authorization_allow_all",
        "authorization_timeout_seconds",
        "tenant_context_required",
        "tenant_header_trusted",
        "privileged_bypass_allowed",
        "gateway_identity_headers_trusted",
        "gateway_identity_envelope_required",
        "audit_enabled",
        "debug_security_errors",
        "trace_propagation",
        "declared_environment",
    }
)

#: Alembic branches this project carries (each has its own revision history).
MIGRATION_BRANCHES = ("control", "tenant")

_REVISION = re.compile(r'^revision\s*=\s*"([^"]+)"', re.MULTILINE)
_DOWN_REVISION = re.compile(r'^down_revision\s*=\s*"([^"]+)"', re.MULTILINE)


@dataclass(frozen=True, slots=True)
class SecurityEvidence:
    """One observation about the system, ready to be reported or stored."""

    control_id: str
    subject: str
    collected_by: str
    collected_at: datetime
    observations: Mapping[str, object]
    reproducible: str
    evidence_id: uuid.UUID = field(default_factory=uuid7)
    environment: str | None = None

    def __post_init__(self) -> None:
        for name in ("control_id", "subject", "collected_by", "reproducible"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"security evidence needs a non-empty {name}")
        object.__setattr__(
            self, "observations", MappingProxyType(audit_metadata(dict(self.observations)))
        )

    def as_dict(self) -> dict[str, object]:
        """JSON-serializable representation (observations are already safe)."""
        return {
            "evidence_id": str(self.evidence_id),
            "control_id": self.control_id,
            "subject": self.subject,
            "collected_by": self.collected_by,
            "collected_at": self.collected_at.isoformat(),
            "environment": self.environment,
            "observations": dict(self.observations),
            "reproducible": self.reproducible,
        }

    def __repr__(self) -> str:
        """Represent the record without its observations (keys only).

        Evidence values describe a deployment; keeping them out of ``repr`` keeps
        them out of a stray log line or traceback, exactly as the audit envelope
        does with its metadata.
        """
        return (
            f"SecurityEvidence(control_id={self.control_id!r}, subject={self.subject!r}, "
            f"collected_by={self.collected_by!r}, observation_keys={sorted(self.observations)!r})"
        )


def collect_configuration_evidence(
    config: SecurityConfig,
    *,
    clock: Clock | None = None,
    environment: str | None = None,
) -> SecurityEvidence:
    """Observe the security configuration's posture-relevant facts.

    Only non-secret facts are read. The configuration model carries no secret
    material to begin with — credentials live in the deployment's own settings —
    but the observation set is fixed as well, so a field added later cannot
    arrive in a report unreviewed.
    """
    authentication = config.authentication
    authorization = config.authorization
    tenancy = config.tenancy
    gateway = config.gateway
    observability = config.observability
    observations: dict[str, object] = {
        "authentication_enabled": authentication.enabled,
        "authentication_required": authentication.require_authentication,
        "authorization_enabled": authorization.enabled,
        "authorization_required": authorization.require_authorization,
        "authorization_fail_closed": authorization.fail_closed,
        "authorization_allow_all": authorization.allow_all,
        "authorization_timeout_seconds": authorization.timeout.total_seconds(),
        "tenant_context_required": tenancy.require_tenant_context,
        "tenant_header_trusted": tenancy.trust_tenant_header,
        "privileged_bypass_allowed": tenancy.allow_privileged_bypass,
        "gateway_identity_headers_trusted": gateway.trust_identity_headers,
        "gateway_identity_envelope_required": gateway.require_identity_envelope,
        "audit_enabled": config.audit.enabled,
        "debug_security_errors": observability.debug_security_errors,
        "trace_propagation": observability.trace_propagation,
        "declared_environment": config.compliance.environment.value,
    }
    return SecurityEvidence(
        control_id="JDL-CONF-01",
        subject="jdlib.security.config.SecurityConfig",
        collected_by="jdlib.security.compliance.collect_configuration_evidence",
        collected_at=(clock or SystemClock()).now(),
        observations=observations,
        reproducible=(
            "build the deployment's SecurityConfig and call "
            "jdlib.security.compliance.collect_configuration_evidence(config)"
        ),
        environment=environment or config.compliance.environment.value,
    )


def collect_migration_evidence(
    *,
    root: pathlib.Path | None = None,
    clock: Clock | None = None,
    environment: str | None = None,
) -> SecurityEvidence:
    """Observe the revision history this checkout carries, per branch.

    This is what the *code* expects; what a live schema has actually applied is a
    database question and belongs to a session-backed collector. Both are needed
    to answer "is the deployment at the expected revision", and recording only
    the second would hide drift between the checkout and the schema.
    """
    base = root or pathlib.Path(__file__).resolve().parents[2] / "migrations"
    observations: dict[str, object] = {}
    for branch in MIGRATION_BRANCHES:
        versions = sorted((base / branch / "versions").glob("*.py"))
        revisions: list[str] = []
        referenced: set[str] = set()
        for path in versions:
            text = path.read_text(encoding="utf-8")
            found = _REVISION.search(text)
            if found is None:
                raise ValueError(f"migration {path.name} has no revision identifier")
            revisions.append(found.group(1))
            down = _DOWN_REVISION.search(text)
            if down is not None:
                referenced.add(down.group(1))
        heads = [revision for revision in revisions if revision not in referenced]
        if len(heads) != 1:
            raise ValueError(
                f"{branch} branch must have exactly one head, found {sorted(heads)}"
            )
        observations[f"{branch}_head"] = heads[0]
        observations[f"{branch}_revision_count"] = len(revisions)
        observations[f"{branch}_revisions"] = revisions
    return SecurityEvidence(
        control_id="JDL-CONF-01",
        subject="jdlib.migrations",
        collected_by="jdlib.security.compliance.collect_migration_evidence",
        collected_at=(clock or SystemClock()).now(),
        observations=observations,
        reproducible="ls src/jdlib/migrations/*/versions (or run jdlib db upgrade-*)",
        environment=environment,
    )
