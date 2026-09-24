"""Control registry (directive §9.1, §9.2).

A structured registry of the security controls this library actually implements,
each mapped onto the frameworks an assessor will ask about (SOC 2 Trust Services
Criteria, ISO/IEC 27001, NIST CSF, NIST SP 800-53, OWASP ASVS, OWASP API Security
Top 10, CIS Controls).

Two rules keep it honest:

* **A mapping is a description, not a certification.** The registry says "this
  control is best described by CC6.1" — it never claims an audit result, and
  nothing in this package may be reported as certification.
* **No silent partials.** A control whose status is anything other than
  ``IMPLEMENTED`` or ``NOT_APPLICABLE`` must explain itself in ``status_note``
  (and ``NOT_APPLICABLE`` says why it does not apply). A test enforces that, so a
  gap cannot be recorded without its reason — which is the whole value of a
  register for whoever reads it next.

``evidence_sources`` names the reproducible artefact behind the claim (a test
file, a document, a live harness). A test asserts every one of those paths exists
in the repository, so the register cannot cite evidence that was deleted or
renamed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

__all__ = [
    "CONTROL_REGISTRY",
    "Control",
    "ControlCategory",
    "ControlFramework",
    "ControlMapping",
    "ImplementationStatus",
    "VerificationMethod",
    "control_by_id",
    "controls_for_framework",
    "frameworks_in_use",
]


class ControlFramework(StrEnum):
    """The framework families a control can be mapped onto (directive §9.1)."""

    SOC2 = "soc2"
    """SOC 2 Trust Services Criteria."""

    ISO_27001 = "iso_27001"
    """ISO/IEC 27001 (2022 Annex A)."""

    NIST_CSF = "nist_csf"
    """NIST Cybersecurity Framework (2.0)."""

    NIST_800_53 = "nist_sp_800_53"
    """NIST SP 800-53 Rev. 5 controls."""

    OWASP_ASVS = "owasp_asvs"
    """OWASP Application Security Verification Standard."""

    OWASP_API_TOP10 = "owasp_api_top10"
    """OWASP API Security Top 10."""

    CIS = "cis"
    """CIS Critical Security Controls (v8)."""


class ControlCategory(StrEnum):
    """What a control protects, so posture can be grouped by concern."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    TENANT_ISOLATION = "tenant_isolation"
    AUDIT = "audit"
    DATA_PROTECTION = "data_protection"
    CONFIGURATION = "configuration"
    OBSERVABILITY = "observability"
    LIFECYCLE = "lifecycle"
    SUPPLY_CHAIN = "supply_chain"


class ImplementationStatus(StrEnum):
    """How far the control is implemented *in this library*.

    This is deliberately not the same vocabulary as the posture result
    (``PASS``/``WARN``/``FAIL``/``NOT_APPLICABLE``): a status is a standing
    property of the control, a posture result is what today's check said.
    """

    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


class VerificationMethod(StrEnum):
    """How the claim is shown to be true (directive §9.2)."""

    TEST = "test"
    """An automated test in this repository exercises it."""

    INSPECTION = "inspection"
    """A reviewer reads code or configuration."""

    ANALYSIS = "analysis"
    """A written evaluation (a threat model, a design decision)."""

    RUNTIME = "runtime"
    """Verified against a running service by the harness in ``tests/infra``."""

    EXTERNAL = "external"
    """The deployment's responsibility; not discharged by this library."""


@dataclass(frozen=True, slots=True)
class ControlMapping:
    """Where a control is described in one framework."""

    framework: ControlFramework
    reference: str
    """The framework's own identifier, e.g. ``CC6.1`` or ``API1:2023``."""


@dataclass(frozen=True, slots=True)
class Control:
    """One control, with everything an evidence collector or an assessor needs."""

    control_id: str
    title: str
    description: str
    category: ControlCategory
    implementation_status: ImplementationStatus
    mappings: tuple[ControlMapping, ...]
    evidence_requirements: tuple[str, ...]
    evidence_sources: tuple[str, ...]
    technical_owner: str
    verification_method: VerificationMethod
    status_note: str | None = None
    """Required for any status other than IMPLEMENTED / NOT_APPLICABLE."""

    def mapping_for(self, framework: ControlFramework) -> ControlMapping | None:
        """This control's mapping into ``framework``, if it has one."""
        for mapping in self.mappings:
            if mapping.framework is framework:
                return mapping
        return None

    def __repr__(self) -> str:
        """Represent the control without its prose (keeps logs readable)."""
        return (
            f"Control(control_id={self.control_id!r}, "
            f"status={self.implementation_status.value!r}, "
            f"frameworks={[m.framework.value for m in self.mappings]!r})"
        )


def _mappings(*pairs: tuple[ControlFramework, str]) -> tuple[ControlMapping, ...]:
    return tuple(ControlMapping(framework, reference) for framework, reference in pairs)


_CONTROLS: tuple[Control, ...] = (
    Control(
        control_id="JDL-AUTHN-01",
        title="Inbound token validation fails closed",
        description=(
            "Access tokens are validated against the issuer's published keys with an "
            "explicit algorithm allow-list: signature, issuer, audience and both time "
            "bounds are checked, an unknown key id is refused, a symmetric algorithm is "
            "never accepted for a public key, and an expired or not-yet-valid token is "
            "refused rather than trusted."
        ),
        category=ControlCategory.AUTHENTICATION,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.1"),
            (ControlFramework.ISO_27001, "A.8.5"),
            (ControlFramework.NIST_800_53, "IA-5"),
            (ControlFramework.OWASP_ASVS, "V3.1"),
            (ControlFramework.OWASP_API_TOP10, "API2:2023"),
            (ControlFramework.CIS, "6.5"),
        ),
        evidence_requirements=(
            "a forged signature, alg=none, HS/RS confusion, a wrong issuer or audience, "
            "an expired or not-yet-valid token, and an unknown key id are all refused",
            "the algorithm allow-list rejects 'none' and every symmetric algorithm at "
            "configuration time",
        ),
        evidence_sources=(
            "tests/unit/security/test_jwt_validator.py",
            "tests/unit/test_authn_base.py",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-AUTHN-02",
        title="API key authentication is scoped and time-bounded",
        description=(
            "API keys are Argon2-hashed at rest, carried with an expiry and a tenant "
            "pin, and their scopes can only narrow (never widen) what the principal's "
            "roles allow."
        ),
        category=ControlCategory.AUTHENTICATION,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.1"),
            (ControlFramework.ISO_27001, "A.5.17"),
            (ControlFramework.NIST_800_53, "IA-5"),
            (ControlFramework.OWASP_ASVS, "V2.1"),
            (ControlFramework.CIS, "5.4"),
        ),
        evidence_requirements=(
            "an expired or revoked key is refused",
            "an out-of-scope permission is denied even when a role grants it",
        ),
        evidence_sources=(
            "tests/unit/test_apikey_parser.py",
            "tests/integration/test_apikey_auth.py",
            "tests/unit/test_pdp.py",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-AUTHN-03",
        title="Bearer-token replay is bounded by the token's own lifetime",
        description=(
            "This library validates tokens statelessly against the issuer's JWKS. It "
            "keeps no session store and no token denylist, so a captured token is "
            "replayable until it expires; revocation is the identity provider's "
            "responsibility and is enforced there."
        ),
        category=ControlCategory.AUTHENTICATION,
        implementation_status=ImplementationStatus.NOT_APPLICABLE,
        mappings=_mappings(
            (ControlFramework.OWASP_ASVS, "V3.5"),
            (ControlFramework.NIST_800_53, "IA-5(13)"),
        ),
        evidence_requirements=(
            "the deployment sets token lifetimes that match its risk appetite",
            "revocation is enforced at the identity provider, not here",
        ),
        evidence_sources=("docs/security/adversarial-review.md",),
        technical_owner="identity-platform",
        verification_method=VerificationMethod.EXTERNAL,
        status_note=(
            "Not applicable at this layer: with no server-side session there is nothing "
            "for the library to denylist, and a local denylist would only cover tokens "
            "this process happened to see. Recorded so an assessor sees the decision "
            "rather than an empty cell."
        ),
    ),
    Control(
        control_id="JDL-AUTHZ-01",
        title="Every authorization decision goes through one policy enforcement point",
        description=(
            "Application code calls the enforcement point, never a policy engine "
            "directly. It refuses an unauthenticated caller, refuses a context with no "
            "tenant binding, refuses a query naming another tenant before the engine is "
            "consulted, and raises on any denial."
        ),
        category=ControlCategory.AUTHORIZATION,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.1"),
            (ControlFramework.ISO_27001, "A.8.3"),
            (ControlFramework.NIST_800_53, "AC-3"),
            (ControlFramework.OWASP_ASVS, "V4.1"),
            (ControlFramework.OWASP_API_TOP10, "API1:2023"),
            (ControlFramework.NIST_CSF, "PR.AA-05"),
        ),
        evidence_requirements=(
            "an anonymous caller, a tenant-less context and a cross-tenant query are "
            "each refused, with the cross-tenant case refused before the engine is asked",
            "a policy denial raises a typed error and never returns",
        ),
        evidence_sources=(
            "tests/unit/security/test_authz_pep.py",
            "tests/integration/test_fastapi_integration.py",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-AUTHZ-02",
        title="A policy engine that cannot answer denies everything",
        description=(
            "An engine that is unavailable, times out, or returns a malformed or "
            "incomplete response produces a degraded denial: never an allow, and "
            "reported as 503 (retryable) rather than 403 so an outage is not filed as a "
            "policy verdict."
        ),
        category=ControlCategory.AUTHORIZATION,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.6"),
            (ControlFramework.ISO_27001, "A.8.20"),
            (ControlFramework.NIST_800_53, "SC-7"),
            (ControlFramework.OWASP_ASVS, "V4.1"),
            (ControlFramework.CIS, "12.7"),
        ),
        evidence_requirements=(
            "unavailability, timeout, a malformed response and a missing action result "
            "each deny",
            "a degraded decision is distinguishable from a policy denial",
        ),
        evidence_sources=(
            "tests/unit/security/test_cerbos_pdp.py",
            "tests/infra/test_cerbos_infra.py",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.RUNTIME,
    ),
    Control(
        control_id="JDL-AUTHZ-03",
        title="Just-in-time privilege stops authorizing when its window closes",
        description=(
            "A privilege carries an issue time and an expiry, and every enforcement "
            "path reads it through a liveness check: privileged raw SQL, hard deletes, "
            "tenant-id rewrites and the relocation write-fence bypass all refuse a "
            "lapsed (or not-yet-valid) privilege."
        ),
        category=ControlCategory.AUTHORIZATION,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.3"),
            (ControlFramework.ISO_27001, "A.8.2"),
            (ControlFramework.NIST_800_53, "AC-2(2)"),
            (ControlFramework.OWASP_ASVS, "V4.1"),
        ),
        evidence_requirements=(
            "an expired privilege cannot run privileged raw SQL, hard-delete, or bypass "
            "the write fence — and the refusal does not reach the database",
            "the guarantee is per use, so a privilege that lapses mid-session stops "
            "authorizing immediately",
        ),
        evidence_sources=(
            "tests/unit/security/test_adversarial_privilege.py",
            "docs/security/adversarial-review.md",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-GW-01",
        title="Gateway-derived identity requires an authenticated integrity boundary",
        description=(
            "Identity headers are honoured only when they arrive inside a signed or "
            "shared-secret assertion with a bounded validity window. With no gateway "
            "configured the headers are ignored outright, and a signature-mode "
            "assertion cannot be downgraded to a shared-secret one."
        ),
        category=ControlCategory.AUTHENTICATION,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.1"),
            (ControlFramework.ISO_27001, "A.8.5"),
            (ControlFramework.NIST_800_53, "IA-3"),
            (ControlFramework.OWASP_API_TOP10, "API2:2023"),
            (ControlFramework.CIS, "12.6"),
        ),
        evidence_requirements=(
            "spoofed, unsigned, expired, over-long or downgraded assertions are refused",
            "a key pinned to one tenant cannot be pointed at another through a header",
        ),
        evidence_sources=(
            "tests/unit/security/test_gateway_adapters.py",
            "tests/integration/test_fastapi_integration.py",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-GW-02",
        title="Gateway plugin verification across products",
        description=(
            "The gateway adapters are verified against a real gateway: Kong 3.6 runs "
            "the header-taking plugins end to end. The Tyk harness exists but stock Tyk "
            "5.3.1 OSS ships no JavaScript or coprocess runtime, so those checks skip "
            "with that reason instead of passing."
        ),
        category=ControlCategory.AUTHENTICATION,
        implementation_status=ImplementationStatus.PARTIAL,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.6"),
            (ControlFramework.ISO_27001, "A.8.20"),
            (ControlFramework.CIS, "12.6"),
        ),
        evidence_requirements=(
            "Kong verification passes against the running gateway",
            "Tyk verification is attempted and its limitation is recorded, not hidden",
        ),
        evidence_sources=(
            "tests/infra/test_kong_infra.py",
            "tests/infra/test_tyk_infra.py",
            "docs/security/gateway-hardening.md",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.RUNTIME,
        status_note=(
            "Partial by engine, not by code: stock Tyk 5.3.1 OSS has no JavaScript or "
            "coprocess runtime, so the adapter's contract is asserted against a stub and "
            "the live checks skip with the reason. Unblocking means a Tyk build with "
            "that runtime, or a supported plugin mechanism."
        ),
    ),
    Control(
        control_id="JDL-SQL-01",
        title="Raw SQL is validated by parsing, not by pattern matching",
        description=(
            "Statements that bypass the ORM go through a real PostgreSQL parser "
            "(pglast): the tenant predicate must be provable on every relation, a "
            "hidden write inside a CTE, a predicate that lives in a comment, an "
            "unscoped UNION branch and a tenant_id assignment are all refused."
        ),
        category=ControlCategory.TENANT_ISOLATION,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.1"),
            (ControlFramework.ISO_27001, "A.8.28"),
            (ControlFramework.NIST_800_53, "SI-10"),
            (ControlFramework.OWASP_ASVS, "V5.3"),
            (ControlFramework.CIS, "16.11"),
        ),
        evidence_requirements=(
            "a genuinely scoped statement is accepted and every dangerous shape is "
            "refused through the session the application calls",
            "a refusal proves nothing executed, by re-reading the rows it would have "
            "changed",
        ),
        evidence_sources=(
            "tests/integration/test_adversarial_raw_sql.py",
            "tests/unit/security/test_adversarial.py",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-ISO-01",
        title="Tenant isolation is enforced by the database, not only by the library",
        description=(
            "Tenant-routed tables carry row-level security policies bound to the "
            "session's tenant setting, and the application role cannot bypass them. The "
            "library also scopes every query it builds, but the guarantee does not rest "
            "on that: a missing predicate cannot become a cross-tenant read."
        ),
        category=ControlCategory.TENANT_ISOLATION,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.1"),
            (ControlFramework.ISO_27001, "A.8.3"),
            (ControlFramework.NIST_800_53, "AC-4"),
            (ControlFramework.NIST_CSF, "PR.DS-01"),
            (ControlFramework.CIS, "3.1"),
        ),
        evidence_requirements=(
            "an unset tenant setting sees no rows and cannot insert",
            "the setting is bound per transaction and cleared when the session closes",
            "RLS verification refuses a table with no policy, an unforced table, and a "
            "bypassing or superuser role",
        ),
        evidence_sources=(
            "tests/integration/test_rls_db.py",
            "docs/jdlib/03-isolation-invariants.md",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.RUNTIME,
    ),
    Control(
        control_id="JDL-ISO-02",
        title="Cross-tenant references are impossible at the schema level",
        description=(
            "References between tenant-routed tables are composite on the tenant "
            "column, so a row cannot point at another tenant's row even when every "
            "application-level check is bypassed, and a tenant_id can neither be "
            "reassigned nor changed after insert."
        ),
        category=ControlCategory.TENANT_ISOLATION,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.1"),
            (ControlFramework.ISO_27001, "A.8.3"),
            (ControlFramework.NIST_800_53, "AC-4"),
            (ControlFramework.OWASP_ASVS, "V1.4"),
        ),
        evidence_requirements=(
            "a cross-tenant foreign-key insert is refused on a raw connection, with no "
            "library guard in the way, while the same-tenant insert succeeds",
            "a bulk update or delete aimed at another tenant's rows changes nothing",
        ),
        evidence_sources=(
            "tests/integration/test_adversarial_tenant_isolation.py",
            "tests/integration/test_session_isolation.py",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-AUDIT-01",
        title="Security events are recorded with fail-closed attribution",
        description=(
            "A stable event vocabulary is persisted in the caller's transaction: an "
            "operation that rolls back leaves no audit row, an event naming another "
            "tenant or another actor is refused rather than written, an unnamed actor "
            "is taken from the context, and a timestamp the recorder cannot corroborate "
            "is refused."
        ),
        category=ControlCategory.AUDIT,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC7.2"),
            (ControlFramework.ISO_27001, "A.8.15"),
            (ControlFramework.NIST_800_53, "AU-3"),
            (ControlFramework.OWASP_ASVS, "V7.1"),
            (ControlFramework.CIS, "8.2"),
        ),
        evidence_requirements=(
            "a forged actor, a forged tenant, a backdated or postdated event and an "
            "event with no actor are each refused",
            "a rolled-back operation leaves no audit row against a real database",
        ),
        evidence_sources=(
            "tests/unit/security/test_adversarial_audit_integrity.py",
            "tests/integration/test_security_audit_persistence.py",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-AUDIT-02",
        title="Reading and exporting the trail are separately authorized",
        description=(
            "Writing the trail confers neither reading nor exporting it. Reads are "
            "tenant-bounded (a query cannot widen them), a cross-tenant read requires "
            "the platform capability, a scope-less caller is refused as unauthenticated, "
            "and an export is bounded, deterministic and recorded as its own event."
        ),
        category=ControlCategory.AUDIT,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.3"),
            (ControlFramework.ISO_27001, "A.5.15"),
            (ControlFramework.NIST_800_53, "AC-6"),
            (ControlFramework.OWASP_ASVS, "V8.1"),
            (ControlFramework.CIS, "6.8"),
        ),
        evidence_requirements=(
            "a write-only principal cannot read or export the trail",
            "a tenant reader asking for another tenant is refused, and the platform "
            "capability is what makes it work",
        ),
        evidence_sources=(
            "tests/unit/security/test_audit_access_export.py",
            "tests/integration/test_audit_isolation_export.py",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-AUDIT-03",
        title="Tamper-evident audit storage outside the database",
        description=(
            "Per-row hash chaining inside the same database was evaluated and rejected: "
            "an actor with UPDATE/DELETE can drop triggers and rewrite the chain, so it "
            "would add cost and theatre without changing what that actor can do. "
            "Detecting database-level tampering therefore requires storage the "
            "application's role cannot rewrite."
        ),
        category=ControlCategory.AUDIT,
        implementation_status=ImplementationStatus.NOT_IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC7.1"),
            (ControlFramework.ISO_27001, "A.8.16"),
            (ControlFramework.NIST_800_53, "AU-9"),
            (ControlFramework.CIS, "8.10"),
        ),
        evidence_requirements=(
            "audit rows are shipped to append-only storage the application role cannot "
            "rewrite (WAL/CDC streaming, retention-locked object storage, a SIEM)",
            "a periodic digest of each tenant's audit range is anchored in that store",
            "the application role holds no UPDATE or DELETE on audit_events",
        ),
        evidence_sources=(
            "docs/security/audit-hardening.md",
            "docs/security/adversarial-review.md",
        ),
        technical_owner="platform-operations",
        verification_method=VerificationMethod.EXTERNAL,
        status_note=(
            "Deliberately not implemented in-library: no in-database scheme stops an "
            "actor who holds database write access, and the fail-closed transaction "
            "semantics never need UPDATE or DELETE on the trail. The residual risk is "
            "recorded in the audit hardening document and must be closed by deployment "
            "controls, not by this library."
        ),
    ),
    Control(
        control_id="JDL-SECRET-01",
        title="Secrets are redacted on every path that leaves the process",
        description=(
            "Error responses, log records, span attributes and audit metadata share one "
            "redaction set: a credential-shaped value becomes [redacted], a "
            "disqualifying field name is redacted whatever its value, and no repository "
            "or generated artefact contains a live credential."
        ),
        category=ControlCategory.DATA_PROTECTION,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.1"),
            (ControlFramework.ISO_27001, "A.8.24"),
            (ControlFramework.NIST_800_53, "SC-8"),
            (ControlFramework.OWASP_ASVS, "V7.1"),
            (ControlFramework.CIS, "3.3"),
        ),
        evidence_requirements=(
            "a credential placed in an allowed field never reaches an error body, a log "
            "record, a span attribute, an audit row, or a real collector",
            "a repository scan finds no real credential, and the scan can fail",
        ),
        evidence_sources=(
            "tests/unit/security/test_error_responses.py",
            "tests/unit/security/test_telemetry.py",
            "tests/unit/security/test_adversarial.py",
            "tests/infra/test_otel_infra.py",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-CONF-01",
        title="Unsafe security configuration cannot start",
        description=(
            "The security configuration is schema-locked and validated on construction "
            "and again on demand: trusting identity headers without a signed envelope, "
            "a weak or missing signing key, a non-secure policy endpoint, an unsafe "
            "algorithm or an unbounded timeout each raise before the process serves."
        ),
        category=ControlCategory.CONFIGURATION,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC8.1"),
            (ControlFramework.ISO_27001, "A.8.9"),
            (ControlFramework.NIST_800_53, "CM-6"),
            (ControlFramework.OWASP_ASVS, "V14.1"),
            (ControlFramework.CIS, "4.1"),
        ),
        evidence_requirements=(
            "each unsafe combination is refused with a configuration error",
            "the public configuration surface is pinned, so a new field cannot arrive "
            "silently",
        ),
        evidence_sources=(
            "tests/unit/security/test_security_config.py",
            "tests/unit/security/test_security_public_surface.py",
        ),
        technical_owner="platform-security",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-OBS-01",
        title="Security telemetry is structured, bounded and non-blocking",
        description=(
            "Security log records carry joinable identifiers and no credential; metric "
            "labels are validated against a bounded allow-list, including "
            "identifier-shaped values; trace context is parsed strictly; and a "
            "telemetry failure can never turn into an authorization or audit failure."
        ),
        category=ControlCategory.OBSERVABILITY,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC7.2"),
            (ControlFramework.ISO_27001, "A.8.16"),
            (ControlFramework.NIST_800_53, "AU-6"),
            (ControlFramework.NIST_CSF, "DE.AE-03"),
            (ControlFramework.CIS, "8.11"),
        ),
        evidence_requirements=(
            "an unbounded label name and an identifier-shaped label value are refused "
            "in the write path",
            "a security span and its redaction are verified against a real collector",
            "a broken metrics backend cannot break an authorization decision",
        ),
        evidence_sources=(
            "tests/unit/security/test_telemetry.py",
            "tests/unit/security/test_tracing.py",
            "tests/infra/test_otel_infra.py",
        ),
        technical_owner="platform-operations",
        verification_method=VerificationMethod.RUNTIME,
    ),
    Control(
        control_id="JDL-LIFE-01",
        title="Tenant lifecycle transitions are bounded and recorded",
        description=(
            "Suspension, archival and purge are explicit transitions with their own "
            "audit events; a purge is bounded and refuses to run outside a servable "
            "tenant, and a deprovisioned tenant's data is removed rather than orphaned."
        ),
        category=ControlCategory.LIFECYCLE,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC6.5"),
            (ControlFramework.ISO_27001, "A.5.34"),
            (ControlFramework.NIST_800_53, "AC-2"),
            (ControlFramework.CIS, "3.2"),
        ),
        evidence_requirements=(
            "each transition emits its own audit event",
            "a purge refuses while the tenant must still be servable",
        ),
        evidence_sources=(
            "tests/integration/test_tenant_purge.py",
            "tests/unit/security/test_audit_control_adapters.py",
        ),
        technical_owner="platform-operations",
        verification_method=VerificationMethod.TEST,
    ),
    Control(
        control_id="JDL-SUPPLY-01",
        title="Dependency and pipeline security gates",
        description=(
            "The repository's own gate (test suite with warnings as errors, linter, "
            "type checker) runs in CI on every push, and CI is where dependency and "
            "artefact checks belong. The pipeline hardening itself is a separate work "
            "stream rather than a claim made here."
        ),
        category=ControlCategory.SUPPLY_CHAIN,
        implementation_status=ImplementationStatus.PARTIAL,
        mappings=_mappings(
            (ControlFramework.SOC2, "CC8.1"),
            (ControlFramework.ISO_27001, "A.8.28"),
            (ControlFramework.NIST_800_53, "SA-11"),
            (ControlFramework.OWASP_ASVS, "V14.2"),
            (ControlFramework.CIS, "16.1"),
        ),
        evidence_requirements=(
            "the full gate runs on every push and its result is readable per commit",
            "dependency and secret scanning run in the pipeline, on pinned versions",
        ),
        evidence_sources=(
            ".github/workflows/ci.yml",
            "docs/security/adversarial-review.md",
        ),
        technical_owner="release-engineering",
        verification_method=VerificationMethod.INSPECTION,
        status_note=(
            "Partial: the test/lint/type gate runs in CI today, and the dedicated "
            "pipeline-security work (dependency scanning, pinned actions, artefact "
            "provenance) is the next phase's scope. Recorded as partial so the gap is "
            "visible until that lands."
        ),
    ),
)

#: The registry, keyed by control id (frozen so callers cannot edit it in place).
CONTROL_REGISTRY: Mapping[str, Control] = MappingProxyType(
    {control.control_id: control for control in _CONTROLS}
)


def control_by_id(control_id: str) -> Control | None:
    """Look a control up by id, returning ``None`` when it is not registered."""
    return CONTROL_REGISTRY.get(control_id)


def controls_for_framework(framework: ControlFramework) -> tuple[Control, ...]:
    """Every control mapped into ``framework``, in registry order."""
    return tuple(
        control for control in _CONTROLS if control.mapping_for(framework) is not None
    )


def frameworks_in_use() -> tuple[ControlFramework, ...]:
    """The frameworks the registry maps onto, in declaration order."""
    seen: list[ControlFramework] = []
    for control in _CONTROLS:
        for mapping in control.mappings:
            if mapping.framework not in seen:
                seen.append(mapping.framework)
    return tuple(seen)
