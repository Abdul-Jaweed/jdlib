"""Security posture (directive §9.4).

Posture answers one question — *which controls are in force here, and how do we
know* — and answers it with the four outcomes the directive names. Getting the
semantics right matters more than the reporting, so they are fixed here rather
than left to each rule:

``PASS``
    The control is in force, and either its enforcement point is inside a code
    path a caller cannot route around (a gate in the library: raw SQL, privilege
    liveness, redaction, tenant binding) or the evidence supplied for it observes
    the state it depends on. A construction-enforced control needs no deployment
    evidence; a deployment-dependent one is only ``PASS`` when something was
    actually observed.

``WARN``
    The control is in force **but unverified here** (no evidence was supplied, or
    the evidence is incomplete — in which case the reason names what is missing),
    or it is switched off in a profile that declares itself unsafe on purpose
    (``development``). It is also the honest outcome for a control the library
    deliberately does not provide but a deployment must, which is a readiness gap
    rather than a library defect.

``FAIL``
    A control that should be in force is absent, disabled or contradicted by the
    evidence. An unsafe combination in a profile other than ``development``, a
    lapsed isolation policy observed on a live catalog, or a pipeline with no
    security gates are all failures — reporting them as warnings is how a posture
    page becomes decoration.

``NOT_APPLICABLE``
    The control's subject does not exist in this deployment: no gateway identity
    trust is configured, or the control addresses something this architecture
    cannot have (replay protection for a stateless validator that keeps no
    server-side session).

One property of this codebase makes the failure cases interesting: the production
profile **refuses to construct** an unsafe configuration (Phase 1 validation), so
the contradictions posture reports in production are missing evidence and missing
infrastructure, while the unsafe-combination failures appear in the profiles
where they can actually exist.

Nothing here concludes anything about an external auditor's opinion. A finding
describes a technical control and the observation behind it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from jdlib.context import Clock, SystemClock
from jdlib.security.compliance.controls import (
    CONTROL_REGISTRY,
    Control,
    control_by_id,
)
from jdlib.security.compliance.evidence import SecurityEvidence
from jdlib.security.config import SecurityConfig

__all__ = [
    "POSTURE_RULES",
    "PostureFinding",
    "PostureOutcome",
    "PostureReport",
    "PostureRule",
    "Severity",
    "evaluate_posture",
]

#: A finding's explanation is the point of the finding; a phrase will not do.
MINIMUM_REASON_LENGTH = 20

#: Rank for :attr:`PostureReport.worst_outcome`. A gap that needs attention
#: outranks a control that simply does not apply here, which outranks a pass.
_OUTCOME_RANK: Mapping[str, int] = {}


class PostureOutcome(StrEnum):
    """What today's check said about a control."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"


class Severity(StrEnum):
    """How much attention an outcome deserves."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_OUTCOME_RANK = {
    PostureOutcome.PASS: 0,
    PostureOutcome.NOT_APPLICABLE: 1,
    PostureOutcome.WARN: 2,
    PostureOutcome.FAIL: 3,
}


@dataclass(frozen=True, slots=True)
class PostureFinding:
    """One control, one outcome, and the explanation behind it."""

    control_id: str
    outcome: PostureOutcome
    severity: Severity
    title: str
    reason: str
    evidence: tuple[SecurityEvidence, ...] = ()

    def __post_init__(self) -> None:
        if control_by_id(self.control_id) is None:
            raise ValueError(f"unknown control: {self.control_id}")
        if not isinstance(self.reason, str) or len(self.reason.strip()) < MINIMUM_REASON_LENGTH:
            raise ValueError(
                f"a posture finding needs a reason of at least "
                f"{MINIMUM_REASON_LENGTH} characters: {self.control_id}"
            )
        if not self.title.strip():
            raise ValueError(f"a posture finding needs a title: {self.control_id}")
        for record in self.evidence:
            if not isinstance(record, SecurityEvidence):
                raise TypeError(
                    f"evidence must be SecurityEvidence, got {type(record).__name__}"
                )
            if record.control_id != self.control_id:
                raise ValueError(
                    f"evidence for {record.control_id} cannot explain a finding for "
                    f"{self.control_id}"
                )
        # Canonical order: the same set of observations must serialize identically
        # however it was supplied.
        object.__setattr__(
            self, "evidence", tuple(sorted(self.evidence, key=lambda item: str(item.evidence_id)))
        )

    def as_dict(self) -> dict[str, object]:
        """Structured form: outcomes and reasons, never observation values."""
        return {
            "control_id": self.control_id,
            "title": self.title,
            "outcome": self.outcome.value,
            "severity": self.severity.value,
            "reason": self.reason,
            "evidence": [
                {
                    "evidence_id": str(record.evidence_id),
                    "control_id": record.control_id,
                    "subject": record.subject,
                    "collected_at": record.collected_at.isoformat(),
                    "collected_by": record.collected_by,
                }
                for record in self.evidence
            ],
        }

    def __repr__(self) -> str:
        return (
            f"PostureFinding(control_id={self.control_id!r}, outcome={self.outcome.value!r}, "
            f"severity={self.severity.value!r}, evidence={len(self.evidence)})"
        )


@dataclass(frozen=True, slots=True)
class PostureReport:
    """Every control in the registry, exactly once, in a deterministic order."""

    findings: tuple[PostureFinding, ...]
    generated_at: datetime
    environment: str

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for finding in self.findings:
            if not isinstance(finding, PostureFinding):
                raise TypeError(f"findings must be PostureFinding, got {type(finding).__name__}")
            if finding.control_id in seen:
                raise ValueError(f"duplicate finding for {finding.control_id}")
            seen.add(finding.control_id)
        object.__setattr__(
            self, "findings", tuple(sorted(self.findings, key=lambda item: item.control_id))
        )

    @property
    def counts(self) -> dict[PostureOutcome, int]:
        """How many findings reached each outcome."""
        counts = {outcome: 0 for outcome in PostureOutcome}
        for finding in self.findings:
            counts[finding.outcome] += 1
        return counts

    @property
    def worst_outcome(self) -> PostureOutcome:
        """The outcome that most deserves attention."""
        return max(
            (finding.outcome for finding in self.findings),
            key=lambda outcome: _OUTCOME_RANK[outcome],
            default=PostureOutcome.PASS,
        )

    @property
    def is_ready(self) -> bool:
        """Whether anything failed — readiness, not certification."""
        return not any(finding.outcome is PostureOutcome.FAIL for finding in self.findings)

    @property
    def failures(self) -> tuple[PostureFinding, ...]:
        return tuple(
            finding for finding in self.findings if finding.outcome is PostureOutcome.FAIL
        )

    def as_dict(self) -> dict[str, object]:
        """Structured report for the CLI, CI or a document."""
        counts = self.counts
        return {
            "generated_at": self.generated_at.isoformat(),
            "environment": self.environment,
            "outcome": self.worst_outcome.value,
            "is_ready": self.is_ready,
            "counts": {outcome.value: count for outcome, count in counts.items()},
            "findings": [finding.as_dict() for finding in self.findings],
        }

    def __repr__(self) -> str:
        counts = self.counts
        summary = ", ".join(
            f"{outcome.value}={counts[outcome]}" for outcome in PostureOutcome if counts[outcome]
        )
        return (
            f"PostureReport(environment={self.environment!r}, findings={len(self.findings)}, "
            f"{summary})"
        )


#: A rule reads the configuration and whatever evidence was collected for its
#: control, and returns the outcome, its severity and the reason.
PostureRule = Callable[
    [SecurityConfig, tuple[SecurityEvidence, ...]],
    "tuple[PostureOutcome, Severity, str]",
]


def _profile_allows_unsafe(config: SecurityConfig) -> bool:
    """Whether this profile declares itself non-enforcing on purpose."""
    return config.compliance.environment.value == "development"


def _missing_observations(evidence: tuple[SecurityEvidence, ...], *keys: str) -> list[str]:
    """Observations the evidence does not carry, across every record supplied."""
    present: set[str] = set()
    for record in evidence:
        present.update(record.observations)
    return [key for key in keys if key not in present]


def _observed_names(record: SecurityEvidence, key: str) -> list[str]:
    """A list-valued observation, read back as the model's ``object`` allows.

    Observations are JSON scalars by construction, but the model only promises
    ``object``: reading one back needs a check, not a cast, and a value of an
    unexpected shape is treated as absent rather than trusted.
    """
    value = record.observations.get(key)
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return []


def _observed_count(record: SecurityEvidence, key: str) -> int:
    """A count-valued observation, or zero when it is not a count."""
    value = record.observations.get(key)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _gate_rule(*, section: str, subject: str, enforcement: str, failure: str) -> PostureRule:
    """Build a rule for a control that is switched on by one configuration flag.

    ``section`` names the configuration section the flag lives in — the accessor is
    by name, so a rule cannot quietly read the wrong one. ``enabled`` is a pass; a
    profile that declares itself unsafe on purpose warns; anywhere else a disabled
    control of this kind is a failure.
    """

    def rule(config: SecurityConfig, evidence: tuple[SecurityEvidence, ...]) -> tuple[
        PostureOutcome, Severity, str
    ]:
        settings = getattr(config, section)
        if getattr(settings, subject):
            return PostureOutcome.PASS, Severity.INFO, f"{enforcement} is in force."
        if _profile_allows_unsafe(config):
            return (
                PostureOutcome.WARN,
                Severity.MEDIUM,
                f"{subject} is disabled in the development profile: {enforcement} is not in "
                f"force here.",
            )
        return PostureOutcome.FAIL, Severity.HIGH, f"{failure} ({subject} is disabled)."

    return rule


# --- the rules -----------------------------------------------------------------

#: Every control in the registry has exactly one rule — a test asserts the sets are
#: equal, so a control cannot be added to the register and quietly left unevaluated.
POSTURE_RULES: Mapping[str, PostureRule] = {
    "JDL-AUTHN-01": _gate_rule(
        section="authentication",
        subject="require_authentication",
        enforcement=(
            "Inbound tokens are validated against the issuer's JWKS and must match "
            "audience, algorithm and expiry before a principal exists"
        ),
        failure="Authentication is not required, so a request can reach a handler without a "
        "validated principal",
    ),
    "JDL-AUTHN-02": _gate_rule(
        section="authentication",
        subject="enabled",
        enforcement="Request credentials are parsed into a principal before dispatch",
        failure="Credential parsing is disabled, so requests carry no authenticated identity",
    ),
    "JDL-AUTHN-03": lambda config, evidence: (
        PostureOutcome.NOT_APPLICABLE,
        Severity.INFO,
        "This validator keeps no server-side session, so there is no session state to replay; "
        "token lifetime and audience checks are what bound a stolen token.",
    ),
    "JDL-AUTHZ-01": lambda config, evidence: _policy_outcome(config, evidence),
    "JDL-AUTHZ-02": lambda config, evidence: (
        (
            PostureOutcome.WARN,
            Severity.MEDIUM,
            "authorization.allow_all is set in the development profile, so decisions are "
            "granted without consulting policy.",
        )
        if config.authorization.allow_all and _profile_allows_unsafe(config)
        else (
            PostureOutcome.FAIL,
            Severity.CRITICAL,
            "authorization.allow_all is set outside a development profile: policy decisions "
            "are granted without being evaluated.",
        )
        if config.authorization.allow_all
        else (
            PostureOutcome.FAIL,
            Severity.HIGH,
            "Authorization does not fail closed, so a policy engine outage could turn into "
            "permission rather than refusal.",
        )
        if not config.authorization.fail_closed or not config.authorization.require_authorization
        else (
            PostureOutcome.PASS,
            Severity.INFO,
            "Authorization is required and fails closed: an engine error or timeout refuses the "
            "request instead of allowing it.",
        )
    ),
    "JDL-AUTHZ-03": lambda config, evidence: (
        PostureOutcome.PASS,
        Severity.INFO,
        "Privilege expiry is enforced at every privileged gate — raw SQL, hard delete, "
        "tenant_id updates and the relocation fence — through one refusal helper, so a lapsed "
        "privilege cannot authorise work.",
    ),
    "JDL-GW-01": lambda config, evidence: (
        (
            PostureOutcome.PASS,
            Severity.INFO,
            "Gateway identity headers are trusted only when accompanied by a signed envelope, "
            "so a client cannot forge them by calling the service directly.",
        )
        if config.gateway.require_identity_envelope
        else (
            PostureOutcome.FAIL,
            Severity.HIGH,
            "Gateway identity headers are trusted without a signed envelope: a caller that "
            "reaches the service directly can forge identity.",
        )
    )
    if config.gateway.trust_identity_headers
    else (
        PostureOutcome.NOT_APPLICABLE,
        Severity.INFO,
        "This deployment does not trust gateway identity headers, so the gateway trust model "
        "does not apply here.",
    ),
    "JDL-GW-02": lambda config, evidence: (
        (
            PostureOutcome.WARN,
            Severity.MEDIUM,
            "Identity headers are trusted here, and the alternative gateway's plugin execution "
            "cannot be verified against its OSS image: the adapter is unit-tested only.",
        )
        if config.gateway.trust_identity_headers
        else (
            PostureOutcome.NOT_APPLICABLE,
            Severity.INFO,
            "No gateway identity trust is configured, so alternate-gateway verification does "
            "not apply here.",
        )
    ),
    "JDL-SQL-01": lambda config, evidence: (
        PostureOutcome.PASS,
        Severity.INFO,
        "The raw_sql gate parses a statement and requires it to name the bound tenant before "
        "execution; a statement that does not is refused.",
    ),
    "JDL-ISO-01": lambda config, evidence: _isolation_outcome(evidence),
    "JDL-ISO-02": lambda config, evidence: (
        PostureOutcome.PASS,
        Severity.INFO,
        "Tenant-routed work runs through a session bound to one tenant context, and the "
        "request-scoped authorization cache cannot outlive that context.",
    ),
    "JDL-AUDIT-01": _gate_rule(
        section="audit",
        subject="enabled",
        enforcement="Security events are written to the audit trail with an actor and time",
        failure="The audit trail is switched off, so security events are not recorded",
    ),
    "JDL-AUDIT-02": lambda config, evidence: (
        PostureOutcome.PASS,
        Severity.INFO,
        "Reading and exporting the trail requires its own authorization decision: the writer "
        "path cannot read it back.",
    ),
    "JDL-AUDIT-03": lambda config, evidence: (
        PostureOutcome.WARN,
        Severity.MEDIUM,
        "Tamper-evident storage is not provided by this library by design: an actor with "
        "database access can rewrite history, so the deployment owns that control.",
    ),
    "JDL-SECRET-01": lambda config, evidence: (
        PostureOutcome.PASS,
        Severity.INFO,
        "Error responses, logs, spans and audit metadata pass through one redaction path, so a "
        "credential-shaped value is redacted rather than stored or emitted.",
    ),
    "JDL-CONF-01": lambda config, evidence: _configuration_outcome(evidence),
    "JDL-OBS-01": lambda config, evidence: (
        (PostureOutcome.WARN, Severity.MEDIUM, "debug_security_errors is set in the development "
         "profile: internal security detail is returned to callers here.")
        if config.observability.debug_security_errors and _profile_allows_unsafe(config)
        else (
            PostureOutcome.FAIL,
            Severity.HIGH,
            "debug_security_errors is set outside a development profile: internal security "
            "detail would be returned to callers.",
        )
        if config.observability.debug_security_errors
        else (
            PostureOutcome.WARN,
            Severity.LOW,
            "Trace context is not propagated, so security events cannot be correlated with the "
            "requests that caused them across services.",
        )
        if not config.observability.trace_propagation
        else (
            PostureOutcome.PASS,
            Severity.INFO,
            "Security telemetry is emitted with structured events, bounded metric labels and "
            "propagated trace context.",
        )
    ),
    "JDL-LIFE-01": lambda config, evidence: (
        PostureOutcome.PASS,
        Severity.INFO,
        "Tenant lifecycle transitions run under the same authorization gates as any other "
        "privileged operation and are recorded in the audit trail.",
    ),
    "JDL-SUPPLY-01": lambda config, evidence: _pipeline_outcome(evidence),
}


def _isolation_outcome(
    evidence: tuple[SecurityEvidence, ...],
) -> tuple[PostureOutcome, Severity, str]:
    """Isolation: decided by what the live catalog says, not by the code alone."""
    if not evidence:
        return (
            PostureOutcome.WARN,
            Severity.MEDIUM,
            "Row-level security is implemented in the schema, but no evidence was supplied "
            "for this report: the policies were not observed on a live catalog.",
        )
    missing = _missing_observations(
        evidence,
        "tables_missing_rls",
        "tables_missing_force",
        "tables_missing_policy",
        "tables_unprovisioned",
    )
    if missing:
        return (
            PostureOutcome.WARN,
            Severity.MEDIUM,
            "The isolation evidence is incomplete: it does not report "
            + ", ".join(sorted(missing))
            + ".",
        )
    without_rls: list[str] = []
    without_force: list[str] = []
    without_policy: list[str] = []
    unprovisioned: list[str] = []
    for record in evidence:
        without_rls.extend(_observed_names(record, "tables_missing_rls"))
        without_force.extend(_observed_names(record, "tables_missing_force"))
        without_policy.extend(_observed_names(record, "tables_missing_policy"))
        unprovisioned.extend(_observed_names(record, "tables_unprovisioned"))
    if without_rls or without_force or without_policy or unprovisioned:
        detail = []
        if unprovisioned:
            detail.append(
                "these tables are not provisioned on this schema: " + ", ".join(unprovisioned)
            )
        if without_rls:
            detail.append("row-level security is not enabled on " + ", ".join(without_rls))
        if without_force:
            detail.append("row-level security is not forced on " + ", ".join(without_force))
        if without_policy:
            detail.append("no isolation policy exists on " + ", ".join(without_policy))
        return (
            PostureOutcome.FAIL,
            Severity.HIGH,
            "Tenant isolation is contradicted by the live catalog: " + "; ".join(detail) + ".",
        )
    checked = sum(_observed_count(record, "tables_checked") for record in evidence)
    return (
        PostureOutcome.PASS,
        Severity.INFO,
        f"Row-level security was observed on every tenant-routed table the catalog reports "
        f"({checked} checked), with a policy on each.",
    )


def _policy_outcome(
    config: SecurityConfig, evidence: tuple[SecurityEvidence, ...]
) -> tuple[PostureOutcome, Severity, str]:
    """A decision point with no policy is not a decision point."""
    if not config.authorization.enabled:
        if _profile_allows_unsafe(config):
            return (
                PostureOutcome.WARN,
                Severity.MEDIUM,
                "Authorization is disabled in the development profile: no policy decision is "
                "taken here.",
            )
        return (
            PostureOutcome.FAIL,
            Severity.CRITICAL,
            "Authorization is disabled, so protected routes execute without a policy decision.",
        )
    counts = [
        _observed_count(record, "policy_files")
        for record in evidence
        if "policy_files" in record.observations
    ]
    if counts and not any(counts):
        return (
            PostureOutcome.FAIL,
            Severity.HIGH,
            "The policy decision point was observed with no policy loaded: every decision would "
            "be a denial or an error.",
        )
    if counts:
        return (
            PostureOutcome.PASS,
            Severity.INFO,
            f"The policy decision point was observed with {sum(counts)} policy file(s) loaded, "
            f"and authorization fails closed.",
        )
    return (
        PostureOutcome.PASS,
        Severity.INFO,
        "Protected routes consult the policy decision point through the PEP, and no caller can "
        "route around that decision.",
    )


def _configuration_outcome(
    evidence: tuple[SecurityEvidence, ...],
) -> tuple[PostureOutcome, Severity, str]:
    """Configuration, including whether the live schema matches the checkout."""
    if not evidence:
        return (
            PostureOutcome.WARN,
            Severity.MEDIUM,
            "The configuration is validated when it is built, but no configuration evidence "
            "was supplied for this report.",
        )
    drifted = [
        record
        for record in evidence
        if "at_head" in record.observations and not record.observations.get("at_head")
    ]
    if drifted:
        record = drifted[0]
        applied = record.observations.get("current_revisions") or "nothing"
        return (
            PostureOutcome.FAIL,
            Severity.HIGH,
            f"The live schema does not match the checkout: it has applied {applied} while the "
            f"expected head is {record.observations.get('expected_head')}.",
        )
    return (
        PostureOutcome.PASS,
        Severity.INFO,
        "The security configuration was observed, and every schema checked matches the revision "
        "this checkout expects.",
    )


def _pipeline_outcome(
    evidence: tuple[SecurityEvidence, ...],
) -> tuple[PostureOutcome, Severity, str]:
    """Supply chain: what the repository's own pipeline actually runs."""
    expected = ("dependency_scan", "secret_scan", "static_analysis", "software_bill_of_materials")
    if not evidence:
        return (
            PostureOutcome.WARN,
            Severity.MEDIUM,
            "No pipeline evidence was supplied for this report: dependency, secret, static and "
            "bill-of-materials gates were not observed.",
        )
    missing = _missing_observations(evidence, *expected)
    if missing:
        return (
            PostureOutcome.WARN,
            Severity.MEDIUM,
            "The pipeline evidence is incomplete: it does not report "
            + ", ".join(sorted(missing))
            + ".",
        )
    absent = [
        key
        for key in expected
        if not any(bool(record.observations.get(key)) for record in evidence)
    ]
    if absent:
        return (
            PostureOutcome.FAIL,
            Severity.HIGH,
            "The pipeline runs no " + ", ".join(sorted(absent)) + " gate.",
        )
    return (
        PostureOutcome.PASS,
        Severity.INFO,
        "The pipeline runs dependency, secret, static-analysis and bill-of-materials gates.",
    )


def evaluate_posture(
    config: SecurityConfig,
    *,
    evidence: Iterable[SecurityEvidence] = (),
    rules: Mapping[str, PostureRule] | None = None,
    clock: Clock | None = None,
    environment: str | None = None,
) -> PostureReport:
    """Evaluate every control in the registry against this configuration.

    ``rules`` exists so a caller (and the tests) can document what a missing rule
    would look like; production callers use the module's own set, which covers the
    registry exactly.
    """
    active_rules = POSTURE_RULES if rules is None else rules
    for control_id in CONTROL_REGISTRY:
        if control_id not in active_rules:
            raise ValueError(f"no posture rule for {control_id}")

    routed: dict[str, list[SecurityEvidence]] = {}
    for record in evidence:
        if not isinstance(record, SecurityEvidence):
            raise TypeError(
                f"evidence must be SecurityEvidence, got {type(record).__name__}"
            )
        if control_by_id(record.control_id) is None:
            raise ValueError(f"unknown control: {record.control_id}")
        routed.setdefault(record.control_id, []).append(record)

    findings: list[PostureFinding] = []
    for control_id in sorted(CONTROL_REGISTRY):
        control: Control = CONTROL_REGISTRY[control_id]
        records = tuple(routed.get(control_id, ()))
        outcome, severity, reason = active_rules[control_id](config, records)
        findings.append(
            PostureFinding(
                control_id=control_id,
                outcome=outcome,
                severity=severity,
                title=control.title,
                reason=reason,
                evidence=records,
            )
        )

    return PostureReport(
        findings=tuple(findings),
        generated_at=(clock or SystemClock()).now(),
        environment=environment or config.compliance.environment.value,
    )
