"""Phase 9: posture outcomes are earned, explained and impossible to hide.

The directive's §9.4 asks for four outcomes, an explanation on every finding, and
structure rather than a status page. Those are claims about code, so they are
attacked:

* each of the four outcomes is exercised, including the two that are easy to
  fake: a **failure** for a control that should be in force and is not, and a
  **not-applicable** for a control whose subject does not exist here,
* a finding without an explanation, a finding that cites another control's
  evidence, a finding for an unknown control, and a report that states one
  control twice are all refused rather than rendered,
* an incomplete evidence payload downgrades the finding to a warning that names
  what is missing — it never crashes and never silently passes,
* every registry control appears exactly once, in a deterministic order, and the
  serialized report carries no observation values and no secret-shaped text.

One property is worth stating plainly: the production profile *refuses to
construct* an unsafe configuration (Phase 1 validation), so the failures this
layer reports are the ones that can actually exist — a non-production profile, or
a control whose evidence is missing in a deployment that claims to be production.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from jdlib.security.compliance import (
    CONTROL_REGISTRY,
    SecurityEvidence,
    collect_configuration_evidence,
)
from jdlib.security.compliance.posture import (
    POSTURE_RULES,
    PostureFinding,
    PostureOutcome,
    PostureReport,
    Severity,
    evaluate_posture,
)
from jdlib.security.config import (
    AuditConfig,
    AuthenticationConfig,
    AuthorizationConfig,
    ComplianceConfig,
    Environment,
    GatewayConfig,
    ObservabilityConfig,
    SecurityConfig,
)
from jdlib.security.errors import SecurityConfigurationError

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


class Clock:
    def now(self) -> datetime:
        return NOW


def _production(**overrides: object) -> SecurityConfig:
    return SecurityConfig(
        compliance=ComplianceConfig(environment=Environment.PRODUCTION), **overrides  # type: ignore[arg-type]
    )


def _staging(**overrides: object) -> SecurityConfig:
    return SecurityConfig(
        compliance=ComplianceConfig(environment=Environment.STAGING), **overrides  # type: ignore[arg-type]
    )


def _evidence(control_id: str, **observations: object) -> SecurityEvidence:
    return SecurityEvidence(
        control_id=control_id,
        subject=f"test:{control_id}",
        collected_by="tests.unit.security.test_compliance_posture",
        collected_at=NOW,
        observations={"probe": True, **observations},
        reproducible="re-run the test",
    )


def _config_evidence(config: SecurityConfig) -> SecurityEvidence:
    return collect_configuration_evidence(config, clock=Clock())


def _rls_evidence(**observations: object) -> SecurityEvidence:
    fields: dict[str, object] = {
        "tables_checked": 4,
        "tables_enforced": 4,
        "tables_missing_rls": [],
        "tables_missing_force": [],
        "tables_missing_policy": [],
        "tables_unprovisioned": [],
        "is_enforced": True,
    }
    fields.update(observations)
    return _evidence("JDL-ISO-01", **fields)


def _pipeline_evidence(**observations: object) -> SecurityEvidence:
    return _evidence(
        "JDL-SUPPLY-01",
        dependency_scan=True,
        secret_scan=True,
        static_analysis=True,
        software_bill_of_materials=True,
        **observations,
    )


def _report(
    config: SecurityConfig, *, evidence: tuple[SecurityEvidence, ...] = ()
) -> PostureReport:
    return evaluate_posture(config, evidence=evidence, clock=Clock())


def _finding(report: PostureReport, control_id: str) -> PostureFinding:
    matches = [finding for finding in report.findings if finding.control_id == control_id]
    assert matches, f"{control_id} missing from the report"
    return matches[0]


# --- the vocabulary and the coverage -------------------------------------------


def test_the_outcomes_are_exactly_the_four_the_directive_names() -> None:
    assert {outcome.value for outcome in PostureOutcome} == {
        "pass",
        "warn",
        "fail",
        "not_applicable",
    }


def test_every_registry_control_is_evaluated_exactly_once() -> None:
    report = _report(_production())

    assert [finding.control_id for finding in report.findings] == sorted(CONTROL_REGISTRY)
    assert set(POSTURE_RULES) == set(CONTROL_REGISTRY), "no control may be silently unevaluated"


def test_a_missing_rule_for_a_registry_control_is_refused() -> None:
    partial = dict(POSTURE_RULES)
    partial.pop("JDL-ISO-01")

    with pytest.raises(ValueError, match="JDL-ISO-01"):
        evaluate_posture(_production(), rules=partial, clock=Clock())


# --- the four outcomes ---------------------------------------------------------


def test_a_clean_production_profile_has_no_failure() -> None:
    config = _production()
    report = _report(
        config, evidence=(_config_evidence(config), _rls_evidence(), _pipeline_evidence())
    )

    assert report.is_ready is True
    assert report.worst_outcome is PostureOutcome.WARN, "the register's own gaps stay visible"
    assert report.counts[PostureOutcome.PASS] >= 10
    assert _finding(report, "JDL-AUTHN-01").outcome is PostureOutcome.PASS
    assert _finding(report, "JDL-AUTHZ-01").outcome is PostureOutcome.PASS
    assert _finding(report, "JDL-AUDIT-01").outcome is PostureOutcome.PASS


def test_a_control_that_should_be_in_force_and_is_not_fails() -> None:
    report = _report(_staging(authorization=AuthorizationConfig(allow_all=True)))

    finding = _finding(report, "JDL-AUTHZ-02")
    assert finding.outcome is PostureOutcome.FAIL
    assert finding.severity is Severity.CRITICAL
    assert "allow_all" in finding.reason
    assert report.is_ready is False


def test_the_same_unsafe_combination_warns_in_development() -> None:
    development = SecurityConfig(authorization=AuthorizationConfig(allow_all=True))
    report = _report(development)

    finding = _finding(report, "JDL-AUTHZ-02")
    assert finding.outcome is PostureOutcome.WARN
    assert finding.severity is Severity.MEDIUM
    assert "development" in finding.reason


def test_production_refuses_to_construct_the_profiles_that_would_fail() -> None:
    # Why the FAIL cases above live in non-production profiles: production cannot
    # be built this way at all. Posture reports what can exist.
    with pytest.raises(SecurityConfigurationError, match="allow-all"):
        _production(authorization=AuthorizationConfig(allow_all=True))
    with pytest.raises(SecurityConfigurationError, match="authentication"):
        _production(authentication=AuthenticationConfig(require_authentication=False))
    with pytest.raises(SecurityConfigurationError, match="debug"):
        _production(observability=ObservabilityConfig(debug_security_errors=True))


def test_a_control_whose_subject_does_not_exist_here_is_not_applicable() -> None:
    report = _report(_production())

    gateway = _finding(report, "JDL-GW-01")
    assert gateway.outcome is PostureOutcome.NOT_APPLICABLE
    assert gateway.severity is Severity.INFO
    assert "headers" in gateway.reason

    replay = _finding(report, "JDL-AUTHN-03")
    assert replay.outcome is PostureOutcome.NOT_APPLICABLE


def test_an_unsigned_gateway_trust_model_cannot_be_constructed() -> None:
    # The gateway trust model is guarded when the configuration is built, in every
    # profile — so the failure the posture rule describes cannot arise by accident.
    with pytest.raises(SecurityConfigurationError, match="signed identity envelope"):
        _staging(
            gateway=GatewayConfig(trust_identity_headers=True, require_identity_envelope=False)
        )


def test_the_gateway_rule_still_fails_a_profile_that_bypassed_validation() -> None:
    # Defence in depth: an object built around the validator still cannot pass
    # posture. This is the one case where a FAIL is reachable for this control.
    bypassed = _staging().model_copy(
        update={
            "gateway": GatewayConfig(
                trust_identity_headers=True, require_identity_envelope=False
            )
        }
    )
    finding = _finding(_report(bypassed), "JDL-GW-01")

    assert finding.outcome is PostureOutcome.FAIL
    assert finding.severity is Severity.HIGH


def test_a_construction_enforced_control_passes_and_names_its_enforcement_point() -> None:
    report = _report(_production())

    # The raw-SQL gate and the privilege gates live in code paths a caller cannot
    # route around, so they are observable from the checkout itself.
    for control_id, needle in (
        ("JDL-SQL-01", "raw_sql"),
        ("JDL-AUTHZ-03", "privilege"),
        ("JDL-SECRET-01", "redact"),
    ):
        finding = _finding(report, control_id)
        assert finding.outcome is PostureOutcome.PASS, control_id
        assert needle in finding.reason.lower(), control_id


# --- evidence drives outcomes --------------------------------------------------


def test_missing_evidence_warns_instead_of_passing_silently() -> None:
    report = _report(_production())

    isolation = _finding(report, "JDL-ISO-01")
    assert isolation.outcome is PostureOutcome.WARN
    assert "evidence" in isolation.reason

    configuration = _finding(report, "JDL-CONF-01")
    assert configuration.outcome is PostureOutcome.WARN

    assert _finding(report, "JDL-SUPPLY-01").outcome is PostureOutcome.WARN


def test_isolation_evidence_decides_the_isolation_finding() -> None:
    config = _production()
    clean = _report(config, evidence=(_rls_evidence(),))
    assert _finding(clean, "JDL-ISO-01").outcome is PostureOutcome.PASS

    broken = _report(
        config,
        evidence=(_rls_evidence(tables_with_rls=3, tables_missing_rls=["audit.events"]),),
    )
    finding = _finding(broken, "JDL-ISO-01")
    assert finding.outcome is PostureOutcome.FAIL
    assert finding.severity is Severity.HIGH
    assert "audit.events" in finding.reason
    assert broken.is_ready is False


def test_incomplete_evidence_downgrades_the_finding_and_says_what_is_missing() -> None:
    config = _production()
    incomplete = SecurityEvidence(
        control_id="JDL-ISO-01",
        subject="test:incomplete",
        collected_by="tests.unit.security.test_compliance_posture",
        collected_at=NOW,
        observations={"policies": 3},
        reproducible="re-run the test",
    )

    finding = _finding(_report(config, evidence=(incomplete,)), "JDL-ISO-01")
    assert finding.outcome is PostureOutcome.WARN
    assert "tables_missing_rls" in finding.reason


def test_a_disabled_audit_trail_fails_the_audit_control() -> None:
    # Reads the audit section, not whichever section happens to have an "enabled"
    # flag — a rule that confuses the two would pass here and fail in production.
    report = _report(_staging(audit=AuditConfig(enabled=False)))

    finding = _finding(report, "JDL-AUDIT-01")
    assert finding.outcome is PostureOutcome.FAIL
    assert finding.severity is Severity.HIGH
    assert _finding(report, "JDL-AUTHZ-01").outcome is PostureOutcome.PASS, (
        "disabling the audit trail must not change the authorization finding"
    )


def test_a_decision_point_with_no_policy_is_a_failure() -> None:
    config = _production()
    empty = _evidence(
        "JDL-AUTHZ-01",
        pdp_kind="cerbos",
        policy_files=0,
        policy_names=[],
        policy_directory_found=True,
    )
    observed = _evidence(
        "JDL-AUTHZ-01",
        pdp_kind="cerbos",
        policy_files=2,
        policy_names=["tenant.yaml", "admin.yaml"],
        policy_directory_found=True,
    )

    empty_report = _report(config, evidence=(empty,))
    assert _finding(empty_report, "JDL-AUTHZ-01").outcome is PostureOutcome.FAIL
    assert (
        _finding(_report(config, evidence=(observed,)), "JDL-AUTHZ-01").outcome
        is PostureOutcome.PASS
    )


def test_schema_drift_is_a_failure() -> None:
    config = _production()
    drift = _evidence(
        "JDL-CONF-01",
        branch="tenant",
        table_present=True,
        current_revision="0001_tenant_baseline",
        current_revisions=["0001_tenant_baseline"],
        expected_head="0002_security_audit_columns",
        at_head=False,
    )
    finding = _finding(_report(config, evidence=(drift,)), "JDL-CONF-01")

    assert finding.outcome is PostureOutcome.FAIL
    assert finding.severity is Severity.HIGH
    assert "0002_security_audit_columns" in finding.reason


def test_a_schema_at_the_expected_head_passes() -> None:
    config = _production()
    current = _evidence(
        "JDL-CONF-01",
        branch="tenant",
        table_present=True,
        current_revision="0002_security_audit_columns",
        current_revisions=["0002_security_audit_columns"],
        expected_head="0002_security_audit_columns",
        at_head=True,
    )

    at_head = _report(config, evidence=(current,))
    assert _finding(at_head, "JDL-CONF-01").outcome is PostureOutcome.PASS


def test_evidence_that_is_not_evidence_is_refused() -> None:
    with pytest.raises(TypeError, match="SecurityEvidence"):
        evaluate_posture(
            _production(), evidence=({"tables_missing_rls": []},), clock=Clock()
        )  # type: ignore[arg-type]


def test_the_configuration_finding_records_the_collector_that_observed_it() -> None:
    config = _production()
    evidence = _config_evidence(config)
    finding = _finding(_report(config, evidence=(evidence,)), "JDL-CONF-01")

    assert finding.outcome is PostureOutcome.PASS
    assert finding.evidence == (evidence,)


# --- findings cannot be malformed ----------------------------------------------


@pytest.mark.parametrize("reason", ["", "   ", "too short"])
def test_a_finding_without_an_explanation_is_refused(reason: str) -> None:
    with pytest.raises(ValueError, match="reason"):
        PostureFinding(
            control_id="JDL-ISO-01",
            outcome=PostureOutcome.FAIL,
            severity=Severity.HIGH,
            title="Isolation",
            reason=reason,
        )


def test_a_finding_for_an_unknown_control_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown control"):
        PostureFinding(
            control_id="JDL-NOT-A-CONTROL",
            outcome=PostureOutcome.PASS,
            severity=Severity.INFO,
            title="Invented",
            reason="this is not a control this library claims to have",
        )


def test_a_finding_that_cites_another_controls_evidence_is_refused() -> None:
    with pytest.raises(ValueError, match="evidence"):
        PostureFinding(
            control_id="JDL-ISO-01",
            outcome=PostureOutcome.PASS,
            severity=Severity.INFO,
            title="Isolation",
            reason="isolation was verified against the live catalog",
            evidence=(_config_evidence(_production()),),
        )


def test_a_report_that_states_one_control_twice_is_refused() -> None:
    finding = PostureFinding(
        control_id="JDL-ISO-01",
        outcome=PostureOutcome.PASS,
        severity=Severity.INFO,
        title="Isolation",
        reason="isolation was verified against the live catalog",
    )

    with pytest.raises(ValueError, match="duplicate"):
        PostureReport(
            findings=(finding, finding), generated_at=NOW, environment="production"
        )


# --- determinism and safety ----------------------------------------------------


def test_findings_are_ordered_deterministically() -> None:
    config = _production()
    records = (_rls_evidence(), _config_evidence(config), _pipeline_evidence())
    first = _report(config, evidence=records)
    second = _report(config, evidence=tuple(reversed(records)))

    assert [f.control_id for f in first.findings] == sorted(CONTROL_REGISTRY)
    assert first.as_dict() == second.as_dict(), "input order must not change the report"


def test_a_report_orders_findings_it_was_handed() -> None:
    # The evaluator walks the registry in order, so this is the only place the
    # report's own canonical ordering is observable — and a caller may build one.
    def finding(control_id: str) -> PostureFinding:
        return PostureFinding(
            control_id=control_id,
            outcome=PostureOutcome.PASS,
            severity=Severity.INFO,
            title="title",
            reason="a reason long enough to satisfy the minimum length rule",
        )

    report = PostureReport(
        findings=(finding("JDL-SQL-01"), finding("JDL-AUDIT-01")),
        generated_at=NOW,
        environment="production",
    )

    assert [f.control_id for f in report.findings] == ["JDL-AUDIT-01", "JDL-SQL-01"]


def test_the_report_knows_its_counts_and_worst_outcome() -> None:
    report = _report(_production(), evidence=(_rls_evidence(),))

    assert sum(report.counts.values()) == len(report.findings)
    assert report.counts[PostureOutcome.NOT_APPLICABLE] >= 1
    assert report.worst_outcome in set(PostureOutcome)
    assert report.as_dict()["generated_at"] == NOW.isoformat()


def test_the_serialized_report_is_structured_and_carries_no_observation_values() -> None:
    config = _production()
    report = _report(config, evidence=(_rls_evidence(file_path="C:/secret/location.db"),))
    text = json.dumps(report.as_dict(), sort_keys=True)

    payload = json.loads(text)
    assert payload["findings"][0]["outcome"] in {o.value for o in PostureOutcome}
    assert "C:/secret/location.db" not in text, "observation values stay out of reports"
    assert "location.db" not in text


def test_no_secret_shaped_text_reaches_the_report() -> None:
    config = _production()
    leaky = SecurityEvidence(
        control_id="JDL-SUPPLY-01",
        subject="test:pipeline",
        collected_by="tests.unit.security.test_compliance_posture",
        collected_at=NOW,
        observations={
            "dependency_scan": True,
            "secret_scan": True,
            "static_analysis": True,
            "software_bill_of_materials": True,
            "note": "ran against postgres://app:hunter2@db.internal:5432/jdlib",
        },
        reproducible="re-run the test",
    )
    report = _report(config, evidence=(leaky,))

    assert "hunter2" not in repr(report)
    assert "db.internal" not in json.dumps(report.as_dict())
