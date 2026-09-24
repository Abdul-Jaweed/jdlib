"""Phase 9: evidence is structured, attributable, safe and reproducible.

The directive's §9.3 asks for four properties and one prohibition: evidence must
be structured, timestamped, attributable and safe, and it must not collect
secrets. Each of those is a claim about code, so each is attacked here rather
than asserted in prose:

* a credential placed in an observation is redacted by the shared sanitiser, and
  the serialized record contains no secret-shaped text at all,
* the configuration collector can only report facts on its allow-list, so a
  configuration field added later cannot leak into a report unreviewed,
* a record with no attribution, a blank reproducible step, or an observations
  payload that is nested or oversized is refused rather than stored,
* ``repr`` prints keys, not values, and the values never appear in it.

The migration collector's job is to record what this checkout *expects*; the
branch it reads must therefore have exactly one head, and a branch with two is an
error rather than a silent choice.
"""

from __future__ import annotations

import json
import pathlib
import uuid
from datetime import UTC, datetime

import pytest

from jdlib.security.compliance import (
    CONFIGURATION_EVIDENCE_KEYS,
    MIGRATION_BRANCHES,
    SecurityEvidence,
    collect_configuration_evidence,
    collect_migration_evidence,
)
from jdlib.security.config import (
    AuthorizationConfig,
    ObservabilityConfig,
    SecurityConfig,
)
from jdlib.security.redaction import REDACTED, redact_text

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


class Clock:
    def now(self) -> datetime:
        return NOW


def _evidence(**overrides: object) -> SecurityEvidence:
    fields: dict[str, object] = {
        "control_id": "JDL-CONF-01",
        "subject": "jdlib.security.config.SecurityConfig",
        "collected_by": "jdlib.security.compliance.collect_configuration_evidence",
        "collected_at": NOW,
        "observations": {"audit_enabled": True},
        "reproducible": "call the collector",
    }
    fields.update(overrides)
    return SecurityEvidence(**fields)  # type: ignore[arg-type]


# --- the record itself ---------------------------------------------------------


def test_a_record_without_attribution_is_refused() -> None:
    with pytest.raises(ValueError, match="collected_by"):
        _evidence(collected_by="   ")
    with pytest.raises(ValueError, match="reproducible"):
        _evidence(reproducible="")
    with pytest.raises(ValueError, match="subject"):
        _evidence(subject="")


def test_a_credential_shaped_observation_is_redacted() -> None:
    record = _evidence(
        observations={
            "declared_environment": "production",
            "note": "connected with postgres://app:hunter2@db.internal:5432/jdlib",
            "client_secret": "not-shaped-like-a-secret-but-named-like-one",
        }
    )

    # The credential is removed from the sentence rather than the sentence being
    # dropped: an evidence reader still learns what was observed, and never the
    # credential. A value under a credential-*named* key is redacted whole.
    assert "hunter2" not in str(record.observations["note"])
    assert REDACTED in str(record.observations["note"])
    assert record.observations["client_secret"] == REDACTED
    assert record.observations["declared_environment"] == "production"
    serialized = json.dumps(record.as_dict())
    assert "hunter2" not in serialized
    assert "db.internal" not in serialized


def test_the_serialized_record_contains_no_secret_shaped_text() -> None:
    # Redacting a record again must change nothing — that is what "safe" means.
    serialized = json.dumps(_evidence(observations={"note": "nothing sensitive here"}).as_dict())
    assert redact_text(serialized) == serialized


def test_nested_or_oversized_observations_are_refused() -> None:
    with pytest.raises(ValueError):
        _evidence(observations={"nested": {"depth": 1}})
    with pytest.raises(ValueError):
        _evidence(observations={"long": "x" * 2000})


def test_repr_prints_keys_and_not_values() -> None:
    record = _evidence(observations={"declared_environment": "production"})
    text = repr(record)
    assert "declared_environment" in text
    assert "production" not in text


def test_a_record_carries_its_own_identifier() -> None:
    first, second = _evidence(), _evidence()
    assert isinstance(first.evidence_id, uuid.UUID)
    assert first.evidence_id != second.evidence_id


# --- the configuration collector ----------------------------------------------


def test_the_configuration_collector_reports_only_allow_listed_facts() -> None:
    record = collect_configuration_evidence(SecurityConfig(), clock=Clock())

    assert set(record.observations) <= CONFIGURATION_EVIDENCE_KEYS
    assert set(record.observations) == CONFIGURATION_EVIDENCE_KEYS


def test_the_configuration_collector_reflects_the_posture() -> None:
    permissive = SecurityConfig(
        authorization=AuthorizationConfig(allow_all=True),
        observability=ObservabilityConfig(debug_security_errors=True),
    )
    record = collect_configuration_evidence(permissive, clock=Clock())

    assert record.observations["authorization_allow_all"] is True
    assert record.observations["debug_security_errors"] is True
    assert record.observations["authentication_required"] is True
    assert record.observations["authorization_fail_closed"] is True
    assert record.observations["tenant_header_trusted"] is False
    assert record.observations["gateway_identity_headers_trusted"] is False
    assert record.observations["declared_environment"] == "development"


def test_the_configuration_collector_is_timestamped_by_its_clock() -> None:
    record = collect_configuration_evidence(SecurityConfig(), clock=Clock())
    assert record.collected_at == NOW
    assert record.collected_by == "jdlib.security.compliance.collect_configuration_evidence"


# --- the migration collector ---------------------------------------------------


def test_migration_evidence_records_one_head_per_branch() -> None:
    record = collect_migration_evidence(clock=Clock())

    for branch in MIGRATION_BRANCHES:
        head = record.observations[f"{branch}_head"]
        revisions = record.observations[f"{branch}_revisions"]
        assert isinstance(head, str) and head
        assert isinstance(revisions, list)
        assert head in revisions
        assert record.observations[f"{branch}_revision_count"] == len(revisions)
    assert record.observations["tenant_revision_count"] >= 2, "traversal must find them all"


def test_migration_evidence_refuses_a_branch_with_two_heads(tmp_path: pathlib.Path) -> None:
    versions = tmp_path / "tenant" / "versions"
    versions.mkdir(parents=True)
    (versions / "0001_one.py").write_text(
        'revision = "a"\ndown_revision = None\n', encoding="utf-8"
    )
    (versions / "0002_two.py").write_text(
        'revision = "b"\ndown_revision = None\n', encoding="utf-8"
    )

    with pytest.raises(ValueError, match="exactly one head"):
        collect_migration_evidence(root=tmp_path, clock=Clock())


def test_a_migration_file_without_a_revision_is_refused(tmp_path: pathlib.Path) -> None:
    versions = tmp_path / "control" / "versions"
    versions.mkdir(parents=True)
    (versions / "0001_broken.py").write_text("down_revision = None\n", encoding="utf-8")

    with pytest.raises(ValueError, match="no revision identifier"):
        collect_migration_evidence(root=tmp_path, clock=Clock())
