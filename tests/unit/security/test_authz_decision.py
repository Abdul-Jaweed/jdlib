"""Phase 3: authorization decision model (directive §15, §17, spec #21, #35).

The decision model is framework- and vendor-neutral: nothing here imports
Cerbos, FastAPI or any transport, so business code can depend on it without
knowing which policy engine is behind it.

Invariants under test:

* a decision is immutable and can never be "allowed" without an explicit
  ALLOW effect, so a mapping mistake cannot fail open,
* a decision that was taken without a policy engine (unavailable, timeout,
  malformed response) is marked degraded and is **never** allowed,
* what leaves the decision toward clients/audit is a small, safe metadata set
  (decision, policy id, policy version, timestamp, reason) — never raw
  attributes or internal policy internals (directive §17),
* attribute values are defensively copied and never appear in ``repr``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import MappingProxyType

import pytest

from jdlib.security.authz.decision import (
    AuthorizationDecision,
    AuthorizationQuery,
    Effect,
)

TENANT_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
SECRET_ATTRIBUTE = "confidential-classification-value"


def _query(**overrides: object) -> AuthorizationQuery:
    values: dict[str, object] = {
        "principal_id": "user-1",
        "tenant_id": TENANT_ID,
        "resource_kind": "document",
        "resource_id": "doc-42",
        "actions": ("read",),
        "roles": frozenset({"editor"}),
    }
    values.update(overrides)
    return AuthorizationQuery(**values)  # type: ignore[arg-type]


# --- query -------------------------------------------------------------------


def test_query_is_immutable() -> None:
    from dataclasses import FrozenInstanceError

    query = _query()
    with pytest.raises(FrozenInstanceError):
        query.resource_id = "other"  # type: ignore[misc]


def test_query_requires_at_least_one_action() -> None:
    with pytest.raises(ValueError):
        _query(actions=())


def test_query_requires_a_resource_and_principal() -> None:
    with pytest.raises(ValueError):
        _query(principal_id="")
    with pytest.raises(ValueError):
        _query(resource_kind="")
    with pytest.raises(ValueError):
        _query(resource_id="")


def test_query_copies_attributes_defensively() -> None:
    source = {"classification": SECRET_ATTRIBUTE}
    query = _query(attributes=source)
    source["classification"] = "mutated-after-construction"
    assert query.attributes["classification"] == SECRET_ATTRIBUTE
    assert isinstance(query.attributes, MappingProxyType)
    with pytest.raises(TypeError):
        query.attributes["classification"] = "mutated"  # type: ignore[index]


def test_query_repr_hides_attribute_values() -> None:
    query = _query(attributes={"classification": SECRET_ATTRIBUTE})
    text = f"{query!r} {query}"
    assert SECRET_ATTRIBUTE not in text
    assert "doc-42" in text


# --- decision: fail-closed construction --------------------------------------


def test_decision_is_immutable() -> None:
    from dataclasses import FrozenInstanceError

    decision = AuthorizationDecision.allow(decided_at=NOW)
    with pytest.raises(FrozenInstanceError):
        decision.allowed = False  # type: ignore[misc]


def test_an_allowed_decision_requires_an_allow_effect() -> None:
    with pytest.raises(ValueError):
        AuthorizationDecision(allowed=True, effect=Effect.DENY, decided_at=NOW)


def test_a_degraded_decision_can_never_be_allowed() -> None:
    with pytest.raises(ValueError):
        AuthorizationDecision(allowed=True, effect=Effect.ALLOW, decided_at=NOW, degraded=True)


def test_allow_and_deny_factories() -> None:
    allowed = AuthorizationDecision.allow(
        decided_at=NOW, policy_id="document", policy_version="default"
    )
    assert allowed.allowed is True
    assert allowed.effect is Effect.ALLOW
    assert allowed.degraded is False
    denied = AuthorizationDecision.deny(reason="no_allow", decided_at=NOW)
    assert denied.allowed is False
    assert denied.effect is Effect.DENY
    assert denied.reason == "no_allow"


def test_unavailable_is_degraded_and_denied() -> None:
    decision = AuthorizationDecision.unavailable(reason="engine_unavailable", decided_at=NOW)
    assert decision.allowed is False
    assert decision.degraded is True
    assert decision.policy_id is None
    assert decision.reason == "engine_unavailable"


# --- decision: what may leave the boundary (directive §17) -------------------


def test_safe_metadata_exposes_only_the_allowed_keys() -> None:
    decision = AuthorizationDecision.deny(
        reason="no_allow",
        decided_at=NOW,
        policy_id="document",
        policy_version="default",
        denied_actions=("delete",),
    )
    metadata = decision.safe_metadata()
    assert set(metadata) == {"decision", "policy_id", "policy_version", "decided_at", "reason"}
    assert metadata["decision"] == "DENY"
    assert metadata["policy_id"] == "document"
    assert metadata["policy_version"] == "default"
    assert metadata["decided_at"] == NOW.isoformat()
    assert "delete" not in str(metadata)  # action names stay out of client metadata


def test_safe_metadata_of_an_unavailable_decision() -> None:
    metadata = AuthorizationDecision.unavailable(
        reason="engine_unavailable", decided_at=NOW
    ).safe_metadata()
    assert metadata["decision"] == "DENY"
    assert metadata["policy_id"] == ""
    assert metadata["policy_version"] == ""


def test_decision_repr_is_safe() -> None:
    decision = AuthorizationDecision.deny(
        reason="no_allow",
        decided_at=NOW,
        policy_id="document",
        policy_version="default",
        denied_actions=("delete",),
    )
    assert "document" in repr(decision)
    assert "DENY" in repr(decision)


def test_denied_actions_are_captured_but_keep_their_order() -> None:
    decision = AuthorizationDecision.deny(
        reason="no_allow", decided_at=NOW, denied_actions=("write", "delete")
    )
    assert decision.denied_actions == ("write", "delete")
    assert decision.allowed is False


def test_a_deny_with_no_denied_actions_is_still_a_deny() -> None:
    # Cerbos DENY results (explicit policy deny) need not name a failing action.
    decision = AuthorizationDecision.deny(reason="explicit_deny", decided_at=NOW)
    assert decision.allowed is False
    assert decision.denied_actions == ()
