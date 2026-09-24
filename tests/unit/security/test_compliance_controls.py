"""Phase 9: the control registry is internally consistent and honest.

Three claims are checked here, and each one is the kind that decays silently:

* every control is described well enough for an assessor to act on (a title, a
  description, an owner, a verification method, at least one framework mapping,
  and machine-checkable evidence requirements),
* a gap cannot be recorded without its reason — the register refuses to carry a
  ``PARTIAL`` or ``NOT_IMPLEMENTED`` row that does not explain itself, which is
  the difference between a register and a wish list,
* the evidence a control cites exists in the repository, so a rename or a delete
  cannot leave the register pointing at something that is gone.

The last one is what keeps this file worth running: it turns the registry from
prose into a claim the machine can falsify.
"""

from __future__ import annotations

import pathlib

import pytest

from jdlib.security.compliance import (
    CONTROL_REGISTRY,
    ControlFramework,
    ImplementationStatus,
    control_by_id,
    controls_for_framework,
    frameworks_in_use,
)

REPO_ROOT = pathlib.Path(__file__).parents[3]

#: The frameworks the directive asks the registry to support (directive §9.1).
DIRECTIVE_FRAMEWORKS = frozenset(
    {
        ControlFramework.SOC2,
        ControlFramework.ISO_27001,
        ControlFramework.NIST_CSF,
        ControlFramework.NIST_800_53,
        ControlFramework.OWASP_ASVS,
        ControlFramework.OWASP_API_TOP10,
        ControlFramework.CIS,
    }
)

#: Statuses that describe a gap and therefore require an explanation.
STATUSES_REQUIRING_A_NOTE = frozenset(
    {
        ImplementationStatus.PARTIAL,
        ImplementationStatus.NOT_IMPLEMENTED,
        ImplementationStatus.NOT_APPLICABLE,
    }
)

MINIMUM_NOTE_LENGTH = 40
MINIMUM_REQUIREMENT_LENGTH = 20


def test_every_directive_framework_has_controls() -> None:
    assert set(frameworks_in_use()) >= DIRECTIVE_FRAMEWORKS
    for framework in DIRECTIVE_FRAMEWORKS:
        assert controls_for_framework(framework), f"no control maps onto {framework.value}"


def test_control_ids_are_unique_and_look_like_ids() -> None:
    ids = [control.control_id for control in CONTROL_REGISTRY.values()]
    assert len(ids) == len(set(ids))
    for control_id in ids:
        assert control_id.startswith("JDL-")
        assert control_id.upper() == control_id


def test_every_control_is_described_enough_to_act_on() -> None:
    for control in CONTROL_REGISTRY.values():
        assert control.title.strip(), control.control_id
        assert len(control.description.strip()) >= MINIMUM_REQUIREMENT_LENGTH, control.control_id
        assert control.technical_owner.strip(), control.control_id
        assert control.mappings, f"{control.control_id} has no framework mapping"
        assert control.evidence_requirements, f"{control.control_id} has no evidence requirement"
        for requirement in control.evidence_requirements:
            assert len(requirement.strip()) >= MINIMUM_REQUIREMENT_LENGTH, control.control_id


def test_a_control_maps_onto_a_framework_at_most_once() -> None:
    for control in CONTROL_REGISTRY.values():
        frameworks = [mapping.framework for mapping in control.mappings]
        assert len(frameworks) == len(set(frameworks)), control.control_id
        for mapping in control.mappings:
            assert mapping.reference.strip(), f"{control.control_id}: empty reference"


def test_a_recorded_gap_must_explain_itself() -> None:
    """No silent partials: a status that is not 'implemented' carries its reason."""
    explained = 0
    for control in CONTROL_REGISTRY.values():
        if control.implementation_status in STATUSES_REQUIRING_A_NOTE:
            assert control.status_note, f"{control.control_id} records a gap with no reason"
            assert len(control.status_note.strip()) >= MINIMUM_NOTE_LENGTH, control.control_id
            explained += 1
        else:
            assert control.implementation_status is ImplementationStatus.IMPLEMENTED
    assert explained >= 3, (
        "a register with no recorded gap is suspicious: this library has documented "
        "residual risk (audit tamper-evidence, Tyk verification, pipeline hardening)"
    )


def test_every_cited_evidence_source_exists() -> None:
    for control in CONTROL_REGISTRY.values():
        assert control.evidence_sources, f"{control.control_id} cites no evidence"
        for source in control.evidence_sources:
            path = REPO_ROOT / source
            assert path.exists(), f"{control.control_id} cites missing evidence: {source}"


def test_the_registry_is_read_only() -> None:
    """Callers get a mapping they cannot edit in place."""
    with pytest.raises(TypeError):
        CONTROL_REGISTRY["JDL-ISO-01"] = None  # type: ignore[index]


def test_lookups_agree_with_the_registry() -> None:
    for control_id, control in CONTROL_REGISTRY.items():
        assert control_by_id(control_id) is control
    assert control_by_id("JDL-NOT-A-CONTROL") is None
    for framework in frameworks_in_use():
        found = controls_for_framework(framework)
        assert all(control.mapping_for(framework) is not None for control in found)
        assert set(found) <= set(CONTROL_REGISTRY.values())


def test_repr_does_not_dump_the_prose() -> None:
    text = repr(control_by_id("JDL-ISO-01"))
    assert "Control(" in text
    assert "isolation is enforced by the database" not in text
