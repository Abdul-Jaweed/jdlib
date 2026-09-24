"""Phase 9: the security commands work, and they do not overclaim.

The directive's §9.5 asks for three commands that fit the existing CLI, that
never print a secret, and that describe readiness rather than certification. Those
are claims, so this file attacks them:

* the commands exist beside the groups the CLI already had, and the group list is
  still complete,
* ``posture`` exits non-zero when a control fails, so it can gate a pipeline, and
  ``--json`` is structurally usable,
* a policy file's *body* never reaches the output — only its name — which is what
  "never print secrets" has to mean for files this command reads,
* the compliance view says what it is: technical controls and evidence, with a
  disclaimer, and no certification claim anywhere in its output.
"""

from __future__ import annotations

import asyncio
import json

import pytest
import typer

testing = pytest.importorskip("typer.testing")

from jdlib.integrations import cli  # noqa: E402
from jdlib.integrations.cli import app  # noqa: E402


def _invoke(*args: str):
    return testing.CliRunner().invoke(app, list(args))


def test_the_security_group_sits_beside_the_existing_groups() -> None:
    result = _invoke("--help")

    assert result.exit_code == 0, result.output
    for group in ("tenant", "db", "rls", "schema", "security"):
        assert group in result.output


def test_the_security_group_lists_its_three_commands() -> None:
    result = _invoke("security", "--help")

    assert result.exit_code == 0, result.output
    for command in ("posture", "evidence", "compliance"):
        assert command in result.output


def test_posture_reports_the_register_and_the_profile() -> None:
    result = _invoke("security", "posture")

    assert result.exit_code == 0, result.output
    assert "profile=development" in result.output
    assert "JDL-AUTHN-01" in result.output
    assert "JDL-SUPPLY-01" in result.output


def test_posture_json_is_usable_by_a_machine() -> None:
    result = _invoke("security", "posture", "--json", "--environment", "production")

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["environment"] == "production"
    assert len(payload["findings"]) == len(cli.CONTROL_REGISTRY)
    assert {"control_id", "outcome", "severity", "reason"} <= set(payload["findings"][0])


def test_posture_fails_the_command_when_a_control_fails(tmp_path) -> None:
    # An empty policy directory is a decision point with nothing loaded to decide
    # with: the control fails, and a command that can gate a pipeline must say so
    # through its exit code — a warning that keeps the exit code at zero gates
    # nothing.
    result = _invoke("security", "posture", "--policy-directory", str(tmp_path), "--json")

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["is_ready"] is False
    failures = [item for item in payload["findings"] if item["outcome"] == "fail"]
    assert [item["control_id"] for item in failures] == ["JDL-AUTHZ-01"]


def test_a_production_profile_without_evidence_warns_rather_than_fails() -> None:
    result = _invoke("security", "posture", "--json", "--environment", "production")

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["is_ready"] is True
    assert payload["counts"]["warn"] >= 3, "the register's unverified controls stay visible"


def test_an_unknown_profile_is_refused() -> None:
    result = _invoke("security", "posture", "--environment", "not-a-profile")

    assert result.exit_code != 0
    assert "unknown environment" in result.output


def test_evidence_is_structured_and_safe() -> None:
    result = _invoke("security", "evidence", "--json")

    assert result.exit_code == 0, result.output
    records = json.loads(result.output)
    subjects = {record["subject"] for record in records}
    assert "jdlib.security.config.SecurityConfig" in subjects
    assert "jdlib.migrations" in subjects
    for record in records:
        assert record["collected_by"] and record["collected_at"] and record["reproducible"]


def test_a_policy_body_never_reaches_the_output(tmp_path) -> None:
    secret = "cerbos-policy-body-marker-2f8c1a"
    policy = tmp_path / "tenant.yaml"
    policy.write_text(
        f"resourcePolicy:\n  apiVersion: api.cerbos.dev/v1\n# {secret}\n", encoding="utf-8"
    )

    result = _invoke("security", "evidence", "--policy-directory", str(tmp_path), "--json")

    assert result.exit_code == 0, result.output
    assert secret not in result.output
    records = json.loads(result.output)
    policy_record = next(r for r in records if "policy-configuration" in r["subject"])
    assert policy_record["observations"]["policy_files"] == 1
    assert policy_record["observations"]["policy_names"] == ["tenant.yaml"]


def test_the_compliance_view_does_not_claim_certification() -> None:
    result = _invoke("security", "compliance")

    assert result.exit_code == 0, result.output
    text = result.output.lower()
    assert "not a certification" in text
    assert "does not make an organisation certified or compliant" in text
    for forbidden in ("soc 2 certified", "iso certified", "we are compliant"):
        assert forbidden not in text


def test_the_compliance_view_filters_by_framework() -> None:
    result = _invoke("security", "compliance", "--framework", "soc2")

    assert result.exit_code == 0, result.output
    assert "framework=soc2" in result.output
    assert "JDL-ISO-01" in result.output


def test_an_unknown_framework_is_refused() -> None:
    result = _invoke("security", "compliance", "--framework", "iso-9001")

    assert result.exit_code != 0
    assert "unknown framework" in result.output


def test_a_live_collection_without_a_schema_is_refused() -> None:
    # The guard is exercised directly: the rendered usage panel truncates on a
    # narrow console, which is how this test failed in CI while passing locally.
    with pytest.raises(typer.BadParameter, match="--schema"):
        asyncio.run(
            cli._collect_evidence(
                cli.SecurityConfig(),
                database_url="postgresql://user@localhost:5432/jdlib",
                schema=None,
                branch="tenant",
                policy_directory=None,
                pdp_kind="cerbos",
                environment=None,
            )
        )

    result = _invoke(
        "security",
        "posture",
        "--database-url",
        "postgresql://user@localhost:5432/jdlib",
    )

    assert result.exit_code != 0
