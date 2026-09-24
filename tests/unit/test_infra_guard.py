"""The integration layer must report SKIPPED, not FAILED, when Docker is absent.

Why this is a test and not just a conftest line: the decision "may these tests run?" is the
thing that was wrong. Without a guard, a developer with no Docker gets a wall of errors that
read like broken code, and a CI run on a runner without Docker reads like a red build. Both
are false. The decision function is therefore pure and tested in both directions, and the
conftest only calls it.
"""

from __future__ import annotations

import subprocess

from tests.support import infra_guard


def test_returns_none_when_docker_answers(monkeypatch) -> None:
    """Docker available: no reason to skip."""

    class _Ok:
        returncode = 0
        stdout = "25.0.0\n"
        stderr = ""

    monkeypatch.setattr(infra_guard.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(infra_guard.subprocess, "run", lambda *a, **k: _Ok())

    assert infra_guard.docker_unavailable_reason() is None


def test_reports_missing_cli(monkeypatch) -> None:
    """No docker binary: say exactly that, so the reader knows what to install."""
    monkeypatch.setattr(infra_guard.shutil, "which", lambda name: None)

    reason = infra_guard.docker_unavailable_reason()

    assert reason is not None
    assert "docker" in reason.lower()
    assert "not" in reason.lower() or "missing" in reason.lower()


def test_reports_unreachable_daemon(monkeypatch) -> None:
    """Binary present but daemon down: the reason must name the daemon, not the binary."""

    class _Fail:
        returncode = 1
        stdout = ""
        stderr = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.\n"

    monkeypatch.setattr(infra_guard.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(infra_guard.subprocess, "run", lambda *a, **k: _Fail())

    reason = infra_guard.docker_unavailable_reason()

    assert reason is not None
    assert "daemon" in reason.lower()
    assert "Cannot connect" in reason


def test_reports_timeout_without_raising(monkeypatch) -> None:
    """A wedged daemon must produce a skip, not an exception from the guard itself."""
    monkeypatch.setattr(infra_guard.shutil, "which", lambda name: "/usr/bin/docker")

    def _timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="docker info", timeout=10)

    monkeypatch.setattr(infra_guard.subprocess, "run", _timeout)

    reason = infra_guard.docker_unavailable_reason()

    assert reason is not None
    # Assert the contract, not my phrasing: a timeout is reported as an unavailable daemon,
    # names the budget it waited, and does not raise. (The first version of this assertion
    # demanded the literal words "timed out"; the implementation's wording is clearer, so the
    # test was corrected rather than the message.)
    assert "daemon" in reason.lower()
    assert "10s" in reason


def test_reason_is_single_line(monkeypatch) -> None:
    """pytest prints the reason on one line; an embedded newline truncates it confusingly."""

    class _Fail:
        returncode = 1
        stdout = ""
        stderr = "line one\nline two\n"

    monkeypatch.setattr(infra_guard.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(infra_guard.subprocess, "run", lambda *a, **k: _Fail())

    reason = infra_guard.docker_unavailable_reason()

    assert reason is not None
    assert "\n" not in reason
