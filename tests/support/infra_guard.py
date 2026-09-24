"""One place that answers "can the integration layer run here?", with a reason if not.

The integration tests start real containers. When Docker is missing — a developer laptop, a
locked-down runner — the honest report is SKIPPED with a precise reason. An error wall reads
as broken code and a red build reads as a broken change; both are false, and both train people
to ignore the signal.

Pure decision, no side effects, so it is unit-tested in both directions and the conftest only
has to call it.
"""

from __future__ import annotations

import shutil
import subprocess

DOCKER_PROBE_TIMEOUT_SECONDS = 10


def docker_unavailable_reason() -> str | None:
    """Return a one-line reason to skip integration tests, or ``None`` if Docker is usable.

    Every returned string is single-line: pytest prints a skip reason inline, and an embedded
    newline truncates the explanation at exactly the point that would have been useful.
    """
    if shutil.which("docker") is None:
        return (
            "the docker CLI is not on PATH, so the containers this layer needs cannot be "
            "started (install docker, or run only the unit layer)"
        )

    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=DOCKER_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return (
            f"the docker daemon did not answer within {DOCKER_PROBE_TIMEOUT_SECONDS}s, so it is "
            "treated as unavailable (a wedged daemon is a skip, not a test failure)"
        )
    except OSError as exc:
        return (
            f"the docker CLI could not be executed ({type(exc).__name__}), so container-backed "
            "tests cannot run"
        )

    if result.returncode != 0:
        lines = (result.stderr or result.stdout or "").strip().splitlines()
        detail = lines[0] if lines else f"exit code {result.returncode}"
        return f"the docker daemon is not reachable: {detail}"

    return None
