"""The whole chain, over a real socket, in a real server process.

Every other layer drives the application in-process, which is the right way to ask a question about
a *route* and the wrong way to ask whether the documented command works. This file runs the command
the README gives -- `uvicorn examples.enterprise.app.asgi:app` -- as a subprocess, waits for it to
answer, and drives it over TCP: credentials verified by the library's authenticator, the tenant
resolved by the resolver chain, the capability put to the live policy engine, the service, and
PostgreSQL.

What that buys, concretely: the ASGI entry point is exercised as a *process* (a composition that
only works when an event loop is already running, or a module that fails at import, is invisible to
an in-process test), the middleware stack runs the way uvicorn runs it rather than the way
`ASGITransport` runs it, and the readiness probe is answered by a deployment rather than a fixture.

The server is stopped with `SIGTERM` and its exit is asserted, because "graceful shutdown" is a
claim about a process and cannot be measured in one.
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from examples.enterprise.tests.support.environment import (
    CERBOS_ENDPOINT,
    GRAPH_URI,
    RUNTIME_DSN,
    requires_cerbos,
)
from examples.enterprise.tests.support.lab import Caller, Chain, add_caller, row_status

pytestmark = requires_cerbos

REPO_ROOT = Path(__file__).resolve().parents[4]
STARTUP_TIMEOUT = 60.0


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _server_environment() -> dict[str, str]:
    """What the documented command needs, and nothing a test invented.

    The same variables the README tells a reader to export: the runtime DSN the application
    connects with, the policy engine's endpoint, and the context signing key a deployment generates.
    """
    env = dict(os.environ)
    env["JDLIB_CONTROL_DSN"] = RUNTIME_DSN
    env["JDLIB_EXAMPLE_CERBOS_ENDPOINT"] = CERBOS_ENDPOINT
    env.setdefault("JDLIB_CONTEXT__SIGNING_KEY", "0" * 64)
    if GRAPH_URI:
        env["JDLIB_EXAMPLE_GRAPH_URI"] = GRAPH_URI
    return env


#: Windows has no `SIGTERM`: `Popen.send_signal` terminates the process, so its exit status says
#: nothing about the application's shutdown path. The graceful-shutdown assertion is therefore a
#: claim this suite makes on the platforms that have a signal to send -- and says so, rather than
#: asserting something weaker everywhere and calling it the same thing.
SIGTERM_IS_GRACEFUL = os.name == "posix"


class Server:
    """A uvicorn process, its port, and its output -- so a failure can be read."""

    def __init__(self, process: subprocess.Popen[str], port: int) -> None:
        self.process = process
        self.port = port
        self.base_url = f"http://127.0.0.1:{port}"
        self._output = ""

    def stop(self, *, timeout: float = 20.0) -> int:
        """Ask the process to stop the way a supervisor does, and return its exit status."""
        self.process.send_signal(signal.SIGTERM)
        try:
            status = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:  # pragma: no cover - a shutdown that never happened
            self.process.kill()
            self.process.wait(timeout=timeout)
            raise
        self._drain()
        return status

    def _drain(self) -> None:
        """Read what the process said and close the pipe: a pipe left open is a warning at exit."""
        if self.process.stdout is not None and not self.process.stdout.closed:
            self._output = self.process.stdout.read()
            self.process.stdout.close()

    def output(self) -> str:
        if not self._output:
            self._drain()
        return self._output


def _start_server(*, port: int | None = None) -> Server:
    """Start the documented command and wait until it answers its liveness probe."""
    chosen = port or _free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "examples.enterprise.app.asgi:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(chosen),
            "--log-level",
            "warning",
        ],
        cwd=str(REPO_ROOT),
        env=_server_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    server = Server(process, chosen)
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                f"the server exited during startup with {process.returncode}:\n{server.output()}"
            )
        try:
            answer = httpx.get(f"{server.base_url}/healthz", timeout=2.0)
            if answer.status_code == 200:
                return server
        except httpx.HTTPError:
            time.sleep(0.25)
    server.stop()
    raise AssertionError(f"the server did not answer /healthz within {STARTUP_TIMEOUT}s")


@pytest.fixture(scope="module")
def server() -> Iterator[Server]:
    """One server for the module, stopped in teardown -- and asserted to have stopped cleanly."""
    running = _start_server()
    try:
        yield running
    finally:
        exit_status = running.stop()
        if SIGTERM_IS_GRACEFUL:
            assert exit_status == 0, f"the server exited with {exit_status}:\n{running.output()}"


@pytest.fixture(scope="module")
def support_caller(chain: Chain) -> Caller:
    """A caller in alpha's tenant holding `support`: reads, and may not write."""
    return asyncio.run(add_caller(chain.alpha, role="support"))


def _headers(caller: Caller | None) -> dict[str, str]:
    return {"authorization": f"Bearer {caller.token}"} if caller is not None else {}


def test_the_liveness_probe_answers_without_credentials(server: Server) -> None:
    """`/healthz` is the process, and it needs no token: a probe that fails during an outage of the
    identity provider gets the process restarted for it."""
    answer = httpx.get(f"{server.base_url}/healthz", timeout=5.0)
    assert answer.status_code == 200
    assert answer.json() == {"status": "ok"}


def test_the_readiness_probe_asks_the_real_dependencies(server: Server) -> None:
    """`/readyz` executes a statement in the control plane and gets a decision from the engine."""
    answer = httpx.get(f"{server.base_url}/readyz", timeout=10.0)
    assert answer.status_code == 200, answer.text
    assert answer.json() == {"status": "ready"}


def test_an_authenticated_request_traverses_the_whole_chain(server: Server, chain: Chain) -> None:
    """Create and read, over TCP, with a key that is really in the control plane."""
    name = f"e2e-{uuid.uuid4().hex[:6]}"
    created = httpx.post(
        f"{server.base_url}/api/resources",
        json={"name": name, "kind": "dataset"},
        headers=_headers(chain.alpha),
        timeout=15.0,
    )
    assert created.status_code == 201, created.text
    resource_id = created.json()["id"]

    read = httpx.get(
        f"{server.base_url}/api/resources/{resource_id}",
        headers=_headers(chain.alpha),
        timeout=15.0,
    )
    assert read.status_code == 200, read.text
    assert read.json()["name"] == name
    assert read.json()["status"] == "active"


def test_a_denied_request_is_refused_over_the_socket_too(
    server: Server, chain: Chain, support_caller: Caller
) -> None:
    """The denial, through the process: 403, the row untouched, and the trail says so."""
    created = httpx.post(
        f"{server.base_url}/api/resources",
        json={"name": f"e2e-denied-{uuid.uuid4().hex[:6]}", "kind": "dataset"},
        headers=_headers(chain.alpha),
        timeout=15.0,
    )
    resource_id = uuid.UUID(created.json()["id"])

    refused = httpx.delete(
        f"{server.base_url}/api/resources/{resource_id}",
        headers=_headers(support_caller),
        timeout=15.0,
    )
    assert refused.status_code == 403, refused.text
    assert refused.json()["code"] == "PERMISSION_DENIED"
    assert row_status(resource_id) == "active"


def test_an_unauthenticated_request_is_refused_over_the_socket_too(server: Server) -> None:
    answer = httpx.get(f"{server.base_url}/api/whoami", timeout=10.0)
    assert answer.status_code == 401, answer.text
    assert set(answer.json()) == {"code", "message", "request_id", "correlation_id"}


def test_another_tenants_row_is_unreachable_over_the_socket_too(
    server: Server, chain: Chain
) -> None:
    created = httpx.post(
        f"{server.base_url}/api/resources",
        json={"name": f"e2e-iso-{uuid.uuid4().hex[:6]}", "kind": "dataset"},
        headers=_headers(chain.alpha),
        timeout=15.0,
    )
    resource_id = created.json()["id"]

    crossed = httpx.get(
        f"{server.base_url}/api/resources/{resource_id}",
        headers=_headers(chain.beta),
        timeout=15.0,
    )
    assert crossed.status_code == 409, crossed.text
    assert crossed.json()["code"] == "INVALID_REFERENCE"


def test_the_process_stops_on_sigterm_and_exits_clean(chain: Chain) -> None:
    """A second server, stopped the way a supervisor stops one.

    Its own server rather than the module's: this test is about the process ending, and a fixture
    that asserted on its own teardown would report a shutdown failure as whichever test happened to
    run last.
    """
    running = _start_server()
    answer = httpx.get(f"{running.base_url}/healthz", timeout=5.0)
    assert answer.status_code == 200

    exit_status = running.stop()
    assert exit_status is not None, "the process did not end"
    if not SIGTERM_IS_GRACEFUL:
        pytest.skip(
            "Windows has no SIGTERM: the process was terminated rather than asked to stop, so its "
            "exit status says nothing about the shutdown path (this assertion runs on POSIX)"
        )
    assert exit_status == 0, f"the server exited with {exit_status}:\n{running.output()}"


def test_a_server_started_without_its_environment_fails_loudly() -> None:
    """The documented failure: no control plane, no server -- and the reason is in the output.

    A deployment that starts and then fails every request is worse than one that refuses to start,
    so this is asserted rather than assumed: the process exits non-zero, and its output names the
    missing setting.
    """
    env = dict(os.environ)
    for key in ("JDLIB_CONTROL_DSN", "JDLIB_CONTEXT__SIGNING_KEY", "JDLIB_EXAMPLE_CERBOS_ENDPOINT"):
        env.pop(key, None)
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "examples.enterprise.app.asgi:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--log-level",
            "warning",
        ],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60.0,
    )
    assert process.returncode != 0, process.stdout
    combined = f"{process.stdout}\n{process.stderr}".lower()
    assert "jdlib_control_dsn" in combined or "validationerror" in combined, combined[-2000:]
