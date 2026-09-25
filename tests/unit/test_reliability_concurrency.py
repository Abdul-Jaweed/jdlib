"""A bounded number of operations at once, refusing rather than queueing without limit (§22, §25).

§25 asks for concurrency control and §22 for rate limits where required; the reliability package
already owns retries, backoff, budgets, breaking and shutdown, and has no concurrency primitive.
Extending that package rather than inventing one beside it is the programme's rule, so the gate
lives there.

Two decisions shape it:

* **the bound is stated, never defaulted.** A gate constructed without a limit is a gate that
  admits everything, and "we forgot to configure it" is not a failure mode a limiter should have;
* **waiting is bounded too.** A saturated gate that queues forever converts an overload into a
  hang: the caller cannot tell "busy" from "broken", and the work behind it ages. The gate waits
  up to a declared deadline and then refuses — fail-closed, with the caller told which it was.

Release happens on the way out whether the body succeeded or raised, because a limiter that leaks
a slot on the error path is a limiter that permanently shrinks under exactly the load it exists
for.
"""

from __future__ import annotations

import asyncio

import pytest

from jdlib.reliability.concurrency import ConcurrencyGate, ConcurrencyLimitError


async def test_the_gate_admits_up_to_its_limit() -> None:
    gate = ConcurrencyGate(limit=2, wait_timeout=0.05)
    async with gate, gate:
        assert gate.in_flight == 2
    assert gate.in_flight == 0


async def test_the_gate_refuses_a_waiter_rather_than_queueing_forever() -> None:
    """Saturation is an answer, not a hang.

    The outer `wait_for` is the test's own guard: an implementation that queues forever would
    otherwise hang the whole suite instead of failing this test, and a mutation probe cannot
    tell those apart without it.
    """
    gate = ConcurrencyGate(limit=1, wait_timeout=0.05)

    async def second_entry() -> None:
        async with gate:
            pytest.fail("the second entry must not be admitted")

    async with gate:
        with pytest.raises(ConcurrencyLimitError):
            await asyncio.wait_for(second_entry(), timeout=1.0)


async def test_the_gate_releases_a_slot_when_the_body_raises() -> None:
    """A limiter that leaks on the error path shrinks under the load it exists for."""
    gate = ConcurrencyGate(limit=1, wait_timeout=0.05)
    with pytest.raises(RuntimeError):
        async with gate:
            raise RuntimeError("the body failed")
    assert gate.in_flight == 0
    async with gate:
        assert gate.in_flight == 1


async def test_a_slot_freed_while_another_waits_is_taken_by_the_waiter() -> None:
    gate = ConcurrencyGate(limit=1, wait_timeout=1.0)
    order: list[str] = []

    async def holder() -> None:
        async with gate:
            order.append("first")
            await asyncio.sleep(0.02)

    async def waiter() -> None:
        await asyncio.sleep(0.005)
        async with gate:
            order.append("second")

    await asyncio.gather(holder(), waiter())
    assert order == ["first", "second"]


async def test_the_bound_is_stated_not_inherited() -> None:
    with pytest.raises(ValueError):
        ConcurrencyGate(limit=0, wait_timeout=0.05)
    with pytest.raises(ValueError):
        ConcurrencyGate(limit=-1, wait_timeout=0.05)
    with pytest.raises(ValueError):
        ConcurrencyGate(limit=1, wait_timeout=0)


async def test_the_wait_is_bounded_by_the_declared_deadline() -> None:
    """A short deadline refuses sooner than a long one — the parameter is the control."""
    gate = ConcurrencyGate(limit=1, wait_timeout=0.02)

    async def second_entry() -> None:
        async with gate:
            pytest.fail("must not be admitted")

    async with gate:
        loop = asyncio.get_running_loop()
        started = loop.time()
        with pytest.raises(ConcurrencyLimitError):
            await asyncio.wait_for(second_entry(), timeout=1.0)
        waited = loop.time() - started
    assert waited < 0.2, f"the refusal took {waited:.3f}s, so the deadline is not the control"
