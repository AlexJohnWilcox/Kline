"""A path that exists but cannot be opened must not read as healthy."""

import asyncio
import os

import pytest

from siem.collectors.syslog import SyslogCollector

pytestmark = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores file permissions, so chmod 000 proves nothing"
)


async def _pump(collector, seconds=1.5):
    """Run collect() briefly and discard whatever it yields.

    collect() is the bare async generator; only start() (which this helper
    deliberately bypasses, to drive collect() directly like test_pihole.py
    does) flips _running. Set it here so health reads "ok"/"blind" the way
    it would for a running collector, matching the convention test_collector_
    health.py uses (poking _running directly) rather than "stopped".
    """
    async def drain():
        async for _ in collector.collect():
            pass

    collector._running = True
    task = asyncio.create_task(drain())
    await asyncio.sleep(seconds)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_unreadable_path_marks_the_collector_blind(tmp_path):
    log = tmp_path / "gate.log"
    log.write_text("Sep 18 17:18:17 gate dropbear[1]: Bad password attempt\n")
    log.chmod(0o000)

    collector = SyslogCollector(paths=[log])
    # Not started yet (collect() hasn't run), so this only rules out blind
    # at construction — matching test_a_syslog_collector_with_a_real_path_is_
    # not_blind's convention rather than asserting "ok" pre-start.
    assert collector.health != "blind"

    await _pump(collector)

    assert collector.health == "blind"
    assert "gate.log" in (collector.blind_reason or "")


@pytest.mark.asyncio
async def test_the_reason_names_permission_not_just_failure(tmp_path):
    log = tmp_path / "gate.log"
    log.write_text("x\n")
    log.chmod(0o000)

    collector = SyslogCollector(paths=[log])
    await _pump(collector)

    reason = (collector.blind_reason or "").lower()
    assert "permission" in reason


@pytest.mark.asyncio
async def test_blindness_clears_when_the_file_becomes_readable(tmp_path):
    log = tmp_path / "gate.log"
    log.write_text("x\n")
    log.chmod(0o000)

    collector = SyslogCollector(paths=[log])
    await _pump(collector)
    assert collector.health == "blind"

    log.chmod(0o644)
    log.write_text("Sep 18 17:18:17 gate dropbear[1]: Bad password attempt for 'root' from 1.2.3.4:5\n")
    await _pump(collector)

    assert collector.health == "ok"
    assert collector.blind_reason is None


@pytest.mark.asyncio
async def test_a_readable_path_is_never_marked_blind(tmp_path):
    log = tmp_path / "syslog"
    log.write_text("Sep 18 17:18:17 erebus sshd[1]: Accepted publickey for nyx from 1.2.3.4 port 22\n")

    collector = SyslogCollector(paths=[log])
    await _pump(collector)

    assert collector.health == "ok"


@pytest.mark.asyncio
async def test_one_unreadable_path_among_several_still_reports_blind(tmp_path):
    good = tmp_path / "syslog"
    good.write_text("Sep 18 17:18:17 erebus sshd[1]: Accepted publickey for nyx from 1.2.3.4 port 22\n")
    bad = tmp_path / "gate.log"
    bad.write_text("x\n")
    bad.chmod(0o000)

    collector = SyslogCollector(paths=[good, bad])
    await _pump(collector)

    # Half-blind is still blind: a feed silently missing is the whole defect.
    assert collector.health == "blind"
    assert "gate.log" in (collector.blind_reason or "")


def test_clear_blind_is_idempotent():
    collector = SyslogCollector(paths=[])
    collector.clear_blind()
    assert collector.blind_reason is None
    collector.mark_blind("something")
    assert collector.health == "blind"
    collector.clear_blind()
    collector.clear_blind()
    assert collector.blind_reason is None
