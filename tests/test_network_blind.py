"""The network collector must answer "can I read my files?" like syslog does.

network.py's collect loop kept the original unhardened shape the syslog
collector was fixed away from: a `>` size gate that never opens a file which
stops growing, and one broad `except OSError` with no PermissionError branch
and no mark_blind. A /var/log/kern.log that exists but is root:adm 0640 --
the normal permission on Debian-family hosts -- read as "ok". It also never
called clear_blind, so the inverse held too: once blind, blind forever.

It now runs the same PathHealth bookkeeping as syslog.py.
"""

import asyncio
import os

import pytest

from siem.collectors.network import NetworkCollector

pytestmark = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores file permissions, so chmod 000 proves nothing"
)

KERN_LINE = (
    "Sep 18 17:18:17 erebus kernel: [UFW BLOCK] IN=eth0 OUT= "
    "SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=1234 DPT=22\n"
)


async def _pump(collector, seconds=1.5):
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
async def test_an_unreadable_firewall_log_marks_the_collector_blind(tmp_path):
    log = tmp_path / "kern.log"
    log.write_text(KERN_LINE)
    log.chmod(0o000)

    collector = NetworkCollector(firewall_paths=[log], dns_paths=[])
    assert collector.health != "blind"

    await _pump(collector)

    assert collector.health == "blind"
    assert "permission" in collector.blind_reason.lower()


@pytest.mark.asyncio
async def test_a_file_that_never_grows_is_still_opened(tmp_path):
    """The `>` size gate meant a static file was never opened after priming,
    so a permission revoked with no further writes never surfaced."""
    log = tmp_path / "kern.log"
    log.write_text(KERN_LINE)
    collector = NetworkCollector(firewall_paths=[log], dns_paths=[])
    log.chmod(0o000)  # readable at construction, revoked before any append

    await _pump(collector)

    assert collector.health == "blind"


@pytest.mark.asyncio
async def test_blindness_clears_when_the_file_becomes_readable(tmp_path):
    log = tmp_path / "kern.log"
    log.write_text(KERN_LINE)
    log.chmod(0o000)
    collector = NetworkCollector(firewall_paths=[log], dns_paths=[])
    await _pump(collector)
    assert collector.health == "blind"

    log.chmod(0o644)
    await _pump(collector)

    assert collector.health == "ok"
    assert collector.blind_reason is None


@pytest.mark.asyncio
async def test_a_vanished_file_reports_blind_not_ok(tmp_path):
    log = tmp_path / "kern.log"
    log.write_text(KERN_LINE)
    collector = NetworkCollector(firewall_paths=[log], dns_paths=[])
    collector.MISSING_GRACE_PASSES = 1
    await _pump(collector)
    assert collector.health == "ok"

    log.unlink()
    await _pump(collector)

    assert collector.health == "blind"


@pytest.mark.asyncio
async def test_a_readable_firewall_log_is_never_marked_blind(tmp_path):
    log = tmp_path / "kern.log"
    log.write_text(KERN_LINE)

    collector = NetworkCollector(firewall_paths=[log], dns_paths=[])
    await _pump(collector)

    assert collector.health == "ok"
