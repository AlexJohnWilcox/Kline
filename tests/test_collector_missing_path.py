"""A configured path that does not exist must never read as healthy.

FileNotFoundError is an OSError. The collect loop's broad `except OSError`
popped the path from its unreadable bookkeeping, the bookkeeping went empty,
and clear_blind() ran -- wiping the blind flag BaseCollector had set at
construction because the path was not there. A typo'd SYSLOG_PATHS, or the
ordinary first-boot window before rsyslog has created the file, produced a
collector reporting "ok" while indexing nothing, within about a second.

The three invariants these tests hold:
  1. an absent configured path is not "ok",
  2. a file that vanishes for a moment (rotation) does not flap the flag,
  3. the loop never clears a blind reason it did not itself set.
"""

import asyncio
from pathlib import Path

import pytest

from siem.collectors.path_health import MISSING_GRACE_PASSES, PathHealth
from siem.collectors.syslog import SyslogCollector

LINE = "Sep 18 17:18:17 gate sshd[1]: Accepted publickey for nyx from 1.2.3.4 port 22\n"


async def _pump(collector, seconds=1.5):
    """Drive collect() for a moment, the way test_collector_unreadable does."""

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


# --- invariant 1: an absent path is not "ok" --------------------------------


@pytest.mark.asyncio
async def test_a_missing_path_never_reports_ok(tmp_path):
    """The exact defect: blind at construction, "ok" a second later."""
    absent = tmp_path / "gate.log"
    collector = SyslogCollector(paths=[absent])
    assert collector.health == "blind"

    await _pump(collector)

    assert collector.health != "ok"
    assert collector.blind_reason is not None


@pytest.mark.asyncio
async def test_a_missing_path_is_named_as_blindness_once_the_grace_expires(tmp_path):
    absent = tmp_path / "gate.log"
    collector = SyslogCollector(paths=[absent])
    collector.MISSING_GRACE_PASSES = 1

    await _pump(collector)

    assert collector.health == "blind"
    assert "gate.log" in collector.blind_reason
    assert "does not exist" in collector.blind_reason


@pytest.mark.asyncio
async def test_one_missing_path_among_several_still_reports_blind(tmp_path):
    """Half-blind is blind: the readable path's events hide the silent one."""
    good = tmp_path / "syslog"
    good.write_text(LINE)
    absent = tmp_path / "gate.log"

    collector = SyslogCollector(paths=[good, absent])
    collector.MISSING_GRACE_PASSES = 1
    # One path exists, so construction does not mark blind. Only the loop can.
    assert collector.health != "blind"

    await _pump(collector)

    assert collector.health == "blind"
    assert "gate.log" in collector.blind_reason


@pytest.mark.asyncio
async def test_a_path_that_appears_later_lifts_the_flag(tmp_path):
    """The inverse: blindness must not be permanent once the cause is fixed."""
    path = tmp_path / "gate.log"
    collector = SyslogCollector(paths=[path])
    collector.MISSING_GRACE_PASSES = 1
    await _pump(collector)
    assert collector.health == "blind"

    path.write_text(LINE)
    await _pump(collector)

    assert collector.health == "ok"
    assert collector.blind_reason is None


# --- invariant 2: rotation does not flap ------------------------------------


def test_the_grace_period_is_longer_than_a_rotation_and_shorter_than_a_window():
    # The loop polls once a second. logrotate's create leaves no file for
    # milliseconds; the shortest detection window is 300 seconds.
    assert 1 < MISSING_GRACE_PASSES < 300


@pytest.mark.asyncio
async def test_a_file_that_vanishes_briefly_does_not_flap_the_flag(tmp_path):
    path = tmp_path / "gate.log"
    path.write_text(LINE)
    collector = SyslogCollector(paths=[path])

    await _pump(collector)
    assert collector.health == "ok"

    # Rotation: the file is gone for fewer passes than the grace allows.
    path.unlink()
    await _pump(collector, seconds=1.5)
    assert collector.health == "ok", "a rotation window must not read as blindness"

    path.write_text(LINE)
    await _pump(collector)
    assert collector.health == "ok"


# --- invariant 3: the loop only clears what it can disprove -----------------


class _Flagged:
    """Minimal stand-in for a collector, to assert on mark/clear directly."""

    def __init__(self):
        self.reason = "set by someone else"
        self.cleared = 0

    def mark_blind(self, reason):
        self.reason = reason

    def clear_blind(self):
        self.cleared += 1
        self.reason = None


def test_a_missing_path_inside_the_grace_does_not_clear_a_foreign_reason():
    """The old shape's precise failure: no unreadable entries yet, so it
    cleared -- including a reason it had never set."""
    path = Path("/nonexistent/gate.log")
    health = PathHealth([path], log_event="test", grace_passes=3)
    collector = _Flagged()

    health.begin_pass()
    health.failed(path, FileNotFoundError(2, "No such file or directory"))
    health.apply(collector)

    assert collector.cleared == 0
    assert collector.reason == "set by someone else"


def test_an_unclassifiable_error_neither_sets_nor_clears():
    path = Path("/nonexistent/gate.log")
    health = PathHealth([path], log_event="test", grace_passes=3)
    collector = _Flagged()

    health.begin_pass()
    health.failed(path, OSError(5, "Input/output error"))
    health.apply(collector)

    assert collector.cleared == 0
    assert collector.reason == "set by someone else"


def test_the_flag_is_cleared_only_by_a_pass_that_read_every_path():
    a, b = Path("/tmp/a"), Path("/tmp/b")
    health = PathHealth([a, b], log_event="test", grace_passes=3)
    collector = _Flagged()

    health.begin_pass()
    health.ok(a)  # b was not reached this pass
    health.apply(collector)
    assert collector.cleared == 0

    health.begin_pass()
    health.ok(a)
    health.ok(b)
    health.apply(collector)
    assert collector.cleared == 1
    assert collector.reason is None
