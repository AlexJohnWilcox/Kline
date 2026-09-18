"""Every persistent read failure must end in blindness, and say so once.

Two defects, both in the module written to prevent exactly this class of
bug:

1. PathHealth.failed escalated only PermissionError and FileNotFoundError.
   Every other OSError -- IsADirectoryError for a path that is a directory,
   EIO on failing hardware, ESTALE on a dropped NFS mount -- fell into an
   `else: pass`, so the collector ran, reported health "ok", and indexed
   nothing, forever, with one log line at the start and silence after.

2. The absent-path reason carried a per-pass counter ("absent for 3
   consecutive passes", then 4, then 5). BaseCollector.mark_blind dedupes
   its warning by comparing reasons, so a string that changes every pass
   defeated the dedupe: one collector_blind WARNING per second, per absent
   path, for the life of the process.

Plus the empty-path-list hole in apply(), which is the same "no evidence
read as positive evidence" shape the module exists to close.
"""

import asyncio
from pathlib import Path

import pytest
import structlog

from siem.collectors.path_health import PathHealth
from siem.collectors.syslog import SyslogCollector


class _Flagged:
    """Minimal collector stand-in, recording every mark/clear."""

    def __init__(self, reason="set by someone else"):
        self.reason = reason
        self.reasons: list[str] = []
        self.cleared = 0

    def mark_blind(self, reason):
        self.reason = reason
        self.reasons.append(reason)

    def clear_blind(self):
        self.cleared += 1
        self.reason = None


def _pass(health, collector, path, exc):
    health.begin_pass()
    health.failed(path, exc)
    health.apply(collector)


# --- 1: an unrecognised OSError still escalates -----------------------------


@pytest.mark.parametrize(
    "exc",
    [
        IsADirectoryError(21, "Is a directory"),
        OSError(5, "Input/output error"),
        OSError(116, "Stale file handle"),
    ],
    ids=["directory", "eio", "estale"],
)
def test_a_persistent_unclassified_error_escalates_to_blind(exc):
    """The eleventh instance of "it runs, it reports success, it does
    nothing" -- measured over five passes, health stayed "ok"."""
    path = Path("/nonexistent/gate.log")
    health = PathHealth([path], log_event="test", grace_passes=3)
    collector = _Flagged(reason=None)

    for _ in range(5):
        _pass(health, collector, path, exc)

    assert collector.reason is not None, "an unreadable path must not read as healthy"
    assert str(path) in collector.reason


def test_an_unclassified_error_names_its_errno_so_an_operator_can_act():
    path = Path("/nonexistent/gate.log")
    health = PathHealth([path], log_event="test", grace_passes=3)
    collector = _Flagged(reason=None)

    for _ in range(3):
        _pass(health, collector, path, OSError(5, "Input/output error"))

    assert "Errno 5" in collector.reason
    assert "Input/output error" in collector.reason


def test_an_unclassified_error_waits_out_the_grace_like_an_absent_one():
    """A single odd errno is still a moment, not a fact."""
    path = Path("/nonexistent/gate.log")
    health = PathHealth([path], log_event="test", grace_passes=3)
    collector = _Flagged(reason=None)

    _pass(health, collector, path, OSError(5, "Input/output error"))
    assert collector.reason is None
    assert collector.cleared == 0


def test_a_permission_error_still_says_permission_denied():
    """Escalating everything must not flatten the reasons that earned
    their wording."""
    path = Path("/nonexistent/gate.log")
    health = PathHealth([path], log_event="test", grace_passes=3)
    collector = _Flagged(reason=None)

    _pass(health, collector, path, PermissionError(13, "Permission denied"))

    assert "permission denied" in collector.reason


def test_a_positive_read_still_clears_an_unclassified_failure():
    path = Path("/nonexistent/gate.log")
    health = PathHealth([path], log_event="test", grace_passes=3)
    collector = _Flagged(reason=None)

    for _ in range(4):
        _pass(health, collector, path, OSError(5, "Input/output error"))
    assert collector.reason is not None

    health.begin_pass()
    health.ok(path)
    health.apply(collector)

    assert collector.reason is None
    assert collector.cleared == 1


@pytest.mark.asyncio
async def test_a_collector_pointed_at_a_directory_never_reports_ok(tmp_path):
    """End to end: a directory in SYSLOG_PATHS exists, so construction does
    not mark blind, and open() raises IsADirectoryError every pass."""
    directory = tmp_path / "logs"
    directory.mkdir()
    collector = SyslogCollector(paths=[directory])
    collector.MISSING_GRACE_PASSES = 1
    assert collector.health != "blind"

    async def drain():
        async for _ in collector.collect():
            pass

    collector._running = True
    task = asyncio.create_task(drain())
    await asyncio.sleep(2.5)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert collector.health == "blind"
    assert "logs" in collector.blind_reason


# --- 2: the reason is stable, so the warning is emitted once ---------------


def test_the_absent_reason_does_not_change_from_pass_to_pass():
    """The regression: a counter in the reason defeated mark_blind's
    dedupe, turning one warning into one per second forever."""
    path = Path("/nonexistent/gate.log")
    health = PathHealth([path], log_event="test", grace_passes=3)
    collector = _Flagged(reason=None)

    for _ in range(8):
        _pass(health, collector, path, FileNotFoundError(2, "No such file or directory"))

    assert len(set(collector.reasons)) == 1, collector.reasons
    assert collector.reasons[0] == f"{path} does not exist"


def test_a_permanently_absent_path_logs_one_collector_blind_warning():
    """Through the real BaseCollector, which is where the spam landed."""
    path = Path("/nonexistent/gate.log")
    health = PathHealth([path], log_event="test", grace_passes=3)
    collector = SyslogCollector(paths=[path])

    with structlog.testing.capture_logs() as logs:
        for _ in range(8):
            _pass(health, collector, path, FileNotFoundError(2, "No such file or directory"))

    blind = [entry for entry in logs if entry["event"] == "collector_blind"]
    assert len(blind) == 1, [entry["reason"] for entry in blind]


def test_the_pass_count_is_a_structlog_field_emitted_once():
    """It is worth keeping -- just not inside an identity string another
    module dedupes on."""
    path = Path("/nonexistent/gate.log")
    health = PathHealth([path], log_event="test", grace_passes=3)
    collector = _Flagged(reason=None)

    with structlog.testing.capture_logs() as logs:
        for _ in range(8):
            _pass(health, collector, path, FileNotFoundError(2, "No such file or directory"))

    escalations = [e for e in logs if e["event"] == "collector_path_blind"]
    assert len(escalations) == 1
    assert escalations[0]["consecutive_passes"] == 3
    assert escalations[0]["path"] == str(path)


# --- 3: no paths is not evidence of health ---------------------------------


def test_a_pass_over_no_paths_at_all_cannot_clear_the_flag():
    """set().issuperset([]) is True, so an empty path list read as "every
    configured path was read cleanly" and cleared the flag."""
    health = PathHealth([], log_event="test", grace_passes=3)
    collector = _Flagged()

    health.begin_pass()
    health.apply(collector)

    assert collector.cleared == 0
    assert collector.reason == "set by someone else"
