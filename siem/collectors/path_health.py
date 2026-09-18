"""Shared "can this collector still read its files?" bookkeeping.

The syslog and network collectors both tail a fixed set of paths in a
one-second loop, and both have to answer the same question on every pass:
is this read failure a fact about the deployment (blindness) or a moment in
time (rotation)? Getting that wrong in either direction is expensive --
never marking blind means a misconfigured collector reports healthy while
indexing nothing, and flapping the flag on rotation makes the honest signal
noise.

It lived inline in one loop and was absent from the other, which is how the
two collectors drifted apart. The rules, once, here:

1. A configured path that cannot be read is blindness, and stays blindness
   until the path is *positively* read again.
2. An absent path is only blindness after MISSING_GRACE_PASSES consecutive
   passes. Rotation makes a file vanish for a fraction of a second; at a
   one-second poll a handful of passes is far below any detection window
   and far above any rotation gap.
3. The flag is only ever cleared by evidence: a pass in which every
   configured path opened and read cleanly. Clearing because the failure
   bookkeeping happens to be empty is what let a FileNotFoundError -- an
   OSError -- wipe a blind flag the loop never set, including the one
   BaseCollector sets at construction for a path that does not exist.
"""

from pathlib import Path

import structlog

logger = structlog.get_logger()

# Consecutive one-second passes a path may be absent before that counts as
# blindness. Three seconds is orders of magnitude longer than the window in
# which logrotate's create leaves no file, and orders of magnitude shorter
# than the 300s detection window whose silence it explains.
MISSING_GRACE_PASSES = 3


class PathHealth:
    """Per-pass read outcomes for a set of tailed paths, and the flag they imply."""

    def __init__(
        self,
        paths: list[Path],
        *,
        log_event: str,
        grace_passes: int = MISSING_GRACE_PASSES,
    ):
        self._paths = list(paths)
        self._log_event = log_event
        self._grace = grace_passes
        # Paths that cannot be read, and why. A path only leaves this
        # mapping by being read successfully (rule 1).
        self._unreadable: dict[Path, str] = {}
        # Consecutive passes each path has been absent (rule 2).
        self._missing: dict[Path, int] = {}
        # Paths read cleanly on the pass currently in progress (rule 3).
        self._read_ok: set[Path] = set()
        # Last error logged per path, so a permanent failure does not emit a
        # warning every second forever.
        self._last_logged: dict[Path, str] = {}

    def begin_pass(self) -> None:
        self._read_ok.clear()

    def ok(self, path: Path) -> None:
        """This path was opened and read without error on this pass."""
        self._missing.pop(path, None)
        self._unreadable.pop(path, None)
        self._last_logged.pop(path, None)
        self._read_ok.add(path)

    def failed(self, path: Path, exc: OSError) -> None:
        """This path could not be read on this pass. Classifies the cause."""
        if isinstance(exc, PermissionError):
            # Not transient: a permission error is a fact about the
            # deployment, not a moment in time.
            self._missing.pop(path, None)
            self._unreadable[path] = f"permission denied reading {path}: {exc}"
        elif isinstance(exc, FileNotFoundError):
            passes = self._missing.get(path, 0) + 1
            self._missing[path] = passes
            if passes >= self._grace:
                self._unreadable[path] = (
                    f"{path} does not exist (absent for {passes} consecutive passes)"
                )
        else:
            # Some other I/O error -- EIO, ELOOP, a vanished mount. Neither
            # claim blindness (it may be a moment) nor sight (the read did
            # not happen): leave whatever this path's last known state was.
            # The path is not in _read_ok either way, so a pass containing
            # one can never clear the flag.
            pass
        self._log(path, exc)

    def _log(self, path: Path, exc: OSError) -> None:
        message = str(exc)
        if self._last_logged.get(path) == message:
            return
        self._last_logged[path] = message
        logger.warning(self._log_event, path=str(path), error=message)

    def apply(self, collector) -> None:
        """Set or clear the collector's blind flag from this pass's outcomes."""
        if self._unreadable:
            collector.mark_blind("; ".join(sorted(self._unreadable.values())))
        elif self._read_ok.issuperset(self._paths):
            # Every configured path was read this pass. That is positive
            # evidence against any blind reason, including one this loop did
            # not set, so it is the only place the flag is cleared.
            collector.clear_blind()
