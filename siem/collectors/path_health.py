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
   until the path is *positively* read again. Every persistent failure
   ends there -- an unrecognised errno is blindness too. The default for
   an error this module does not know is "blind", never "fine".
2. An absent path is only blindness after MISSING_GRACE_PASSES consecutive
   passes. Rotation makes a file vanish for a fraction of a second; at a
   one-second poll a handful of passes is far below any detection window
   and far above any rotation gap.
3. The flag is only ever cleared by evidence: a pass in which every
   configured path opened and read cleanly. Clearing because the failure
   bookkeeping happens to be empty is what let a FileNotFoundError -- an
   OSError -- wipe a blind flag the loop never set, including the one
   BaseCollector sets at construction for a path that does not exist.
4. A blind reason is stable for as long as its cause is. BaseCollector
   dedupes its warning by comparing reasons, so anything that varies from
   pass to pass -- a counter, a timestamp -- turns one warning into one
   per second, forever.
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
        # Consecutive passes each path has failed to read (rule 2). Every
        # failure counts, whatever its class: the class decides the reason
        # and whether the grace applies, not whether we are counting.
        self._failures: dict[Path, int] = {}
        # Paths read cleanly on the pass currently in progress (rule 3).
        self._read_ok: set[Path] = set()
        # Last error logged per path, so a permanent failure does not emit a
        # warning every second forever.
        self._last_logged: dict[Path, str] = {}

    def begin_pass(self) -> None:
        self._read_ok.clear()

    def ok(self, path: Path) -> None:
        """This path was opened and read without error on this pass."""
        self._failures.pop(path, None)
        self._unreadable.pop(path, None)
        self._last_logged.pop(path, None)
        self._read_ok.add(path)

    def failed(self, path: Path, exc: OSError) -> None:
        """This path could not be read on this pass. Classifies the cause.

        The classification decides *how soon* a failure becomes blindness
        and *what the operator is told*. It never decides whether a
        persistent failure becomes blindness at all -- that is always yes.
        Only two classes earn special treatment, and both earn it:
        PermissionError is a fact about the deployment from the first pass,
        and FileNotFoundError is the one failure that is routinely a
        fraction of a second long (logrotate), so it waits out the grace.
        """
        passes = self._failures.get(path, 0) + 1
        self._failures[path] = passes

        if isinstance(exc, PermissionError):
            # Not transient: a permission error is a fact about the
            # deployment, not a moment in time.
            self._go_blind(path, f"permission denied reading {path}: {exc}", passes)
        elif isinstance(exc, FileNotFoundError):
            if passes >= self._grace:
                self._go_blind(path, f"{path} does not exist", passes)
        elif passes >= self._grace:
            # Anything else: IsADirectoryError for a path that is a
            # directory, EIO on failing hardware, ESTALE on a dropped NFS
            # mount. Not recognising an error is not a reason to call the
            # collector healthy -- a read that keeps failing is blindness
            # whatever its errno, and the errno goes in the reason so an
            # operator has something to act on.
            self._go_blind(path, f"cannot read {path}: {exc}", passes)

        self._log(path, exc)

    def _go_blind(self, path: Path, reason: str, passes: int) -> None:
        """Record a path as unreadable, announcing the escalation once.

        The reason must be stable for as long as its cause is (rule 4), so
        the consecutive-pass count is a field on this one warning rather
        than part of the string mark_blind dedupes on.
        """
        if self._unreadable.get(path) == reason:
            return
        self._unreadable[path] = reason
        logger.warning(
            "collector_path_blind",
            event_source=self._log_event,
            path=str(path),
            reason=reason,
            consecutive_passes=passes,
        )

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
        elif self._paths and self._read_ok.issuperset(self._paths):
            # Every configured path was read this pass. That is positive
            # evidence against any blind reason, including one this loop did
            # not set, so it is the only place the flag is cleared.
            #
            # `self._paths and` is load-bearing: set().issuperset([]) is
            # True, so without it a collector configured with no paths at
            # all would clear its flag on every pass having read nothing.
            # Neither collector can reach here with an empty list today,
            # but "no evidence" reading as "positive evidence" is the exact
            # shape of bug this module exists to prevent.
            collector.clear_blind()
