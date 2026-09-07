"""SIGTERM must actually stop the daemon.

The bug this exists to catch: the signal handler in tessera/main.py called
`server.shutdown()` directly. BaseServer.shutdown() blocks until
serve_forever's loop acknowledges the request, and a Python signal handler
runs on the main thread — the thread already inside serve_forever. So the
handler waited for a loop that could not run until the handler returned. The
daemon printed "received signal 15, shutting down" and then hung forever;
`systemd` would sit through TimeoutStopSec (90s by default, and the unit does
not set it) on every stop and every `Restart=on-failure` restart before
resorting to SIGKILL.

Reading the source cannot tell the two versions apart, so these tests stop a
real daemon on a real socket and time it. Every assertion is bounded: a hang
must surface as a failure, never as a test run that never ends.

Sabotage that must make these go red: revert the handler in
src/tessera/main.py to a bare `server.shutdown()`. Measured on WSL2 before the
fix, the process was still alive 20.070s after SIGTERM and needed SIGKILL
(exit 137); after the fix it exits in 0.220s with exit code 0.
"""

from __future__ import annotations

import signal
import subprocess
import time

import pytest

# serve_forever runs with poll_interval=0.2, so a healthy stop lands just over
# 0.2s. 5s is generous enough that a loaded machine cannot flake it and still
# nowhere near the unbounded wait the deadlock produced.
STOP_DEADLINE_SECS = 5.0


def _stop_and_time(process: subprocess.Popen, sig: int) -> tuple[int, float, str]:
    started = time.monotonic()
    process.send_signal(sig)
    try:
        returncode = process.wait(timeout=STOP_DEADLINE_SECS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        output = process.stdout.read() if process.stdout else ""
        pytest.fail(
            f"the daemon was still running {STOP_DEADLINE_SECS}s after signal "
            f"{sig} and had to be killed. Daemon output:\n{output}"
        )
    elapsed = time.monotonic() - started
    output = process.stdout.read() if process.stdout else ""
    return returncode, elapsed, output


def test_sigterm_stops_the_daemon_promptly(live_server) -> None:
    returncode, elapsed, output = _stop_and_time(live_server.process, signal.SIGTERM)
    assert "received signal 15, shutting down" in output, (
        "the SIGTERM handler never ran, so this proves nothing about it"
    )
    assert returncode == 0, f"unclean exit {returncode} on SIGTERM:\n{output}"
    assert elapsed < STOP_DEADLINE_SECS


def test_sigint_stops_the_daemon_promptly(live_server) -> None:
    """SIGINT is wired to the same handler, so it can deadlock the same way."""
    returncode, elapsed, output = _stop_and_time(live_server.process, signal.SIGINT)
    assert "received signal 2, shutting down" in output
    assert returncode == 0, f"unclean exit {returncode} on SIGINT:\n{output}"
    assert elapsed < STOP_DEADLINE_SECS
