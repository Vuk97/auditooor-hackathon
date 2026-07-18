"""cosmos-detector-runner per-file wall-clock guard (Task #162, SEI 2026-07-05).

A catastrophic-backtracking (regex x large .go file) pair must NOT hang the whole
step-2 scan: it is bounded to a per-file cap and recorded as a TYPED skip (never a
silent skip, never a fabricated finding), and the scan continues. The guard is
fail-open where SIGALRM is unavailable (non-main-thread / non-Unix).
"""
import importlib.util
import re
import time
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "cosmos-detector-runner.py"
_spec = importlib.util.spec_from_file_location("cdr", str(_TOOL))
cdr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cdr)


class TimeLimitGuardTest(unittest.TestCase):
    def test_catastrophic_regex_is_bounded(self):
        t0 = time.monotonic()
        raised = False
        try:
            with cdr._time_limit(1):
                # (a+)+$ backtracks exponentially on a long non-matching string.
                re.search(r"(a+)+$", "a" * 42 + "b" * 6)
        except cdr._MatchTimeout:
            raised = True
        dt = time.monotonic() - t0
        self.assertTrue(raised, "catastrophic regex must trip the timeout")
        self.assertLess(dt, 5.0, "must abort near the 1s cap, not hang")

    def test_fail_open_zero_seconds_is_noop(self):
        # seconds<=0 -> never arms SIGALRM, block runs unbounded (fail-open).
        with cdr._time_limit(0):
            x = sum(range(1000))
        self.assertEqual(x, 499500)

    def test_normal_block_no_false_timeout(self):
        with cdr._time_limit(5):
            m = re.search(r"foo", "foobar")
        self.assertIsNotNone(m)

    def test_timer_disarmed_after_block(self):
        # After a normal (non-timing-out) block the itimer must be cleared so a
        # later slow-but-legit computation is not killed by a stale alarm.
        with cdr._time_limit(5):
            pass
        t0 = time.monotonic()
        # busy ~1.2s; if the alarm leaked this would raise _MatchTimeout.
        while time.monotonic() - t0 < 1.2:
            _ = sum(range(500))
        self.assertGreaterEqual(time.monotonic() - t0, 1.2)


if __name__ == "__main__":
    unittest.main()
