#!/usr/bin/env python3
r"""Regression: step2c-campaign.py finalize must parse medusa's `calls:` progress
count even when the log carries ANSI/VT100 color escape sequences.

Axelar-SC ITS field run 2026-07-12: a real 1M-call medusa campaign (0 failures)
could not be finalized - `finalize` printed "no `calls:` count found ... campaign
did not run" because medusa colorizes its progress output by default
("calls: \x1b[1m 372660\x1b[0m ...") and the `\bcalls:\s*(\d+)` regex does not
match across an interleaved escape sequence. finalize now strips ANSI before
matching.
"""
import importlib.util
import unittest
from pathlib import Path

_MOD = Path(__file__).resolve().parent.parent / "step2c-campaign.py"
_spec = importlib.util.spec_from_file_location("s2c", _MOD)
s = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s)


class TestAnsiCallsParse(unittest.TestCase):
    def test_strip_ansi_removes_sgr_codes(self):
        colored = "fuzz: \x1b[1melapsed: 15s\x1b[0m, calls: \x1b[1m 372660\x1b[0m ( 24395/sec)"
        stripped = s._strip_ansi(colored)
        self.assertNotIn("\x1b", stripped)
        self.assertIn("calls:  372660", stripped)

    def test_calls_regex_matches_after_strip(self):
        colored = "fuzz: calls: \x1b[1m 1000787\x1b[0m ( 24000/sec)"
        # raw colored line does NOT match (the bug)
        self.assertIsNone(s._CALLS_RE.search(colored))
        # stripped line DOES match with the real count
        m = s._CALLS_RE.search(s._strip_ansi(colored))
        self.assertIsNotNone(m)
        self.assertEqual(s._int(m.group(1)), 1000787)

    def test_plain_log_still_parses(self):
        plain = "elapsed: 3s, calls: 83209 (27730/sec)"
        m = s._CALLS_RE.search(s._strip_ansi(plain))
        self.assertIsNotNone(m)
        self.assertEqual(s._int(m.group(1)), 83209)


if __name__ == "__main__":
    unittest.main()
