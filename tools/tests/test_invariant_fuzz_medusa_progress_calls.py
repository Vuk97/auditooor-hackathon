#!/usr/bin/env python3
"""Regression (Strata 2026-07-07): _max_logged_calls parses the medusa progress-line
call counter `⇾ fuzz: elapsed: ..., calls: N (rate/sec)`. medusa emits NO `Total calls:`
summary line, so before this a genuine >=1M-call medusa campaign reconciled to 0 and its
HONEST fuzz_campaign_receipt.json was false-flagged fuzz-receipt-unreconciled (6 real 1.2M
medusa campaigns blocked audit-complete). The counter is cumulative+monotonic so MAX == the
final total; scoped to lines with `fuzz:` before `calls:` so it never maxes forge's bare
per-invariant `calls: N` (which must be summed, not maxed)."""
import importlib.util
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "invariant-fuzz-completeness.py"
_spec = importlib.util.spec_from_file_location("ifc_medusa", _MOD)
_m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _m
_spec.loader.exec_module(_m)


class TestMedusaProgressCalls(unittest.TestCase):
    def test_medusa_progress_counter_is_maxed(self):
        log = (
            "↾ fuzz: elapsed:    4m06s, calls:    1069636 (  4203/sec), seq/s: 84\n"
            "↾ fuzz: elapsed:    4m39s, calls:    1205872 (  3752/sec), seq/s: 74\n"
            "↾ Transaction test limit reached, halting now...\n"
            "↾ Fuzzer stopped, test results follow below ...\n"
            "↾ [PASSED] Property Test: AccountingNavConservation.echidna_nav_conservation()\n")
        self.assertEqual(_m._max_logged_calls(log), 1205872)

    def test_echidna_total_calls_still_parsed(self):
        self.assertEqual(_m._max_logged_calls("Total calls: 500172\n"), 500172)

    def test_echidna_fuzzing_progress_still_parsed(self):
        self.assertEqual(_m._max_logged_calls("fuzzing: 500172/500000\n"), 500172)

    def test_forge_bare_calls_not_inflated_by_medusa_pattern(self):
        # forge per-invariant `calls: N` WITHOUT a `fuzz:` prefix must NOT be picked up
        # by the medusa pattern (it is summed elsewhere by _executed_call_count). Here
        # _max_logged_calls sees no medusa/echidna/total marker -> 0.
        forge = "[PASS] invariant_a() (runs: 256, calls: 128000, reverts: 0)\n"
        self.assertEqual(_m._max_logged_calls(forge), 0)

    def test_empty(self):
        self.assertEqual(_m._max_logged_calls(""), 0)


class TestAnsiColoredMedusaLog(unittest.TestCase):
    """Regression (NUVA 2026-07-08): a REAL medusa run to a TTY/pipe emits COLORED
    progress lines - `\\x1b[1m` SGR codes are interleaved BETWEEN `calls:` and the
    number (`calls: \\x1b[1m 487280 (...)`), so the counter regexes miss it and a
    genuine >=1M campaign log reads as 0 executed calls (invariant-fuzz false-red).
    _strip_ansi must normalize the colored log to parse identically to NO_COLOR."""

    # A verbatim colored medusa 1.5 progress line as captured from a real run.
    COLORED = (
        "\x1b[1m\x1b[32m↾\x1b[0m\x1b[0m \x1b[1m\x1b[1mfuzz: \x1b[0melapsed: "
        "\x1b[1m     39s\x1b[0m, calls: \x1b[1m    487280 ( 12519/sec)\x1b[0m, "
        "seq/s: \x1b[1m   250\x1b[0m, branches: \x1b[1m  1201\x1b[0m, corpus: "
        "\x1b[1m  118\x1b[0m, failures: \x1b[1m0/9844\x1b[0m\x1b[0m\n"
    )

    def test_strip_ansi_removes_sgr_codes(self):
        self.assertNotIn("\x1b", _m._strip_ansi(self.COLORED))
        self.assertIn("calls:     487280", _m._strip_ansi(self.COLORED))

    def test_executed_call_count_parses_colored_log(self):
        self.assertEqual(_m._executed_call_count(self.COLORED), 487280)

    def test_max_logged_calls_parses_colored_log(self):
        self.assertEqual(_m._max_logged_calls(self.COLORED), 487280)

    def test_colored_and_plain_agree(self):
        plain = _m._strip_ansi(self.COLORED)
        self.assertEqual(
            _m._executed_call_count(self.COLORED),
            _m._executed_call_count(plain),
        )


if __name__ == "__main__":
    unittest.main()
