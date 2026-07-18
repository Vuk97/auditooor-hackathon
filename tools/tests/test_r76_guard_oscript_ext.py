#!/usr/bin/env python3
"""Regression: r76-hallucination-guard.grep_excerpt() must scan DSL/non-mainstream
source extensions (.oscript/.aa/.cairo/.move/...), not just .sol/.rs/.go/.ts/.py.
Obyte 2026-07-09: a CONFIRMED finding whose code_excerpt was a verbatim line from an
.oscript AA was ALWAYS auto-downgraded to MAYBE at emit time because grep never scanned
.oscript. Adding the extension can only add real matches; it never false-matches."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent


def _load():
    s = importlib.util.spec_from_file_location("r76g", _T / "r76-hallucination-guard.py")
    m = importlib.util.module_from_spec(s)
    sys.modules["r76g"] = m
    s.loader.exec_module(m)
    return m


class TestR76OscriptExt(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws(self, fname: str, body: str) -> Path:
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        (d / "src" / fname).write_text(body)
        return d

    def test_oscript_real_excerpt_matches(self):
        line = "$res = $lib_aa#11.$get_exchange_result(this_address, $yes_amount, $no_amount)"
        ws = self._ws("agent.oscript", "{\n  init: `{\n    " + line + ";\n  }`\n}\n")
        self.assertTrue(self.m.grep_excerpt(ws, line), "real .oscript line must match (not downgrade)")

    def test_aa_extension_matches(self):
        line = "response['distributed'] = $total_donated - $remaining_after_cascade_split"
        ws = self._ws("agent.aa", line + "\n")
        self.assertTrue(self.m.grep_excerpt(ws, line))

    def test_fabricated_line_still_fails(self):
        ws = self._ws("agent.oscript", "{ init: `{ $x = 1; }` }\n")
        self.assertFalse(
            self.m.grep_excerpt(ws, "a completely fabricated hallucinated pattern line xyz12345 not present"),
            "guard must still catch a fabricated excerpt",
        )

    def test_solidity_unchanged(self):
        line = "function getClaimId(string memory sender_address) internal pure returns (string memory)"
        ws = self._ws("Counterstake.sol", "contract C {\n  " + line + " { }\n}\n")
        self.assertTrue(self.m.grep_excerpt(ws, line), "solidity behavior must be unchanged")


if __name__ == "__main__":
    unittest.main()
