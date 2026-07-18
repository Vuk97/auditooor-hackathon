#!/usr/bin/env python3
"""Regression: causal-chain-extract.is_placeholder_text must reject bare markdown-
header defenses ('## Patch', '### Mitigation') and explicit non-defenses ('Not
specified in competition report.', 'Consider the following scenario:') so the chain
quality gate does not admit auto-mined header/preamble junk as a `defense`.
2026-07-08 (corpus->capability drain loop, box J, tick3). Context: carrying
verification_tier into the predicate row unblocked many records but exposed ~1327
markdown-header + ~86 preamble junk defenses; these guards drop them (measured
2610->12367 with header junk 1327->13, 0 pointer)."""
import importlib.util
import unittest
from pathlib import Path

_s = importlib.util.spec_from_file_location(
    "cce", Path(__file__).resolve().parent.parent / "causal-chain-extract.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


class T(unittest.TestCase):
    def _ph(self, t):
        return m.is_placeholder_text(t)

    def test_rejects_bare_markdown_headers(self):
        for t in ("## Patch", "### Mitigation", "### Recommended Mitigation Steps",
                  "#### Fix", "## Remediation"):
            self.assertTrue(self._ph(t), f"should reject bare header {t!r}")

    def test_rejects_explicit_nondefenses(self):
        for t in ("Fix status:** Not specified in competition report.",
                  "Consider the following scenario:",
                  "Mitigation not stated in the report.",
                  "See the PoC for details."):
            self.assertTrue(self._ph(t), f"should reject non-defense {t!r}")

    def test_keeps_real_defenses(self):
        for t in ("Add a length-prefixed key encoding and reject prefix-colliding keys.",
                  "## Patch Apply a reentrancy guard and move state writes before the external call",
                  "Never range over a map for consensus output; sort keys then iterate deterministically.",
                  "enforce explicit authorization checks on every privileged state transition"):
            self.assertFalse(self._ph(t), f"should KEEP real defense {t!r}")


if __name__ == "__main__":
    unittest.main()
