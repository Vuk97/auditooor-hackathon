#!/usr/bin/env python3
"""Regression guard (G9): `make audit` must write the completion marker after the
CORE audit completes and BEFORE the unbounded advisory tail (audit-preflight,
brain-prime, ...).

Before 2026-06-27 the success path wrote last_audit_complete_marker only at the
very END of the recipe, after audit-preflight (UNBOUNDED per-fn packs). On a
15-repo monorepo preflight ran >1h, so the marker (which GAP29 hunt-phase-ordering
+ the per-fn hunt depend on) was never written and ALL downstream hunting stalled
behind advisory work. Fix: an early idempotent marker write right after the
inscope-manifest/dataflow-slice (core-complete), before the preflight stage.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"


class MakeAuditMarkerBeforePreflightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.src = MAKEFILE.read_text(encoding="utf-8")

    def _audit_recipe(self) -> str:
        # The `audit:` recipe through to its completion-summary tail.
        start = self.src.index("\naudit:")
        end = self.src.index("audit-completion-marker-test:")
        return self.src[start:end]

    def test_early_marker_write_exists_with_g9_note(self) -> None:
        recipe = self._audit_recipe()
        self.assertIn("after CORE audit (G9", recipe,
                      "early core-complete marker write (G9) missing from make audit")

    def test_marker_write_precedes_audit_preflight(self) -> None:
        recipe = self._audit_recipe()
        # Position of the FIRST completion-marker `write` (excluding write-if-core-complete)
        # must come before the first `audit-preflight WS=` invocation.
        marker_iter = [m.start() for m in re.finditer(
            r"audit-completion-marker\.py write\b(?!-if-core-complete)", recipe)]
        self.assertTrue(marker_iter, "no plain `audit-completion-marker.py write` in recipe")
        preflight = recipe.index('audit-preflight WS="$(_WS_RESOLVED)"')
        self.assertLess(marker_iter[0], preflight,
                        "completion marker must be written BEFORE the unbounded audit-preflight")

    def test_final_idempotent_write_still_present(self) -> None:
        # The end-of-recipe write must remain (idempotent refresh after advisory tail).
        recipe = self._audit_recipe()
        writes = re.findall(r"audit-completion-marker\.py write\b(?!-if-core-complete)", recipe)
        self.assertGreaterEqual(len(writes), 2,
                                "expected BOTH an early (core-complete) and a final marker write")


if __name__ == "__main__":
    unittest.main()
