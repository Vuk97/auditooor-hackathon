#!/usr/bin/env python3
"""cross-module-trust-seam.py - regression + mutation (non-vacuity) tests.

Pins tools/cross-module-trust-seam.py, the A2 cross-module trust-boundary seam
detector built on has_guard_in_closure (GUARDED-PRODUCER) +
unguarded_paths_to_sink (BYPASS-PATH) + DataFlowEngine._guards_for_vars
(consumer re-check).

Honesty (R80): these tests require a real Slither compile of the in-tree
fixtures. If Slither is not importable the suite SKIPs (it does not fake a
pass).

Matrix:
  - guarded-producer + unguarded-bypass-consumer -> 1 seam.
  - consumer-rechecks                            -> 0 seams (benign).
  - no-guarded-producer                          -> 0 seams.

Non-vacuity: ``test_mutate_guard_predicate_breaks_case1`` neutralises
has_guard_in_closure (-> always False) inside the tool's loaded predicate
module and asserts Case 1 collapses 1 -> 0, proving the guard predicate is
load-bearing.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "cross_module_trust_seam"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "cross_module_trust_seam", TOOLS / "cross-module-trust-seam.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _slither_available() -> bool:
    try:
        import slither  # noqa: F401

        return True
    except Exception:
        return False


SKIP_NO_SLITHER = unittest.skipUnless(
    _slither_available(), "slither-analyzer not importable; seam tests need a real compile"
)


def _rows(tool, fixture_name: str):
    with tempfile.TemporaryDirectory() as td:
        ws = pathlib.Path(td)
        acct = tool.emit(ws, FX / fixture_name, 1000)
        jl = ws / ".auditooor" / "cross_module_trust_seams.jsonl"
        rows = [ln for ln in (jl.read_text().splitlines() if jl.exists() else []) if ln.strip()]
        return acct, rows


class StrictSubstrateTest(unittest.TestCase):
    def test_strict_missing_substrate_fails_closed(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            acct = tool.emit(ws, ws / "missing-foundry-target", 1000, strict=True)
            self.assertEqual(acct["strict_verdict"], "fail-cross-module-trust-seam")
            self.assertTrue(acct["strict_blockers"])
            self.assertTrue(
                any("substrate" in blocker for blocker in acct["strict_blockers"])
            )


@SKIP_NO_SLITHER
class SeamMatrixTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_case1_guarded_producer_unguarded_consumer_one_seam(self):
        acct, rows = _rows(self.tool, "seam_guarded_producer_unguarded_consumer.sol")
        self.assertFalse(acct.get("degraded"), acct)
        self.assertEqual(len(rows), 1, f"expected exactly 1 seam, got {len(rows)}: {rows}")
        self.assertEqual(acct["rows"], 1)

    def test_case2_consumer_rechecks_zero(self):
        acct, rows = _rows(self.tool, "no_seam_consumer_rechecks.sol")
        self.assertFalse(acct.get("degraded"), acct)
        self.assertEqual(len(rows), 0, f"consumer re-checks -> expected 0 seams: {rows}")

    def test_case3_no_guarded_producer_zero(self):
        acct, rows = _rows(self.tool, "no_seam_no_guarded_producer.sol")
        self.assertFalse(acct.get("degraded"), acct)
        self.assertEqual(len(rows), 0, f"no guarded producer -> expected 0 seams: {rows}")

    def test_mutate_guard_predicate_breaks_case1(self):
        """Neutralise has_guard_in_closure inside the tool's predicate module:
        with no guarded producer detectable, Case 1 must collapse 1 -> 0."""
        tool = _load_tool()
        real_load = tool._load

        def fake_load(name, filename):
            m = real_load(name, filename)
            if name == "_cmts_sp" and m is not None and hasattr(m, "has_guard_in_closure"):
                m.has_guard_in_closure = lambda fn, *a, **k: False
            return m

        tool._load = fake_load
        acct, rows = _rows(tool, "seam_guarded_producer_unguarded_consumer.sol")
        self.assertEqual(
            len(rows), 0,
            f"mutated predicate (no guard detected) must yield 0 seams, got {len(rows)}",
        )


if __name__ == "__main__":
    unittest.main()
