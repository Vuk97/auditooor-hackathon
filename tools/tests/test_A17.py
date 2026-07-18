#!/usr/bin/env python3
"""A17 freshness-TOCTOU trust-seam detector - regression + mutation (non-vacuity).

Pins the third arm of tools/cross-module-trust-seam.py:
``emit_freshness_toctou_seams`` (validate-freshness-here / consume-stale-there).
It reuses A2's storage-mediated writer[V]->reader[V] JOIN but swaps the guard
predicate for a FRESHNESS (time/oracle) compare + a freshness-typing filter on V.

Honesty (R80): these tests require a real Slither compile of the in-tree
fixtures. If Slither is not importable the suite SKIPs (it never fakes a pass).

Matrix (the target property MISSING fires; PRESENT/guarded is SILENT):
  - validator + consumer that OMITS the freshness re-check   -> 1 seam.
  - consumer RE-VALIDATES freshness (require vs block.timestamp) -> 0 (benign).
  - consumer carries an AGE term (block.timestamp - V)        -> 0 (stale-by-design).
  - producer has NO freshness (time/oracle) validator         -> 0 (nothing to trust).
  - V is a REPLAY-UNIQUENESS / AC mapping (EIP3009 FP)        -> 0 (not decay-typed).

Non-vacuity (each guard is load-bearing - a mutation flips the verdict):
  - neutralise the PRODUCER freshness predicate -> Case 1 collapses 1 -> 0.
  - neutralise the AGE-term FP-guard            -> Case 3 fires 0 -> 1.
  - neutralise the consumer RE-CHECK detection  -> Case 2 fires 0 -> 1.
  - neutralise the REPLAY/AC exclusion          -> Case 5 fires 0 -> 1.
"""
from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "freshness_toctou"

CASE1 = "seam_validated_consumed_stale.sol"
CASE2 = "no_seam_consumer_rechecks.sol"
CASE3 = "no_seam_age_term.sol"
CASE4 = "no_seam_no_freshness_validator.sol"
CASE5 = "no_seam_replay_uniqueness.sol"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "cross_module_trust_seam_a17", TOOLS / "cross-module-trust-seam.py"
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
    _slither_available(),
    "slither-analyzer not importable; freshness-seam tests need a real compile",
)


def _rows(tool, fixture_name: str):
    with tempfile.TemporaryDirectory() as td:
        ws = pathlib.Path(td)
        acct = tool.emit_freshness_toctou_seams(ws, FX / fixture_name, 1000, force=True)
        jl = ws / ".auditooor" / "freshness_toctou_seams.jsonl"
        rows = [ln for ln in (jl.read_text().splitlines() if jl.exists() else []) if ln.strip()]
        return acct, rows


@SKIP_NO_SLITHER
class FreshnessSeamMatrixTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_off_by_default_no_force_no_env(self):
        """Advisory-first: with no force + no env the arm is a no-op (0 rows,
        off-by-default) - a green ws stays green."""
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            acct = self.tool.emit_freshness_toctou_seams(ws, FX / CASE1, 1000, force=False)
            self.assertEqual(acct.get("status"), "off-by-default", acct)
            self.assertEqual(acct.get("rows"), 0)

    def test_case1_validator_stale_consumer_one_seam(self):
        acct, rows = _rows(self.tool, CASE1)
        self.assertFalse(acct.get("degraded"), acct)
        self.assertEqual(len(rows), 1, f"expected exactly 1 freshness seam, got {len(rows)}: {rows}")
        self.assertEqual(acct["rows"], 1)
        self.assertEqual(acct["freshness_producer_vars"], 1)

    def test_case2_consumer_rechecks_zero(self):
        acct, rows = _rows(self.tool, CASE2)
        self.assertFalse(acct.get("degraded"), acct)
        self.assertEqual(len(rows), 0, f"consumer re-checks freshness -> expected 0 seams: {rows}")
        # the producer IS a freshness validator; only the consumer re-check suppresses it.
        self.assertEqual(acct["freshness_producer_vars"], 1)

    def test_case3_age_term_zero(self):
        acct, rows = _rows(self.tool, CASE3)
        self.assertFalse(acct.get("degraded"), acct)
        self.assertEqual(len(rows), 0, f"stale-by-design age term -> expected 0 seams: {rows}")
        self.assertEqual(acct["freshness_producer_vars"], 1)

    def test_case4_no_freshness_validator_zero(self):
        acct, rows = _rows(self.tool, CASE4)
        self.assertFalse(acct.get("degraded"), acct)
        self.assertEqual(len(rows), 0, f"no freshness validator -> expected 0 seams: {rows}")
        self.assertEqual(acct["freshness_producer_vars"], 0)

    def test_case5_replay_uniqueness_mapping_zero(self):
        """NUVA EIP3009 FP regression: a signature-replay UNIQUENESS mapping
        (_authorizationStates) whose writer reads block.timestamp for an UNRELATED
        validAfter/validBefore deadline is NOT a freshness/time-decayed producer.
        The var is never freshness-typed -> 0 seams AND freshness_producer_vars==0
        (a green ws stays green - the FP no longer fires)."""
        acct, rows = _rows(self.tool, CASE5)
        self.assertFalse(acct.get("degraded"), acct)
        self.assertEqual(len(rows), 0, f"replay-uniqueness mapping -> expected 0 seams: {rows}")
        self.assertEqual(
            acct["freshness_producer_vars"], 0,
            "a replay-uniqueness / AC mapping must NOT be typed a freshness producer",
        )

    def test_row_shape_carries_plane_and_queue_keys(self):
        _acct, rows = _rows(self.tool, CASE1)
        import json

        r = json.loads(rows[0])
        self.assertEqual(r["freshness_quantity"], "updatedAt")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["covered_by_a2"])
        # the exact key the enforcement-plane reader (_consolidate_a2) folds on:
        self.assertIn("unguarded_consumer_sink", r)
        self.assertIn("fn", r["unguarded_consumer_sink"])
        self.assertIn("validator", r)
        self.assertIn("bypass_entrypoint", r)


@SKIP_NO_SLITHER
class FreshnessSeamNonVacuityTest(unittest.TestCase):
    """Each guard is load-bearing: a targeted mutation flips the verdict."""

    def test_mutate_producer_predicate_breaks_case1(self):
        """Neutralise the STRICT producer freshness predicate: with no freshness
        validator detectable, Case 1 must collapse 1 -> 0."""
        tool = _load_tool()
        tool._a17_producer_freshness_pred = lambda node: False
        _acct, rows = _rows(tool, CASE1)
        self.assertEqual(len(rows), 0,
                         f"mutated producer predicate must yield 0 seams, got {len(rows)}")

    def test_age_term_fp_guard_is_load_bearing(self):
        """Neutralise the STALE-BY-DESIGN age-term FP-guard: Case 3 (which the
        guard suppresses) must then FIRE 0 -> 1, proving the guard is real."""
        tool = _load_tool()
        tool._a17_has_age_term = lambda fn, var: False
        _acct, rows = _rows(tool, CASE3)
        self.assertEqual(len(rows), 1,
                         f"disabling the age-term guard must expose 1 seam, got {len(rows)}")

    def test_consumer_recheck_detection_is_load_bearing(self):
        """Neutralise BOTH consumer-re-check detectors: Case 2 (which the re-check
        suppresses) must then FIRE 0 -> 1, proving the re-check test is real."""
        tool = _load_tool()
        tool._a17_expr_is_freshness = lambda expr: False
        tool._a17_is_freshness_guard = lambda node: False
        _acct, rows = _rows(tool, CASE2)
        self.assertEqual(len(rows), 1,
                         f"disabling re-check detection must expose 1 seam, got {len(rows)}")

    def test_replay_uniqueness_exclusion_is_load_bearing(self):
        """Neutralise the REPLAY-UNIQUENESS / AC exclusion: Case 5 (the EIP3009 FP
        the exclusion suppresses) must then FIRE 0 -> 1, proving the exclusion is
        the real thing killing the FP (not a fixture accident)."""
        tool = _load_tool()
        tool._a17_var_is_replay_or_ac = lambda var: False
        _acct, rows = _rows(tool, CASE5)
        self.assertEqual(len(rows), 1,
                         f"disabling the replay/AC exclusion must expose the FP seam, got {len(rows)}")


if __name__ == "__main__":
    unittest.main()
