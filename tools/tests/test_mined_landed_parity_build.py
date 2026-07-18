#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-mined-landed-producer registered via agent-pathspec-register.py -->
"""Guarding tests for tools/mined-landed-parity-build.py.

Verifies the canonical mined_landed_parity.json producer:
  1. all-landed -> parity_ok=True, ledger satisfies the audit-completeness gate
  2. an undecided (no-verdict) sidecar stays UNACCOUNTED -> parity_ok=False
     (the producer must NOT invent a disposition / fake parity)
  3. idempotent: a second run appends zero new learning records
  4. a confirmed sidecar lands in learning_staged.jsonl, not known_dead_ends.jsonl
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / file))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


mlp = _load("mlp_under_test", "mined-landed-parity-build.py")
acc = _load("acc_under_test", "audit-completeness-check.py")


def _mkws(sidecars: dict) -> Path:
    ws = Path(tempfile.mkdtemp())
    d = ws / "hunt_findings_sidecars"
    d.mkdir(parents=True)
    for name, obj in sidecars.items():
        (d / name).write_text(json.dumps(obj), encoding="utf-8")
    return ws


class TestMinedLandedParityBuild(unittest.TestCase):
    def test_all_landed_parity_holds_and_satisfies_gate(self):
        ws = _mkws({
            "a.json": {"hypothesis": "reentrancy in withdraw", "verdict": "refuted"},
            "b.json": {"hypothesis": "overflow in mint", "verdict": "by-design"},
            "c.json": {"hypothesis": "auth bypass", "disposition": "no-exploit"},
        })
        r = mlp.build(ws, check=False)
        self.assertEqual(r["sidecar_count"], 3)
        self.assertEqual(r["landed_count"], 3)
        self.assertEqual(r["unaccounted_count"], 0)
        self.assertTrue(r["parity_ok"])
        # The written ledger must make the audit-completeness gate PASS.
        res = acc.check_mined_landed(ws)
        self.assertTrue(res.ok, f"gate should pass on full parity: {res.reason}")

    def test_undecided_sidecar_unaccounted_not_faked(self):
        ws = _mkws({
            "a.json": {"hypothesis": "reentrancy", "verdict": "refuted"},
            # finding content (hypothesis) but NO verdict/disposition -> undecided
            "b.json": {"hypothesis": "maybe a bug, not yet adjudicated"},
        })
        r = mlp.build(ws, check=True)
        self.assertEqual(r["sidecar_count"], 2)
        self.assertEqual(r["landed_count"], 1)
        self.assertEqual(r["unaccounted_count"], 1)
        self.assertFalse(r["parity_ok"],
                         "an undecided sidecar must NOT be counted landed (no faking)")

    def test_idempotent_second_run_appends_nothing(self):
        ws = _mkws({
            "a.json": {"hypothesis": "x", "verdict": "refuted"},
            "b.json": {"hypothesis": "y", "verdict": "fp"},
        })
        r1 = mlp.build(ws, check=False)
        self.assertEqual(r1.get("landed_records_appended"), 2)
        r2 = mlp.build(ws, check=False)
        self.assertEqual(r2.get("landed_records_appended"), 0,
                         "re-run must not duplicate landed records")
        self.assertTrue(r2["parity_ok"])

    def test_confirmed_routes_to_learning_staged(self):
        ws = _mkws({
            "a.json": {"hypothesis": "real bug", "verdict": "confirmed"},
            "b.json": {"hypothesis": "not a bug", "verdict": "refuted"},
        })
        mlp.build(ws, check=False)
        staged = (ws / ".auditooor" / "learning_staged.jsonl")
        dead = (ws / ".auditooor" / "known_dead_ends.jsonl")
        self.assertTrue(staged.is_file() and staged.read_text().strip(),
                        "confirmed finding must land in learning_staged.jsonl")
        self.assertIn("confirmed", staged.read_text())
        self.assertTrue(dead.is_file() and "refuted" in dead.read_text(),
                        "refuted finding must land in known_dead_ends.jsonl")

    def test_zero_sidecars_trivial_pass(self):
        ws = Path(tempfile.mkdtemp())
        r = mlp.build(ws, check=True)
        self.assertEqual(r["sidecar_count"], 0)
        self.assertTrue(r["parity_ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
