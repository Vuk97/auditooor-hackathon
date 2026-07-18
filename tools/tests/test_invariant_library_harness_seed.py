#!/usr/bin/env python3
"""
test_invariant_library_harness_seed.py - guard tests for the corpus-fed
runnable-oracle CANDIDATE seeder (tools/invariant-library-harness-seed.py).

Covers:
  * a conservation invariant yields a balance-sum predicate_sketch AND
    execution_status == 'planned' (the SPEC-mandated guard).
  * the five SPEC category->family mappings.
  * an unmapped category falls back to needs-human (still execution_status=planned).
  * HONESTY: every emitted record has execution_status 'planned' (never a
    claimed pass / mutation-verified state).
  * verification_tier is PRESERVED unchanged from the corpus row.
  * idempotence: same corpus -> byte-identical output.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "invariant-library-harness-seed.py"

sys.path.insert(0, str(ROOT / "tools"))
import importlib.util


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "invariant_library_harness_seed", str(TOOL)
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _row(category, statement, commit, tier="tier-2-verified-public-archive",
         inv_id="INV-X-0001"):
    return {
        "invariant_id": inv_id,
        "category": category,
        "statement": statement,
        "commit_point_pattern": commit,
        "verification_tier": tier,
        "target_lang": "solidity",
    }


class TestConservationGuard(unittest.TestCase):
    def test_conservation_yields_balance_sum_predicate_and_planned(self):
        """SPEC guard: conservation -> balance-sum predicate_sketch + planned."""
        row = _row(
            "conservation",
            "Sum of user shares MUST equal convertToShares(totalAssets).",
            "deposit(): mint dead-shares on first deposit",
            inv_id="INV-CON-001",
        )
        rec = MOD.seed_record(row, "invariants_pilot_audited.jsonl")
        self.assertEqual(rec["harness_family"], "balance-sum-invariant")
        self.assertIn("sum(component_balances_after)", rec["predicate_sketch"])
        self.assertIn("==", rec["predicate_sketch"])
        # HONESTY: a sketch is NOT a mutation-verified harness.
        self.assertEqual(rec["execution_status"], "planned")
        # negative test = the breaking mutation.
        self.assertIn("MUTATION", rec["negative_test_sketch"])
        # verification_tier preserved unchanged.
        self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
        # the original statement / commit point are carried into the sketch.
        self.assertIn("convertToShares", rec["predicate_sketch"])

    def test_five_spec_category_mappings(self):
        cases = {
            "conservation": "balance-sum-invariant",
            "custody": "no-unauthorized-transfer",
            "atomicity": "no-double-spend",
            "freshness": "monotonic-state",
            "authorization": "access-gate",
        }
        for cat, fam in cases.items():
            rec = MOD.seed_record(_row(cat, "x", "y"), "f.jsonl")
            self.assertEqual(rec["harness_family"], fam, f"{cat}->{fam}")
            self.assertEqual(rec["execution_status"], "planned")

    def test_unmapped_category_needs_human_still_planned(self):
        rec = MOD.seed_record(_row("some-novel-class", "x", "y"), "f.jsonl")
        self.assertEqual(rec["harness_family"], "needs-human")
        self.assertEqual(rec["execution_status"], "planned")
        self.assertIn("hand-author", rec["negative_test_sketch"])


class TestHonesty(unittest.TestCase):
    def test_no_record_claims_verified_or_pass(self):
        """R80: nothing here is mutation-verified; all are 'planned'."""
        for cat in ("conservation", "custody", "atomicity", "freshness",
                    "authorization", "ordering", "junk-unmapped"):
            rec = MOD.seed_record(_row(cat, "stmt", "commit"), "f.jsonl")
            self.assertEqual(rec["execution_status"], "planned")
            blob = json.dumps(rec).lower()
            for banned in ("mutation-verified", "verified-harness", "executed_clean",
                           '"pass"', "observed_pass"):
                self.assertNotIn(banned, blob, f"{cat}: leaked {banned!r}")


class TestEndToEnd(unittest.TestCase):
    def test_cli_emits_planned_candidates_and_is_idempotent(self):
        corpus = [
            _row("conservation", "sum invariant", "commit-a", inv_id="INV-CON-001"),
            _row("custody", "custody invariant", "commit-b", inv_id="INV-CUS-001"),
        ]
        with tempfile.TemporaryDirectory() as td:
            cpath = Path(td) / "corpus.jsonl"
            cpath.write_text("\n".join(json.dumps(r) for r in corpus) + "\n")
            out = Path(td) / "plans.jsonl"

            def run():
                return subprocess.run(
                    [sys.executable, str(TOOL),
                     "--corpus", str(cpath), "--out", str(out)],
                    capture_output=True, text=True,
                )

            r1 = run()
            self.assertEqual(r1.returncode, 0, r1.stderr)
            first = out.read_text()
            recs = [json.loads(l) for l in first.splitlines()]
            self.assertEqual(len(recs), 2)
            self.assertTrue(all(x["execution_status"] == "planned" for x in recs))
            self.assertEqual(recs[0]["harness_family"], "balance-sum-invariant")
            self.assertEqual(recs[1]["harness_family"], "no-unauthorized-transfer")

            r2 = run()
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertEqual(out.read_text(), first, "output must be idempotent")

    def test_runs_against_real_corpus(self):
        """Smoke: the real prose-only corpus produces planned candidates."""
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "plans.jsonl"
            r = subprocess.run(
                [sys.executable, str(TOOL), "--out", str(out), "--limit", "20"],
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            recs = [json.loads(l) for l in out.read_text().splitlines()]
            self.assertEqual(len(recs), 20)
            self.assertTrue(all(x["execution_status"] == "planned" for x in recs))


if __name__ == "__main__":
    unittest.main()
