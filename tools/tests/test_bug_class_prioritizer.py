#!/usr/bin/env python3
"""Tests for tools/audit/bug-class-prioritizer.py (LANE W4.13).

Stdlib only. All corpus indexes are synthetic in-tempdir fixtures so the
test is hermetic and does not depend on the live corpus state.

Coverage matrix:
  1. End-to-end: synthetic taxonomy + FP corpus + profile -> ranked JSON.
  2. Score formula: priority == weighted sum of the four [0,1] components.
  3. Detector-hit concentration: the workspace's busiest class outranks a
     higher-severity class with zero workspace hits.
  4. Language filter: a class in an off-language subtree gets DENS ~ 0.
  5. Unresolved detector-hit key: a custom class not in the corpus is still
     scored and flagged unresolved_corpus_class.
  6. FP precision: a class present in the FP ledger uses TP/(TP+FP), not 0.5.
  7. Weight normalisation: non-summing-to-1 weights are renormalised so
     priority stays in [0,1].
  8. Brief renderer: --brief emits the ranked markdown table.
  9. Schema + envelope: schema string + context_pack_hash present.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit" / "bug-class-prioritizer.py"


def _write_taxonomy(path: Path) -> None:
    doc = {
        "schema": "auditooor.attack_class_taxonomy.v1",
        "total_records": 300,
        "classes": [
            {
                "attack_class": "theft-via-reentrancy",
                "subtrees": ["evm_defi_audits"],
                "total_records": 200,
                "tier12_pct": 90.0,
            },
            {
                "attack_class": "missing-modifier-on-state-write",
                "subtrees": ["evm_fix_history"],
                "total_records": 50,
                "tier12_pct": 100.0,
            },
            {
                "attack_class": "cosmos-ibc-replay",
                "subtrees": ["go_cosmos_ibc"],
                "total_records": 50,
                "tier12_pct": 80.0,
            },
        ],
    }
    path.write_text(json.dumps(doc), encoding="utf-8")


def _write_fp_corpus(tags_dir: Path, ledger: Path) -> None:
    tags_dir.mkdir(parents=True, exist_ok=True)
    # universal-FP tag YAML: curator confidence estimate
    (tags_dir / "dsl_pattern_universal_fp_001_mm.yaml").write_text(
        "schema_version: auditooor.hackerman_record.v1\n"
        "attack_class: missing-modifier-on-state-write\n"
        "source_extraction_confidence: 0.85\n"
        "synthetic_fixture: true\n",
        encoding="utf-8",
    )
    # live ledger: TP/FP verdicts for theft-via-reentrancy -> 3/(3+1)=0.75
    ledger.write_text(
        "# auditooor.fp_verdict_ledger.v1 synthetic\n"
        + json.dumps({"attack_class": "theft-via-reentrancy", "verdict": "tp"}) + "\n"
        + json.dumps({"attack_class": "theft-via-reentrancy", "verdict": "tp"}) + "\n"
        + json.dumps({"attack_class": "theft-via-reentrancy", "verdict": "tp"}) + "\n"
        + json.dumps({"attack_class": "theft-via-reentrancy", "verdict": "fp"}) + "\n",
        encoding="utf-8",
    )


def _run(profile_path: Path, taxonomy: Path, tags_dir: Path, ledger: Path,
         extra=None):
    args = [
        sys.executable, str(TOOL),
        "--profile", str(profile_path),
        "--taxonomy", str(taxonomy),
        "--fp-tags-dir", str(tags_dir),
        "--fp-ledger", str(ledger),
        "--json",
    ]
    if extra:
        args += extra
    proc = subprocess.run(args, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, (
        "rc=%d stderr=%s" % (proc.returncode, proc.stderr[-500:])
    )
    return proc


class TestBugClassPrioritizer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.taxonomy = d / "taxonomy.json"
        self.tags_dir = d / "fp_tags"
        self.ledger = d / "fp_ledger.jsonl"
        self.profile = d / "profile.json"
        _write_taxonomy(self.taxonomy)
        _write_fp_corpus(self.tags_dir, self.ledger)
        # solidity-heavy workspace; busiest detector hit on the modifier class
        self.profile.write_text(json.dumps({
            "workspace": "fixture-ws",
            "languages": {"solidity": 1.0},
            "protocol_category": "lending",
            "detector_hits": {
                "missing-modifier-on-state-write": 20,
                "theft-via-reentrancy": 4,
                "custom-bespoke-bug": 6,
            },
        }), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _env(self, extra=None):
        proc = _run(self.profile, self.taxonomy, self.tags_dir, self.ledger,
                    extra)
        return json.loads(proc.stdout)

    def test_1_end_to_end_ranked_json(self):
        env = self._env()
        self.assertEqual(env["schema"], "auditooor.bug_class_priority.v1")
        self.assertTrue(env["ranked_attack_classes"])
        # 3 corpus classes + 1 unresolved custom = 4 scored
        self.assertEqual(env["classes_scored"], 4)

    def test_2_score_formula_is_weighted_sum(self):
        env = self._env()
        w = env["score_weights"]
        for row in env["ranked_attack_classes"]:
            c = row["components"]
            expected = (
                w["sev"] * c["sev"] + w["dens"] * c["dens"]
                + w["conc"] * c["conc"] + w["prec"] * c["prec"]
            )
            self.assertAlmostEqual(row["priority"], expected, places=3)
            self.assertGreaterEqual(row["priority"], 0.0)
            self.assertLessEqual(row["priority"], 1.0)

    def test_3_detector_hit_concentration_lifts_rank(self):
        env = self._env()
        ranks = {r["attack_class"]: r["rank"]
                 for r in env["ranked_attack_classes"]}
        # modifier class has 20 hits (busiest) -> outranks reentrancy (4 hits)
        self.assertLess(ranks["missing-modifier-on-state-write"],
                        ranks["theft-via-reentrancy"])

    def test_4_language_filter_zeros_off_language_density(self):
        env = self._env()
        row = next(r for r in env["ranked_attack_classes"]
                   if r["attack_class"] == "cosmos-ibc-replay")
        # go subtree, solidity-only workspace -> DENS ~ 0
        self.assertEqual(row["components"]["dens"], 0.0)
        self.assertEqual(row["evidence"]["language_match"], 0.0)

    def test_5_unresolved_custom_class_flagged(self):
        env = self._env()
        row = next(r for r in env["ranked_attack_classes"]
                   if r["attack_class"] == "custom-bespoke-bug")
        self.assertTrue(row["evidence"]["unresolved_corpus_class"])
        self.assertEqual(row["evidence"]["corpus_records"], 0)

    def test_6_fp_ledger_precision_overrides_default(self):
        env = self._env()
        row = next(r for r in env["ranked_attack_classes"]
                   if r["attack_class"] == "theft-via-reentrancy")
        # 3 TP / 1 FP -> 0.75, not the 0.5 default
        self.assertAlmostEqual(row["components"]["prec"], 0.75, places=3)
        self.assertEqual(row["evidence"]["fp_precision_source"], "ledger-or-tag")
        # modifier class precision comes from the tag YAML estimate (0.85)
        mod = next(r for r in env["ranked_attack_classes"]
                   if r["attack_class"] == "missing-modifier-on-state-write")
        self.assertAlmostEqual(mod["components"]["prec"], 0.85, places=3)

    def test_7_weight_normalisation(self):
        # weights summing to 2.0 must renormalise; priority stays in [0,1]
        env = self._env(extra=[
            "--weight-sev", "0.5", "--weight-dens", "0.5",
            "--weight-conc", "0.5", "--weight-prec", "0.5",
        ])
        wsum = sum(env["score_weights"].values())
        self.assertAlmostEqual(wsum, 1.0, places=5)
        for row in env["ranked_attack_classes"]:
            self.assertLessEqual(row["priority"], 1.0)

    def test_8_brief_renders_table(self):
        proc = subprocess.run(
            [sys.executable, str(TOOL),
             "--profile", str(self.profile),
             "--taxonomy", str(self.taxonomy),
             "--fp-tags-dir", str(self.tags_dir),
             "--fp-ledger", str(self.ledger),
             "--brief"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        self.assertIn("Hunt these attack classes first", proc.stdout)
        self.assertIn("missing-modifier-on-state-write", proc.stdout)
        self.assertIn("Dispatch rationale", proc.stdout)

    def test_9_envelope_has_schema_and_hash(self):
        env = self._env()
        self.assertTrue(env["context_pack_hash"])
        self.assertTrue(env["context_pack_id"].startswith(
            "auditooor.bug_class_priority.v1:"))
        self.assertIn("score_formula", env)


if __name__ == "__main__":
    unittest.main()
