#!/usr/bin/env python3
"""Wave-9 S6 tests — mechanical detector grounding scorer.

Coverage (6+ assertions):
  T1  S6 returns {} for functions with no detector hits (empty report)
  T2  S6 boosts attack classes for functions where detector fired (line match)
  T3  Severity weighting works: HIGH contribution > MEDIUM > LOW
  T4  File path matching tolerates suffix matches (ws-relative vs absolute)
  T5  Line-range fuzz: hit within ±30 lines of function body still matches
  T6  Weights sum updated: w1+w2+w3+w4+w5+w6 reads from yaml as expected value
  T7  combine_scores accepts s6 kwarg + applies w6 weight
  T8  rank() exposes w6 + s6_enabled in inputs payload (backward compat smoke)
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "ranker.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("ranker_s6_for_test", MOD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {MOD_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ranker_s6_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


RA = _load()


# Minimal engage_report struct (output of parse_engage_report)
def _make_report(hits):
    """Build a minimal parsed engage_report with the given hit list."""
    clusters = []
    if hits:
        clusters.append({
            "cluster_name": hits[0].get("detector_id", "test-detector"),
            "expected_hits": len(hits),
            "hits": hits,
        })
    return {
        "schema": "auditooor.engage_report_parsed.v1",
        "workspace": "/Users/wolf/audits/test-ws",
        "total_hits": len(hits),
        "by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": len(hits)},
        "distinct_detectors": 1,
        "clusters": clusters,
        "source_path": "/Users/wolf/audits/test-ws/engage_report.md",
        "parse_ok": True,
    }


# Detector -> attack class mapping for tests
FIXTURE_DET_AC_MAP = {
    "setters-with-no-access-control": ["admin-bypass", "missing-access-control"],
    "reentrancy-no-guard": ["reentrancy", "callback-mid-state-mutation"],
    "unchecked-external-call": ["return-value-not-checked"],
    "high-sev-detector": ["funds-theft"],
    "medium-sev-detector": ["accounting-error"],
    "low-sev-detector": ["griefing"],
}


class TestRankerS6(unittest.TestCase):

    # T1: empty engage_report -> S6 returns {}
    def test_t1_empty_report_returns_empty(self):
        result = RA.score_s6_detector_grounding(
            target_file="src/Vault.sol",
            target_line_range=(100, 120),
            workspace_engage_report=None,
            detector_to_attack_classes_map=FIXTURE_DET_AC_MAP,
        )
        self.assertEqual(result, {})

        result2 = RA.score_s6_detector_grounding(
            target_file="src/Vault.sol",
            target_line_range=(100, 120),
            workspace_engage_report={"clusters": [], "parse_ok": True},
            detector_to_attack_classes_map=FIXTURE_DET_AC_MAP,
        )
        self.assertEqual(result2, {})

    # T2: detector fired on this file+line -> attack classes boosted
    def test_t2_detector_hit_boosts_attack_classes(self):
        report = _make_report([{
            "severity": "LOW",
            "detector_id": "setters-with-no-access-control",
            "file_path": "/Users/wolf/audits/test-ws/src/Vault.sol",
            "line": 105,
            "snippet": "function setOwner(address newOwner) external {",
            "dupe_risk": "SKIPPED",
            "cross_ws": None,
        }])
        result = RA.score_s6_detector_grounding(
            target_file="src/Vault.sol",
            target_line_range=(100, 120),
            workspace_engage_report=report,
            detector_to_attack_classes_map=FIXTURE_DET_AC_MAP,
        )
        self.assertIn("admin-bypass", result,
                      "admin-bypass should be in S6 output")
        self.assertIn("missing-access-control", result,
                      "missing-access-control should be in S6 output")
        # Both attack classes from the mapping should get contributions
        ab_contrib = sum(e["contribution"] for e in result["admin-bypass"])
        self.assertGreater(ab_contrib, 0.0,
                           "admin-bypass contribution should be > 0")

    # T3: severity weighting HIGH > MEDIUM > LOW
    def test_t3_severity_weighting_order(self):
        def _s6_for_sev(sev, detector="high-sev-detector"):
            report = _make_report([{
                "severity": sev,
                "detector_id": detector if sev == "HIGH" else (
                    "medium-sev-detector" if sev == "MEDIUM" else "low-sev-detector"
                ),
                "file_path": "/Users/wolf/audits/test-ws/src/Vault.sol",
                "line": 110,
                "snippet": "test",
                "dupe_risk": None,
                "cross_ws": None,
            }])
            # Adjust cluster name to match detector_id
            if report["clusters"]:
                report["clusters"][0]["cluster_name"] = report["clusters"][0]["hits"][0]["detector_id"]
            r = RA.score_s6_detector_grounding(
                target_file="src/Vault.sol",
                target_line_range=(100, 130),
                workspace_engage_report=report,
                detector_to_attack_classes_map=FIXTURE_DET_AC_MAP,
            )
            # Sum all contributions
            return sum(
                sum(e["contribution"] for e in evs)
                for evs in r.values()
            )

        high_score = _s6_for_sev("HIGH")
        medium_score = _s6_for_sev("MEDIUM")
        low_score = _s6_for_sev("LOW")
        self.assertGreater(high_score, medium_score,
                           f"HIGH ({high_score}) should > MEDIUM ({medium_score})")
        self.assertGreater(medium_score, low_score,
                           f"MEDIUM ({medium_score}) should > LOW ({low_score})")
        self.assertGreater(low_score, 0.0)

    # T4: file path suffix matching (ws-relative vs absolute)
    def test_t4_file_path_suffix_matching(self):
        # Hit uses absolute path; target uses ws-relative
        report = _make_report([{
            "severity": "LOW",
            "detector_id": "setters-with-no-access-control",
            "file_path": "/Users/wolf/audits/test-ws/src/VaultV2.sol",
            "line": 306,
            "snippet": "function setOwner(address newOwner) external {",
            "dupe_risk": None,
            "cross_ws": None,
        }])
        # workspace-relative target
        result_rel = RA.score_s6_detector_grounding(
            target_file="src/VaultV2.sol",
            target_line_range=(300, 320),
            workspace_engage_report=report,
            detector_to_attack_classes_map=FIXTURE_DET_AC_MAP,
        )
        self.assertIn("admin-bypass", result_rel,
                      "Suffix match: src/VaultV2.sol should match /Users/.../src/VaultV2.sol")

        # Absolute path target should also match
        result_abs = RA.score_s6_detector_grounding(
            target_file="/Users/wolf/audits/test-ws/src/VaultV2.sol",
            target_line_range=(300, 320),
            workspace_engage_report=report,
            detector_to_attack_classes_map=FIXTURE_DET_AC_MAP,
        )
        self.assertIn("admin-bypass", result_abs,
                      "Exact match: absolute path should match")

    # T5: line-range fuzz — hit within ±30 lines of function body matches
    def test_t5_line_range_fuzz(self):
        report = _make_report([{
            "severity": "LOW",
            "detector_id": "setters-with-no-access-control",
            "file_path": "/Users/wolf/audits/test-ws/src/Vault.sol",
            "line": 150,  # 30 lines below fn body end (100-120)
            "snippet": "function setOwner(address newOwner) external {",
            "dupe_risk": None,
            "cross_ws": None,
        }])
        # Within fuzz window (±30)
        result_within = RA.score_s6_detector_grounding(
            target_file="src/Vault.sol",
            target_line_range=(100, 120),  # hit at 150 = line_end+30 = edge of window
            workspace_engage_report=report,
            detector_to_attack_classes_map=FIXTURE_DET_AC_MAP,
        )
        self.assertIn("admin-bypass", result_within,
                      "Hit within ±30 fuzz window should match")

        # Outside fuzz window
        report2 = _make_report([{
            "severity": "LOW",
            "detector_id": "setters-with-no-access-control",
            "file_path": "/Users/wolf/audits/test-ws/src/Vault.sol",
            "line": 200,  # 80 lines below fn end — outside ±30
            "snippet": "test",
            "dupe_risk": None,
            "cross_ws": None,
        }])
        result_outside = RA.score_s6_detector_grounding(
            target_file="src/Vault.sol",
            target_line_range=(100, 120),
            workspace_engage_report=report2,
            detector_to_attack_classes_map=FIXTURE_DET_AC_MAP,
        )
        self.assertNotIn("admin-bypass", result_outside,
                         "Hit 80 lines outside fn range should NOT match")

    # T6: ranker_weights.yaml has w1..w6; their intended sum (with w6 active) = 1.0
    def test_t6_weights_include_w6(self):
        import os
        weights_path = REPO_ROOT / "audit" / "ranker_weights.yaml"
        self.assertTrue(weights_path.exists(), "ranker_weights.yaml must exist")
        os.environ["RANKER_CACHE_DISABLED"] = "1"
        try:
            cfg = RA.load_weights(weights_path)
        finally:
            os.environ.pop("RANKER_CACHE_DISABLED", None)
        w = cfg.get("weights", {})
        self.assertIn("w6", w, "w6 must be in ranker_weights.yaml")
        total = sum(float(w.get(f"w{i}", 0)) for i in range(1, 7))
        self.assertAlmostEqual(total, 1.0, places=3,
                               msg=f"w1+w2+w3+w4+w5+w6 should sum to 1.0, got {total}")

    # T7: combine_scores accepts s6 kwarg + applies w6 weight
    def test_t7_combine_scores_s6(self):
        s1: dict = {}
        s4: dict = {}
        s6 = {"reentrancy": [{"contribution": 1.0, "scorer": "S6"}]}
        # With w6=0.5, reentrancy score should be 0.5*1.0 = 0.5
        combined = RA.combine_scores(
            s1, s4, s2={}, s3={}, s5={}, s6=s6,
            w1=0.45, w2=0.175, w3=0.175, w4=0.10, w5=0.05, w6=0.5,
        )
        reentrancy_row = next(
            (r for r in combined if r["attack_class"] == "reentrancy"), None
        )
        self.assertIsNotNone(reentrancy_row, "reentrancy should appear in combined output")
        # score = w6 * s6_total = 0.5 * 1.0 = 0.5 (no convergence bonus since only S6)
        self.assertAlmostEqual(reentrancy_row["score"], 0.5, places=3,
                               msg=f"Expected score 0.5 but got {reentrancy_row['score']}")

    # T8: rank() exposes w6 + s6_enabled in inputs (backward compat smoke)
    def test_t8_rank_backward_compat(self):
        import os
        os.environ["RANKER_PREDICTION_LOG_DISABLED"] = "1"
        try:
            rr = RA.rank(
                target_repo="morpho-org/morpho-blue",
                file_path="src/vault-v2/src/VaultV2.sol",
                function_signature="function setOwner(address newOwner) external",
                top_n=3,
                min_confidence=0.0,
                workspace_engage_report=None,  # no report → w6 forced to 0
            )
        finally:
            os.environ.pop("RANKER_PREDICTION_LOG_DISABLED", None)
        inp = rr.inputs
        self.assertIn("w6", inp, "rank() inputs must expose w6")
        self.assertIn("s6_enabled", inp, "rank() inputs must expose s6_enabled")
        # Without engage_report, w6 should be forced to 0.0
        self.assertEqual(inp["w6"], 0.0,
                         "w6 should be 0.0 when no workspace_engage_report provided")
        self.assertFalse(inp["s6_enabled"],
                         "s6_enabled should be False when no engage_report provided")


if __name__ == "__main__":
    unittest.main()
