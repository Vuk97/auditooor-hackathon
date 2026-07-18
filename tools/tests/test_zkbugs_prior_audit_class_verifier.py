#!/usr/bin/env python3
"""Tests for zkbugs-prior-audit-class-verifier.py.

Verifies:
1. --list returns >= 30 classes
2. Positive fixture (under-constrained) classifies as DROP-class-b
3. Negative fixture (unrelated Solidity reentrancy) classifies as NOVEL-CANDIDATE
4. --framework circom filters correctly (Halo2-only classes filtered out)
5. stdin round-trip produces same result as file classification
6. --json flag produces parseable JSON output
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zkbugs-prior-audit-class-verifier.py"
FIXTURE_DIR = ROOT / "tools" / "detectors" / "fixtures" / "zkbugs_class_verifier"
CLASS_DB = ROOT / "reference" / "zkbugs_prior_audit_classes.yaml"


def _load_tool():
    spec = importlib.util.spec_from_file_location("zkbugs_prior_audit_class_verifier", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_tool()


class ZkbugsPriorAuditClassVerifierTest(unittest.TestCase):

    def setUp(self) -> None:
        self.classes = MOD._load_class_db(CLASS_DB)
        self.idf = MOD._build_idf(self.classes)

    def test_list_returns_at_least_30_classes(self) -> None:
        """The class DB must contain at least 30 curated classes."""
        self.assertGreaterEqual(len(self.classes), 30,
                                f"Expected >= 30 classes, got {len(self.classes)}")

    def test_positive_fixture_under_constrained_is_drop_class_b(self) -> None:
        """Under-constrained signal fixture must classify as DROP-class-b."""
        fixture = (FIXTURE_DIR / "pos_01_under_constrained.md").read_text(encoding="utf-8")
        results = MOD.classify_text(fixture, self.classes, self.idf, threshold=0.4)
        self.assertTrue(len(results) > 0, "Expected at least one result")
        top = results[0]
        self.assertEqual(top["verdict"], "DROP-class-b",
                         f"Expected DROP-class-b, got {top['verdict']} "
                         f"(score={top['combined_score']}, class={top['class_id']})")

    def test_positive_fixture_range_check_is_drop_class_b(self) -> None:
        """Range-check-missing fixture must classify as DROP-class-b."""
        fixture = (FIXTURE_DIR / "pos_02_range_check_missing.md").read_text(encoding="utf-8")
        results = MOD.classify_text(fixture, self.classes, self.idf, threshold=0.4)
        self.assertTrue(len(results) > 0)
        top = results[0]
        self.assertEqual(top["verdict"], "DROP-class-b",
                         f"Expected DROP-class-b, got {top['verdict']} "
                         f"(score={top['combined_score']}, class={top['class_id']})")

    def test_negative_fixture_solidity_reentrancy_is_novel_candidate(self) -> None:
        """Solidity reentrancy fixture must classify as NOVEL-CANDIDATE (not a ZK bug class)."""
        fixture = (FIXTURE_DIR / "neg_01_unrelated_solidity_reentrancy.md").read_text(encoding="utf-8")
        results = MOD.classify_text(fixture, self.classes, self.idf, threshold=0.4)
        self.assertTrue(len(results) > 0)
        top = results[0]
        self.assertEqual(top["verdict"], "NOVEL-CANDIDATE",
                         f"Expected NOVEL-CANDIDATE for reentrancy, got {top['verdict']} "
                         f"(score={top['combined_score']}, class={top['class_id']})")

    def test_negative_fixture_novel_polynomial_is_novel_candidate(self) -> None:
        """Novel polynomial scheme bug must classify as NOVEL-CANDIDATE."""
        fixture = (FIXTURE_DIR / "neg_02_novel_polynomial_scheme_bug.md").read_text(encoding="utf-8")
        results = MOD.classify_text(fixture, self.classes, self.idf, threshold=0.4)
        self.assertTrue(len(results) > 0)
        top = results[0]
        self.assertEqual(top["verdict"], "NOVEL-CANDIDATE",
                         f"Expected NOVEL-CANDIDATE for novel FRI bug, got {top['verdict']} "
                         f"(score={top['combined_score']}, class={top['class_id']})")

    def test_framework_filter_circom_excludes_halo2_only_classes(self) -> None:
        """--framework circom must filter out Halo2-only classes."""
        all_results = MOD.classify_text("dummy text", self.classes, self.idf, threshold=0.4)
        circom_results = MOD.classify_text("dummy text", self.classes, self.idf,
                                           threshold=0.4, framework="circom")
        all_class_ids = {r["class_id"] for r in all_results}
        circom_class_ids = {r["class_id"] for r in circom_results}
        # There should be fewer classes when filtered to circom
        self.assertLessEqual(len(circom_class_ids), len(all_class_ids))
        # Halo2-only classes (e.g. rlc-collision, state-machine-transition-unconstrained)
        # should not appear in circom results
        halo2_only = {"rlc-collision", "state-machine-transition-unconstrained"}
        self.assertEqual(halo2_only & circom_class_ids, set(),
                         f"Halo2-only classes appeared in circom results: {halo2_only & circom_class_ids}")

    def test_stdin_round_trip_matches_file_classification(self) -> None:
        """--classify-stdin must produce same result as --classify for the same text."""
        fixture_path = FIXTURE_DIR / "pos_01_under_constrained.md"
        fixture_text = fixture_path.read_text(encoding="utf-8")

        # File-based
        proc_file = subprocess.run(
            [sys.executable, str(TOOL), "--classify", str(fixture_path), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc_file.returncode, 1, f"Expected rc=1 (DROP-class-b), got {proc_file.returncode}")
        result_file = json.loads(proc_file.stdout)

        # Stdin-based
        proc_stdin = subprocess.run(
            [sys.executable, str(TOOL), "--classify-stdin", "--json"],
            input=fixture_text, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc_stdin.returncode, 1, f"Expected rc=1 (DROP-class-b) via stdin, got {proc_stdin.returncode}")
        result_stdin = json.loads(proc_stdin.stdout)

        # Verdicts match
        self.assertEqual(result_file["verdict"], result_stdin["verdict"])
        # Top match class_id matches
        self.assertEqual(result_file["top_matches"][0]["class_id"],
                         result_stdin["top_matches"][0]["class_id"])

    def test_json_output_is_parseable_with_required_fields(self) -> None:
        """--json flag must produce valid JSON with required top-level keys."""
        fixture_path = FIXTURE_DIR / "pos_01_under_constrained.md"
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--classify", str(fixture_path), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        data = json.loads(proc.stdout)
        self.assertIn("verdict", data)
        self.assertIn("threshold", data)
        self.assertIn("top_matches", data)
        self.assertIsInstance(data["top_matches"], list)
        self.assertTrue(len(data["top_matches"]) > 0)
        top = data["top_matches"][0]
        self.assertIn("class_id", top)
        self.assertIn("combined_score", top)
        self.assertIn("verdict", top)

    def test_list_command_cli(self) -> None:
        """--list must print all classes to stdout."""
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--list"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # Should contain class headers
        self.assertIn("CLASS_ID", proc.stdout)
        # Count class lines (lines that don't start with dashes or Total:)
        class_lines = [
            ln for ln in proc.stdout.splitlines()
            if ln.strip() and not ln.startswith("-") and not ln.startswith("CLASS") and not ln.startswith("Total")
        ]
        self.assertGreaterEqual(len(class_lines), 30,
                                f"Expected >= 30 class lines in --list output, got {len(class_lines)}")

    def test_novel_candidate_returns_rc_0(self) -> None:
        """NOVEL-CANDIDATE findings must return exit code 0."""
        fixture_path = FIXTURE_DIR / "neg_01_unrelated_solidity_reentrancy.md"
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--classify", str(fixture_path)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0,
                         f"Expected rc=0 for NOVEL-CANDIDATE, got {proc.returncode}")


if __name__ == "__main__":
    unittest.main()
