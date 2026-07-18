#!/usr/bin/env python3
"""Focused tests for predicate-domain-coverage-verifier.py."""

from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import tempfile
from pathlib import Path
from typing import Any

import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "predicate-domain-coverage-verifier.py"

_spec = importlib.util.spec_from_file_location(
    "predicate_domain_coverage_verifier",
    TOOL,
)
assert _spec is not None and _spec.loader is not None
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class PredicateDomainCoverageVerifierTest(unittest.TestCase):
    def _write_report(self, root: Path, payload: dict[str, Any]) -> Path:
        path = root / "live-target-report.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path

    def test_domain_index_is_reported(self) -> None:
        data = mod.build_verifier_payload()
        self.assertIn("AUTH", data["predicate_domain_ids"])
        self.assertIn("CUST", data["predicate_domain_ids"])
        self.assertGreater(data["predicate_total_count"], 0)
        self.assertIn("AUTH", data["predicate_by_domain"])
        self.assertIn("INV-AUTH-001", data["predicate_by_domain"]["AUTH"]["predicates"])

    def test_semantic_match_counts_from_v3_entry_points(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report = {
                "schema": "auditooor.live_target_intelligence.v3",
                "entry_points": [
                    {
                        "cluster_id": "sig-1",
                        "p1_match_tier": "SEMANTIC-MATCH",
                        "semantic_p1_invariants": ["INV-AUTH-001", "INV-CUST-001"],
                    },
                    {
                        "cluster_id": "sig-2",
                        "p1_match_tier": "TOPICAL-MATCH",
                        "semantic_p1_invariants": ["INV-AUTH-002"],
                    },
                    {
                        "cluster_id": "sig-3",
                        "p1_match_tier": "SEMANTIC-MATCH",
                        "semantic_p1_invariants": ["INV-AUTH-006", "INV-L2-001"],
                    },
                ],
            }
            report_path = self._write_report(root, report)
            data = mod.build_verifier_payload(live_target_json=report_path)
            self.assertEqual(data["live_target_report"]["status"], "ok")
            self.assertEqual(data["live_target_report"]["semantic_match_rows"], 2)
            self.assertEqual(data["semantic_match_counts"]["AUTH"]["entry_hits"], 2)
            self.assertEqual(data["semantic_match_counts"]["AUTH"]["invariant_hits"], 2)
            self.assertEqual(data["semantic_match_counts"]["CUST"]["entry_hits"], 1)
            self.assertEqual(data["semantic_match_counts"]["CUST"]["invariant_hits"], 1)
            self.assertEqual(data["semantic_match_counts"]["L2"]["entry_hits"], 1)
            self.assertEqual(data["semantic_match_counts"]["L2"]["invariant_hits"], 1)

    def test_fallback_to_prioritized_rows_and_missing_report(self) -> None:
        payload = mod.build_verifier_payload(live_target_json=Path("/tmp/does-not-exist.json"))
        self.assertEqual(payload["live_target_report"]["status"], "missing")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report = {
                "prioritized_entries": [
                    {
                        "p1_match_tier": "SEMANTIC-MATCH",
                        "matched_p1_invariants": ["INV-LN-001", "INV-LN-002"],
                    },
                ]
            }
            report_path = self._write_report(root, report)
            data = mod.build_verifier_payload(live_target_json=report_path)
            self.assertEqual(data["live_target_report"]["status"], "ok")
            self.assertEqual(data["semantic_match_counts"]["LN"]["entry_hits"], 1)
            self.assertEqual(data["semantic_match_counts"]["LN"]["invariant_hits"], 2)

    def test_output_json_option_writes_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = root / "artifacts" / "predicate-coverage.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = mod.main(["--json", "--output-json", str(output)])
            self.assertEqual(rc, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], mod.SCHEMA)
            self.assertIn("predicate_domain_ids", payload)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
