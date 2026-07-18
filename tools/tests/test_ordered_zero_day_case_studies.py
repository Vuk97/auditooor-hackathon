#!/usr/bin/env python3
"""Focused regression checks for sanitized ordered zero-day case studies."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "ordered_zero_day_case_studies"


def _load_tool(name: str):
    path = ROOT / "tools" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ORDER = _load_tool("reasoner-regen-pass.py")
HUNT = _load_tool("ordered-llm-hunt.py")
LANG = _load_tool("language-capability-contract.py")


class OrderedZeroDayCaseStudiesTest(unittest.TestCase):
    def _manifest_and_receipt(self, case: str) -> tuple[dict, dict, Path]:
        case_dir = FIXTURES / case
        manifest_path = case_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        receipt = json.loads((case_dir / "receipt.json").read_text(encoding="utf-8"))
        return manifest, receipt, manifest_path

    def test_index_covers_four_sanitized_cases(self):
        index = json.loads((FIXTURES / "INDEX.json").read_text(encoding="utf-8"))
        self.assertEqual(index["cases"], ["nuva", "sei", "obyte", "intuition"])
        self.assertEqual(set(index["case_files"]), set(index["cases"]))
        self.assertEqual(index.get("lead_names", []), [])

    def test_manifest_receipt_hashes_and_schemas(self):
        for case in ("nuva", "sei", "obyte", "intuition"):
            manifest, receipt, manifest_path = self._manifest_and_receipt(case)
            self.assertEqual(manifest["schema"], "auditooor.ordered_zero_day_case_study_manifest.v1")
            self.assertEqual(receipt["schema"], "auditooor.ordered_zero_day_case_study_receipt.v1")
            self.assertEqual(receipt["case"], manifest["case"])
            self.assertEqual(receipt["manifest_sha256"], HUNT._sha256_file(manifest_path))

    def test_go_cosmos_accepted_risk_and_reasoner_parity(self):
        nuva, _, _ = self._manifest_and_receipt("nuva")
        sei, _, _ = self._manifest_and_receipt("sei")
        self.assertEqual(nuva["accepted_risk_awareness"]["ecosystem"], "cosmos")
        self.assertEqual(nuva["accepted_risk_awareness"]["decision"], "accepted-risk")
        self.assertEqual(sei["reasoner_parity"], ["go", "rust", "solidity"])

    def test_unsupported_applicable_languages_are_blocked(self):
        manifest, _, _ = self._manifest_and_receipt("obyte")
        self.assertEqual(set(manifest["languages"]), {"javascript", "oscript"})
        self.assertEqual({row["status"] for row in manifest["unsupported_applicable"].values()}, {"blocked"})
        self.assertTrue(all(row["reason"] == "unsupported-applicable"
                            for row in manifest["unsupported_applicable"].values()))
        authoritative = LANG.authoritative_languages()
        self.assertTrue({"javascript", "oscript"}.issubset(authoritative))
        contract = LANG.load_contract(ROOT / "reference" / "language_capabilities.json")
        report = LANG.query_contract(contract, set(manifest["languages"]), ("engine",))
        self.assertFalse(report["ok"])
        self.assertEqual(report["blocked_languages"], ["javascript", "oscript"])

    def test_solidity_pipeline_runs_producer_before_consumers(self):
        manifest, _, _ = self._manifest_and_receipt("intuition")
        stages = manifest["pipeline"]
        self.assertEqual([row["stage"] for row in stages], ["producer", "reasoner", "depth", "drive"])
        self.assertTrue(ORDER.is_producer(stages[0]["command"]))
        self.assertFalse(ORDER.is_producer(stages[1]["command"]))
        self.assertNotIn("--autorun-producers", ORDER.freeze_command(stages[1]["command"]))

    def test_stale_source_artifact_is_rejected(self):
        manifest, receipt, _ = self._manifest_and_receipt("intuition")
        self.assertEqual(manifest["source_artifact"]["status"], "stale")
        self.assertTrue(manifest["source_artifact"]["reject"])
        self.assertEqual(receipt["status"], "rejected-stale-source")
        self.assertEqual(ORDER.classify_staleness(True, 10.0, [11.0]), "stale")
        self.assertEqual(ORDER.classify_staleness(True, 12.0, [11.0]), "fresh")


if __name__ == "__main__":
    unittest.main()
