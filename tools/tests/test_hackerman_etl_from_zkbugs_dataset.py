#!/usr/bin/env python3
# r36-rebuttal: lane zkbugs-dataset-etl registered 2 files via tools/agent-pathspec-register.py at lane start
"""Tests for tools/hackerman-etl-from-zkbugs-dataset.py.

R37 sibling-test contract (~/.claude/CLAUDE.md): every miner under
tools/hackerman-etl-from-*.py MUST have a sibling test asserting every
emitted record carries a non-empty verification_tier.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-zkbugs-dataset.py"
FIXTURE_DIR = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_etl_from_zkbugs_dataset"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromZkbugsDatasetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_zkbugs_dataset")
        self.assertTrue(FIXTURE_DIR.exists(), f"missing fixture dir: {FIXTURE_DIR}")

    # -----------------------------------------------------------------
    def _run(self, dry_run: bool, out_root: Path):
        return self.tool.run(
            dataset_root=FIXTURE_DIR,
            out_root=out_root,
            batch_id="zkbugs-dataset-test",
            dry_run=dry_run,
            limit=None,
        )

    def test_dry_run_mines_expected_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run(dry_run=True, out_root=Path(tmp))
        # 2 valid bugs (circom IsZero + arkworks fixpoint); the stub entry
        # with <3 mandatory fields is skipped. Each valid bug -> 1 inv + 1 det.
        self.assertEqual(summary["invariant_records"], 2)
        self.assertEqual(summary["detector_seed_records"], 2)
        self.assertEqual(summary["records_mined"], 4)
        self.assertGreaterEqual(summary["skipped_insufficient_fields"], 1)

    def test_r37_every_record_carries_nonempty_tier(self) -> None:
        """R37: every emitted record carries a non-empty verification_tier."""
        with tempfile.TemporaryDirectory() as tmp:
            out_root = Path(tmp)
            summary = self._run(dry_run=False, out_root=out_root)
            self.assertEqual(summary["records_missing_tier"], [])
            self.assertEqual(summary["verification_tier"],
                             "tier-2-verified-public-archive")

            inv_files = list((out_root / "invariant_library_extended"
                              / "zkbugs-dataset-test").glob("*.yaml"))
            det_files = list((out_root / "detector_synthesis_v2"
                              / "zkbugs-dataset-test").glob("*.json"))
            self.assertEqual(len(inv_files), 2)
            self.assertEqual(len(det_files), 2)

            for f in inv_files:
                body = f.read_text(encoding="utf-8").split("---\n", 1)[1]
                rec = json.loads(body)
                self.assertTrue(rec.get("verification_tier"),
                                f"inv record missing tier: {f}")
                self.assertTrue(rec["content"].get("verification_tier"),
                                f"inv content missing tier: {f}")
                self.assertTrue(rec["content"]["invariant_id"].startswith("INV-ZKBUGS-"))
                self.assertTrue(rec["content"]["statement"])

            for f in det_files:
                rec = json.loads(f.read_text(encoding="utf-8"))
                self.assertTrue(rec.get("verification_tier"),
                                f"det record missing tier: {f}")
                self.assertEqual(rec["status"], "ok")
                # result must be a JSON-string decodable to a detector dict
                payload = json.loads(rec["result"])
                self.assertTrue(payload.get("detector_sketch"))
                self.assertTrue(payload.get("attack_class"))

    def test_attack_class_mapping(self) -> None:
        self.assertEqual(
            self.tool._map_attack_class("Under-Constrained",
                                        "Wrong Translation of Logic into Constraints",
                                        "Soundness"),
            "circuit-unconstrained-variable")
        self.assertEqual(
            self.tool._map_attack_class("Missing Range Check",
                                        "Invalid comparison on fixed-point values",
                                        "Soundness"),
            "circuit-missing-range-check")
        # default fallback
        self.assertEqual(
            self.tool._map_attack_class("", "", ""),
            "circuit-unconstrained-variable")

    def test_dsl_to_target_lang(self) -> None:
        self.assertEqual(self.tool._dsl_to_target_lang("Circom"), "circom")
        self.assertEqual(self.tool._dsl_to_target_lang("Arkworks"), "rust")
        self.assertEqual(self.tool._dsl_to_target_lang("Halo2"), "rust")
        self.assertEqual(self.tool._dsl_to_target_lang("Noir"), "noir")
        self.assertEqual(self.tool._dsl_to_target_lang("Mystery"), "any")

    def test_skips_insufficient_fields(self) -> None:
        entry = {"Id": "x", "Commands": {}}  # only 1 mandatory field
        self.assertLess(self.tool._count_mandatory(entry), self.tool.MIN_MANDATORY)
        full = {"Id": "x", "DSL": "Circom", "Vulnerability": "Under-Constrained",
                "Impact": "Soundness", "Project": "p"}
        self.assertGreaterEqual(self.tool._count_mandatory(full),
                                self.tool.MIN_MANDATORY)

    def test_promote_compatible_invariant_shape(self) -> None:
        """The emitted invariant YAML must be readable by the
        invariant_library_extended extractor in promote-mined-to-canonical."""
        promote = _load(REPO_ROOT / "tools" / "promote-mined-to-canonical.py",
                        "_promote_mined_for_zkbugs_dataset_test")
        with tempfile.TemporaryDirectory() as tmp:
            out_root = Path(tmp)
            self._run(dry_run=False, out_root=out_root)
            inv_files = list((out_root / "invariant_library_extended"
                              / "zkbugs-dataset-test").glob("*.yaml"))
            self.assertTrue(inv_files)
            f = inv_files[0]
            # Parse the JSON body and feed the extractor directly.
            body = f.read_text(encoding="utf-8").split("---\n", 1)[1]
            rec = json.loads(body)
            extracted = promote._extract_invariant_library_extended(
                rec, f, "zkbugs-dataset-test")
            self.assertEqual(len(extracted), 1)
            self.assertTrue(extracted[0]["invariant_id"].startswith("INV-ZKBUGS-"))
            self.assertEqual(extracted[0]["verification_tier"],
                             "tier-2-verified-public-archive")
            self.assertTrue(extracted[0]["statement"])


if __name__ == "__main__":
    unittest.main()
