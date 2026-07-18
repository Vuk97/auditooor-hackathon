from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "w69-governor-quorum-live-supply-snapshot-mismatch"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
CLASS_MAP = ROOT / "reference" / "detector_class_map_complete.yaml"
SMOKE = ROOT / "detectors" / "fixtures" / "w69_governor_quorum_live_supply_snapshot_mismatch" / "smoke.json"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-class-map-builder.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class W69GovernorQuorumLiveSupplySnapshotMetadataTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder_w69_governance")

    def test_reference_yaml_and_class_map_register_governance_snapshot_mismatch(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        result = self.classifier.classify_pattern(spec, PATTERN)
        class_map = yaml.safe_load(CLASS_MAP.read_text(encoding="utf-8"))
        mapping = class_map["mappings"][PATTERN]

        self.assertEqual(spec["pattern"], PATTERN)
        self.assertEqual(
            spec["fixtures"]["vuln"],
            "detectors/fixtures/w69_governor_quorum_live_supply_snapshot_mismatch/oz_style_positive.sol",
        )
        self.assertEqual(
            spec["fixtures"]["clean"],
            "detectors/fixtures/w69_governor_quorum_live_supply_snapshot_mismatch/oz_style_clean.sol",
        )
        self.assertIn("governance-snapshot-mismatch", spec["tags"])
        self.assertEqual(result["attack_class"], "governance-snapshot-mismatch")
        self.assertEqual(result["evidence"], "tags")
        self.assertEqual(mapping["attack_class"], "governance-snapshot-mismatch")
        self.assertEqual(mapping["has_fixture_pair"], True)

    def test_smoke_sidecar_matches_oz_style_fixture_pair(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)


if __name__ == "__main__":
    unittest.main()
