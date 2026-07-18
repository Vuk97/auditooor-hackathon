from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
COSMOS_RUNNER = ROOT / "tools" / "cosmos-detector-runner.py"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-class-map-builder.py"


CASES = {
    "w68-consensus-param-corruption-no-validate": {
        "attack_class": "consensus-param-corruption",
        "reference": ROOT / "reference" / "patterns.dsl" / "w68-consensus-param-corruption-no-validate.yaml",
        "positive": ROOT / "detectors" / "fixtures" / "w68_consensus_param_corruption_no_validate" / "positive",
        "clean": ROOT / "detectors" / "fixtures" / "w68_consensus_param_corruption_no_validate" / "clean",
        "positive_tokens": [
            "func (k Keeper) UpdateConsensusParams",
            "k.SetConsensusParams(ctx, params)",
        ],
        "positive_absent": ["params.Validate()"],
        "clean_tokens": [
            "func (k Keeper) UpdateConsensusParams",
            "params.Validate()",
        ],
        "expected_hits": 1,
    },
    "w68-ibc-rate-limit-bypass-packet-handler": {
        "attack_class": "ibc-rate-limit-bypass",
        "reference": ROOT / "reference" / "patterns.dsl" / "w68-ibc-rate-limit-bypass-packet-handler.yaml",
        "positive": ROOT / "detectors" / "fixtures" / "w68_ibc_rate_limit_bypass_packet_handler" / "positive",
        "clean": ROOT / "detectors" / "fixtures" / "w68_ibc_rate_limit_bypass_packet_handler" / "clean",
        "positive_tokens": [
            "func (im IBCModule) OnRecvPacket",
            "SendCoinsFromModuleToAccount",
            "func (im IBCModule) OnTimeoutPacket",
        ],
        "positive_absent": ["CheckRateLimitAndUpdateFlow", "UndoSend"],
        "clean_tokens": [
            "CheckRateLimitAndUpdateFlow",
            "UndoSend",
        ],
        "expected_hits": 2,
    },
    "w68-subaccount-isolation-bypass-missing-owner-check": {
        "attack_class": "sub-account-isolation-bypass",
        "reference": ROOT / "reference" / "patterns.dsl" / "w68-subaccount-isolation-bypass-missing-owner-check.yaml",
        "positive": ROOT / "detectors" / "fixtures" / "w68_subaccount_isolation_bypass_missing_owner_check" / "positive",
        "clean": ROOT / "detectors" / "fixtures" / "w68_subaccount_isolation_bypass_missing_owner_check" / "clean",
        "positive_tokens": [
            "func (k msgServer) WithdrawFromSubaccount",
            "msg.SubaccountId",
            "MustGetSubaccount",
        ],
        "positive_absent": ["CheckValidSubaccount"],
        "clean_tokens": [
            "CheckValidSubaccount",
            "msg.SubaccountId",
        ],
        "expected_hits": 1,
    },
}


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class W68PhaseBZeroCoverageCosmosPatternsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = _load_module(COSMOS_RUNNER, "cosmos_detector_runner")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder")

    def _findings_payload(self, fixture: Path, pattern: str) -> dict:
        with tempfile.TemporaryDirectory(prefix=f"{pattern}_") as tmp:
            out = Path(tmp) / "findings.json"
            rc = self.runner.run(
                fixture,
                only=pattern,
                patterns_dir=(ROOT / "reference" / "patterns.dsl"),
                out_path=out,
                quiet=True,
            )
            self.assertEqual(rc, 0)
            return json.loads(out.read_text(encoding="utf-8"))

    def test_content_map_classifies_patterns_into_zero_coverage_targets(self) -> None:
        for pattern, meta in CASES.items():
            with self.subTest(pattern=pattern):
                spec = yaml.safe_load(meta["reference"].read_text(encoding="utf-8"))
                result = self.classifier.classify_pattern(spec, pattern)
                self.assertEqual(result["attack_class"], meta["attack_class"])

    def test_reference_yaml_points_at_owned_fixture_pairs(self) -> None:
        for pattern, meta in CASES.items():
            with self.subTest(pattern=pattern):
                reference = meta["reference"].read_text(encoding="utf-8")
                self.assertIn(f"pattern: {pattern}", reference)
                self.assertIn(str(meta["positive"].relative_to(ROOT)), reference)
                self.assertIn(str(meta["clean"].relative_to(ROOT)), reference)

    def test_fixture_pairs_model_vulnerable_and_clean_shapes(self) -> None:
        for pattern, meta in CASES.items():
            with self.subTest(pattern=pattern):
                positive_files = sorted(p for p in meta["positive"].rglob("*.go"))
                clean_files = sorted(p for p in meta["clean"].rglob("*.go"))
                self.assertTrue(positive_files, f"missing go files for {pattern} positive")
                self.assertTrue(clean_files, f"missing go files for {pattern} clean")

                positive_text = "\n".join(p.read_text(encoding="utf-8") for p in positive_files)
                clean_text = "\n".join(p.read_text(encoding="utf-8") for p in clean_files)
                for token in meta["positive_tokens"]:
                    self.assertIn(token, positive_text)
                for token in meta["positive_absent"]:
                    self.assertNotIn(token, positive_text)
                for token in meta["clean_tokens"]:
                    self.assertIn(token, clean_text)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        for pattern, meta in CASES.items():
            with self.subTest(pattern=pattern):
                positive_payload = self._findings_payload(meta["positive"], pattern)
                self.assertEqual(
                    positive_payload["summary"]["findings_count"],
                    meta["expected_hits"],
                )
                self.assertEqual(
                    {finding["pattern"] for finding in positive_payload["findings"]},
                    {pattern},
                )

                clean_payload = self._findings_payload(meta["clean"], pattern)
                self.assertEqual(clean_payload["summary"]["findings_count"], 0)
                self.assertEqual(clean_payload["findings"], [])


if __name__ == "__main__":
    unittest.main()
