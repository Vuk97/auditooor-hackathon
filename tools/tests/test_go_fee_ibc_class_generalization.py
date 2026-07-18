from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
COSMOS_RUNNER = ROOT / "tools" / "cosmos-detector-runner.py"
PATTERNS_DIR = ROOT / "reference" / "patterns.dsl"
IBC_SIBLING = "ibc-packet-flow-control-missing"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GoFeeIbcClassGeneralizationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest")
        cls.runner = _load_module(COSMOS_RUNNER, "cosmos_detector_runner")

    def _findings_count(self, fixture: Path, pattern: str) -> int:
        with tempfile.TemporaryDirectory(prefix=f"{pattern}_") as tmp:
            out_path = Path(tmp) / "findings.json"
            rc = self.runner.run(
                fixture,
                only=pattern,
                patterns_dir=PATTERNS_DIR,
                out_path=out_path,
                quiet=True,
            )
            self.assertEqual(rc, 0)
            payload = json.loads(out_path.read_text(encoding="utf-8"))
            return int(payload["summary"]["findings_count"])

    def test_decode_before_fee_is_not_fee_redirect(self) -> None:
        for slug in (
            "cosmos_decode_before_fee_unbounded",
            "go_wave1.cosmos_decode_before_fee_unbounded",
        ):
            with self.subTest(slug=slug):
                self.assertEqual(
                    self.backtest.derive_attack_class(slug, None),
                    "codec-recursion-amplification",
                )
                self.assertNotEqual(
                    self.backtest.derive_attack_class(slug, None),
                    "fee-redirect",
                )

    def test_go_ibc_detector_class_map_is_rate_limit_bypass(self) -> None:
        for slug in (
            "cosmos_ibc_packet_handler_missing_rate_limit",
            "go_wave1.cosmos_ibc_packet_handler_missing_rate_limit",
        ):
            with self.subTest(slug=slug):
                self.assertEqual(
                    self.backtest.derive_attack_class(slug, None),
                    "ibc-rate-limit-bypass",
                )

    def test_ibc_sibling_spec_declares_same_class(self) -> None:
        spec = yaml.safe_load((PATTERNS_DIR / f"{IBC_SIBLING}.yaml").read_text(encoding="utf-8"))
        self.assertEqual(spec["pattern"], IBC_SIBLING)
        self.assertEqual(spec["backend"], "cosmos")
        self.assertIn("ibc-rate-limit-bypass", spec["tags"])
        self.assertEqual(
            self.backtest.derive_attack_class(IBC_SIBLING, spec["tags"]),
            "ibc-rate-limit-bypass",
        )

    def test_ibc_sibling_fixture_pair_and_origin_generalize(self) -> None:
        sibling_pos = ROOT / "detectors" / "fixtures" / "ibc_packet_flow_control_missing" / "positive"
        sibling_clean = ROOT / "detectors" / "fixtures" / "ibc_packet_flow_control_missing" / "clean"
        origin_pos = ROOT / "detectors" / "fixtures" / "w68_ibc_rate_limit_bypass_packet_handler" / "positive"
        origin_clean = ROOT / "detectors" / "fixtures" / "w68_ibc_rate_limit_bypass_packet_handler" / "clean"

        self.assertEqual(self._findings_count(sibling_pos, IBC_SIBLING), 2)
        self.assertEqual(self._findings_count(sibling_clean, IBC_SIBLING), 0)
        self.assertEqual(self._findings_count(origin_pos, IBC_SIBLING), 2)
        self.assertEqual(self._findings_count(origin_clean, IBC_SIBLING), 0)


if __name__ == "__main__":
    unittest.main()
