#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "circom_wave1" / "zkbugs_num2bits_254_state_alias.py"
RUNNER = ROOT / "tools" / "circom-detect.py"


def _load_detector():
    spec = importlib.util.spec_from_file_location("zkbugs_circom_num2bits", DETECTOR)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkBugsCircomNum2BitsDetectorTest(unittest.TestCase):
    def test_flags_state_bits_above_bn254_margin(self) -> None:
        detector = _load_detector()
        source = """
        template BlacklistLeafState() {
            signal input blacklistLeaf;
            component leafBits = Num2Bits(254);
            leafBits.in <== blacklistLeaf;
            state <== leafBits.out[251] + leafBits.out[252] + leafBits.out[253];
        }
        """
        self.assertEqual(len(detector.num2bits_254_state_alias_offsets(source)), 1)

    def test_ignores_low_width_decomposition(self) -> None:
        detector = _load_detector()
        source = """
        template LowBits() {
            signal input leaf;
            component bits = Num2Bits(64);
            bits.in <== leaf;
            tag <== bits.out[0] + bits.out[1];
        }
        """
        self.assertEqual(detector.num2bits_254_state_alias_offsets(source), [])

    def test_runner_hits_positive_fixture_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "circom.log"
            fixture_dir = ROOT / "detectors" / "circom_wave1" / "test_fixtures"
            positive = fixture_dir / "zkbugs_num2bits_254_state_alias_positive.circom"
            negative = fixture_dir / "zkbugs_num2bits_254_state_alias_negative.circom"

            pos = subprocess.run(
                [sys.executable, str(RUNNER), "--only", "zkbugs_num2bits_254_state_alias", "--file", str(positive), "--log", str(log)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(pos.returncode, 0, pos.stderr)
            self.assertIn("(1 hits)", log.read_text(encoding="utf-8"))

            neg = subprocess.run(
                [sys.executable, str(RUNNER), "--only", "zkbugs_num2bits_254_state_alias", "--file", str(negative), "--log", str(log)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(neg.returncode, 0, neg.stderr)
            self.assertIn("(0 hits)", log.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
