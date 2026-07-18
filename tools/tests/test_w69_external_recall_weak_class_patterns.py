from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-class-map-builder.py"
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
RUN_CUSTOM = ROOT / "detectors" / "run_custom.py"

CASES = {
    "w69-erc1155-order-fill-callback-reentrancy": {
        "attack_class": "reentrancy-cross-contract",
        "reference": ROOT / "reference" / "patterns.dsl" / "w69-erc1155-order-fill-callback-reentrancy.yaml",
        "fixture": ROOT / "detectors" / "fixtures" / "w69_erc1155_order_fill_callback_reentrancy",
        "positive_tokens": [
            "safeTransferFrom(",
            "order.filledAmount += amount",
            "emit OrderFilled",
        ],
        "clean_tokens": [
            "external nonReentrant",
            "order.filledAmount = nextFilled",
            "safeTransferFrom(",
        ],
        "expected_hits": 1,
    },
    "w69-bridge-payload-recipient-unchecked": {
        "attack_class": "missing-recipient-validation",
        "reference": ROOT / "reference" / "patterns.dsl" / "w69-bridge-payload-recipient-unchecked.yaml",
        "fixture": ROOT / "detectors" / "fixtures" / "w69_bridge_payload_recipient_unchecked",
        "positive_tokens": [
            "abi.decode(payload, (address, uint256))",
            "token.safeTransfer(recipient, amount)",
        ],
        "clean_tokens": [
            "recipient == address(0)",
            "expectedRecipient",
            "token.safeTransfer(recipient, amount)",
        ],
        "expected_hits": 1,
    },
    "w69-vault-share-mint-division-before-multiplication": {
        "attack_class": "fund-loss-via-arithmetic",
        "reference": ROOT / "reference" / "patterns.dsl" / "w69-vault-share-mint-division-before-multiplication.yaml",
        "fixture": ROOT / "detectors" / "fixtures" / "w69_vault_share_mint_division_before_multiplication",
        "positive_tokens": [
            "shares = assets / totalAssets() * totalSupply()",
            "asset.safeTransferFrom(msg.sender, address(this), assets)",
            "_mint(receiver, shares)",
        ],
        "clean_tokens": [
            "Math.mulDiv",
            "if (shares == 0) revert ZeroShares()",
            "_mint(receiver, shares)",
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


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            proc = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return candidate
    return None


class W69ExternalRecallWeakClassPatternsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder")
        cls.backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest")

    def test_patterns_compile_under_strict_guards(self) -> None:
        for pattern, meta in CASES.items():
            with self.subTest(pattern=pattern):
                with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
                    ok = self.compiler.compile_pattern(
                        meta["reference"],
                        Path(tmp) / "wave69",
                        strict_yaml_shapes=True,
                        strict_unsupported_keys=True,
                    )
                self.assertTrue(ok)

    def test_content_map_classifies_patterns_into_phase_e_targets(self) -> None:
        for pattern, meta in CASES.items():
            with self.subTest(pattern=pattern):
                spec = yaml.safe_load(meta["reference"].read_text(encoding="utf-8"))
                result = self.classifier.classify_pattern(spec, pattern)
                self.assertEqual(result["attack_class"], meta["attack_class"])
                self.assertEqual(
                    self.backtest.derive_attack_class(pattern, spec.get("tags")),
                    meta["attack_class"],
                )

    def test_reference_yaml_points_at_owned_fixture_pairs(self) -> None:
        for pattern, meta in CASES.items():
            with self.subTest(pattern=pattern):
                reference = meta["reference"].read_text(encoding="utf-8")
                self.assertIn(f"pattern: {pattern}", reference)
                self.assertIn(str((meta["fixture"] / "positive.sol").relative_to(ROOT)), reference)
                self.assertIn(str((meta["fixture"] / "clean.sol").relative_to(ROOT)), reference)

    def test_fixture_pairs_model_vulnerable_and_clean_shapes(self) -> None:
        for pattern, meta in CASES.items():
            with self.subTest(pattern=pattern):
                positive = (meta["fixture"] / "positive.sol").read_text(encoding="utf-8")
                clean = (meta["fixture"] / "clean.sol").read_text(encoding="utf-8")
                for token in meta["positive_tokens"]:
                    self.assertIn(token, positive)
                for token in meta["clean_tokens"]:
                    self.assertIn(token, clean)

    def test_smoke_records_capture_positive_and_clean_counts(self) -> None:
        for pattern, meta in CASES.items():
            with self.subTest(pattern=pattern):
                payload = json.loads((meta["fixture"] / "smoke.json").read_text(encoding="utf-8"))
                self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
                self.assertEqual(payload["pattern"], pattern)
                self.assertEqual(payload["positive_hits"], meta["expected_hits"])
                self.assertEqual(payload["clean_hits"], 0)

    def test_generated_wave69_modules_are_checked_in(self) -> None:
        for pattern in CASES:
            with self.subTest(pattern=pattern):
                module_path = ROOT / "detectors" / "wave69" / f"{pattern.replace('-', '_')}.py"
                self.assertTrue(module_path.is_file())
                source = module_path.read_text(encoding="utf-8")
                self.assertIn(f'ARGUMENT = "{pattern}"', source)

    def test_run_custom_sees_generated_wave69_detectors(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        for pattern, meta in CASES.items():
            for fixture_name, expected_hits in (
                ("positive.sol", meta["expected_hits"]),
                ("clean.sol", 0),
            ):
                with self.subTest(pattern=pattern, fixture=fixture_name):
                    proc = subprocess.run(
                        [
                            python,
                            str(RUN_CUSTOM),
                            str(meta["fixture"] / fixture_name),
                            pattern,
                        ],
                        cwd=ROOT,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=120,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stdout)
                    self.assertIn("[ok] loaded 1 custom detector(s)", proc.stdout)
                    self.assertIn(f"=== Running {pattern} ===", proc.stdout)
                    self.assertIn(f"[done] total hits: {expected_hits}", proc.stdout)

    def test_direct_pattern_runner_positive_fires_and_clean_stays_quiet(self) -> None:
        if _python_with_slither() is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        engine = self.backtest._import_engine()
        for pattern, meta in CASES.items():
            with self.subTest(pattern=pattern):
                spec = yaml.safe_load(meta["reference"].read_text(encoding="utf-8"))
                positive_hits, positive_error = self.backtest.run_pattern_on_file(
                    spec,
                    meta["fixture"] / "positive.sol",
                    engine,
                )
                self.assertIsNone(positive_error)
                self.assertEqual(positive_hits, meta["expected_hits"])

                clean_hits, clean_error = self.backtest.run_pattern_on_file(
                    spec,
                    meta["fixture"] / "clean.sol",
                    engine,
                )
                self.assertIsNone(clean_error)
                self.assertEqual(clean_hits, 0)


if __name__ == "__main__":
    unittest.main()
