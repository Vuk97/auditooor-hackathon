from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
TOOL = ROOT / "tools" / "pattern-compile.py"
PATTERN = "rs-rewards-duplicate-pair-key-missing-pool-identity"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave17" / "rs_rewards_duplicate_pair_key_missing_pool_identity.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "rs_rewards_duplicate_pair_key_missing_pool_identity"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"


def _load_pattern_compile():
    spec = importlib.util.spec_from_file_location("pattern_compile", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


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


class RsRewardsDuplicatePairKeyMissingPoolIdentityTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        self.assertNotIn("UNKNOWN predicate key", proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_pattern_compile_round_trip_matches_generated_detector(self) -> None:
        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(prefix=".pattern_compile_rs_rewards_", dir=ROOT) as tmp:
            out_dir = Path(tmp) / "wave17"
            compiled = compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(compiled)
            generated = out_dir / DETECTOR.name
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")
            self.assertEqual(
                DETECTOR.read_text(encoding="utf-8"),
                generated.read_text(encoding="utf-8"),
            )

    def test_reference_and_fixture_metadata(self) -> None:
        reference_text = REFERENCE.read_text(encoding="utf-8")
        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        smoke_text = SMOKE.read_text(encoding="utf-8")

        self.assertIn(f"pattern: {PATTERN}", reference_text)
        self.assertIn("fire4-rwrq-rewards-distribution-skew-8542fded6d21", reference_text)
        self.assertIn("token pair", reference_text)
        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("canonical pool identity", detector_text)

        self.assertIn("mapping(bytes32 => uint256) public rewardsByPair;", positive_text)
        self.assertIn("rewardsByPair[pair] += amount;", positive_text)
        self.assertIn("bytes32 fullPoolIdentity", positive_text)

        self.assertIn("mapping(bytes32 => bytes32) public canonicalPoolForPair;", clean_text)
        self.assertIn("require(canonicalPoolForPair[pair] == poolId", clean_text)
        self.assertIn('"pattern": "rs-rewards-duplicate-pair-key-missing-pool-identity"', smoke_text)
        self.assertIn('"positive_hits": 2', smoke_text)
        self.assertIn('"clean_hits": 0', smoke_text)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
