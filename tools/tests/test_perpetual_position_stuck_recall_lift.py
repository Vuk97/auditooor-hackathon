from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "pattern-compile.py"
PATTERN = "perpetual-position-stuck-umbrella"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "perpetual_position_stuck_umbrella"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
RUNNER = ROOT / "detectors" / "run_custom.py"


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
        "/opt/homebrew/opt/python@3.14/bin/python3.14",
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


class PerpetualPositionStuckRecallLiftTest(unittest.TestCase):
    def _runner_hits(self, path: Path) -> int:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [python, str(RUNNER), str(path), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("[ok] loaded 1 custom detector(s) (tier filter: S,E,A default)", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_pattern_compile_strict_round_trip(self) -> None:
        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(prefix=".pattern_compile_perp_stuck_", dir=ROOT) as tmp:
            out_dir = Path(tmp) / "wave17"
            compiled = compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(compiled)
            generated = out_dir / "perpetual_position_stuck_umbrella.py"
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")
            py_compile.compile(str(generated), doraise=True)
            generated_text = generated.read_text(encoding="utf-8")
            self.assertIn(f'ARGUMENT = "{PATTERN}"', generated_text)
            self.assertIn("unliquidatable or uncloseable", generated_text)

    def test_dsl_generalizes_three_same_class_branches(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        self.assertEqual(spec["pattern"], PATTERN)
        self.assertEqual(spec["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(spec["promotion_allowed"])
        self.assertEqual(spec["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(spec["fixtures"]["vuln"], str(POSITIVE.relative_to(ROOT)))
        self.assertEqual(spec["fixtures"]["clean"], str(CLEAN.relative_to(ROOT)))

        match_text = "\n".join(str(item) for item in spec["match"])
        self.assertIn("positionIdList", match_text)
        self.assertIn("accountPositions", match_text)
        self.assertIn("wasLiquidated", match_text)
        self.assertIn("liquidationNonce", match_text)
        self.assertIn("minDebt", match_text)
        self.assertIn("dustThreshold", match_text)
        self.assertIn("MAX_POSITIONS_PER_ACCOUNT", match_text)

        description = spec["wiki_description"]
        self.assertIn("attacker-grown position list", description)
        self.assertIn("post-liquidation exit/redeem", description)
        self.assertIn("dust/minimum-position thresholds", description)

    def test_fixtures_cover_vulnerable_and_clean_shapes(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("contract VulnPerpetualPositionStuck", positive)
        self.assertIn("acc.options.length", positive)
        self.assertIn("contract VulnExitAfterLiquidationStuck", positive)
        self.assertIn("payout = position.collateral - position.debt;", positive)
        self.assertIn("position.margin -= position.debt;", positive)
        self.assertIn("contract VulnDustThresholdCloseStuck", positive)
        self.assertIn("remainingDebt >= minDebt", positive)
        self.assertNotIn("wasLiquidated", positive)
        self.assertNotIn("MAX_POSITIONS_PER_ACCOUNT", positive)

        self.assertIn("contract CleanPerpetualPositions", clean)
        self.assertIn("MAX_OPTIONS", clean)
        self.assertIn("positionId < accountOptions[account].length", clean)
        self.assertIn("contract CleanExitAfterLiquidation", clean)
        self.assertIn("bool wasLiquidated;", clean)
        self.assertIn("if (position.wasLiquidated)", clean)
        self.assertIn("contract CleanDustThresholdClose", clean)
        self.assertIn("remainingDebt > 0 && remainingDebt < minDebt", clean)
        self.assertIn('require(repayAmount > 0, "zero close");', clean)

    def test_generated_detector_default_tier_hits_positive_and_skips_clean(self) -> None:
        self.assertEqual(self._runner_hits(POSITIVE), 4)
        self.assertEqual(self._runner_hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
