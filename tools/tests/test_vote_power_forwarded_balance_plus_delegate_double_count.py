from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
TOOL = ROOT / "tools" / "pattern-compile.py"
PATTERN = "vote-power-forwarded-balance-plus-delegate-double-count"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave17" / "vote_power_forwarded_balance_plus_delegate_double_count.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "vote_power_forwarded_balance_plus_delegate_double_count"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"

W68_DIRECT_POSITIVE = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "vote_double_count_positive.sol"
W68_DIRECT_CLEAN = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "vote_double_count_clean.sol"
REASSIGN_POSITIVE = ROOT / "detectors" / "fixtures" / "delegation_reassignment_stale_vote_source" / "positive.sol"
REASSIGN_CLEAN = ROOT / "detectors" / "fixtures" / "delegation_reassignment_stale_vote_source" / "clean.sol"


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


class VotePowerForwardedBalancePlusDelegateDoubleCountTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
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
        return int(match.group(1)), proc.stdout

    def test_pattern_compile_round_trip_matches_generated_detector(self) -> None:
        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(
            prefix=".pattern_compile_vote_forwarded_balance_",
            dir=ROOT,
        ) as tmp:
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

    def test_reference_yaml_fixture_and_smoke_metadata_stay_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        yaml_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn("vuln: detectors/fixtures/vote_power_forwarded_balance_plus_delegate_double_count/positive.sol", yaml_text)
        self.assertIn("clean: detectors/fixtures/vote_power_forwarded_balance_plus_delegate_double_count/clean.sol", yaml_text)
        self.assertIn("_weightList[i] = carriedWeight + delegatedPower[_tokenId];", positive_text)
        self.assertIn("_vote(nextPeriod, _tokenId, _poolList, _weightList);", positive_text)
        self.assertNotIn("period[nextPeriod].voted[_tokenId] = true;", positive_text)
        self.assertIn("period[nextPeriod].voted[_tokenId] = true;", clean_text)
        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["attack_class"], "vote-double-count")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_clean_fixture_is_quiet(self) -> None:
        hits, log_text = self._hits(POSITIVE)
        self.assertEqual(hits, 1, log_text)
        hits, log_text = self._hits(CLEAN)
        self.assertEqual(hits, 0, log_text)

    def test_named_miss_and_adjacent_controls_have_expected_scope(self) -> None:
        hits, log_text = self._hits(W68_DIRECT_POSITIVE)
        self.assertEqual(hits, 1, log_text)
        hits, log_text = self._hits(W68_DIRECT_CLEAN)
        self.assertEqual(hits, 0, log_text)

        hits, log_text = self._hits(REASSIGN_POSITIVE)
        self.assertEqual(hits, 0, log_text)
        hits, log_text = self._hits(REASSIGN_CLEAN)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
