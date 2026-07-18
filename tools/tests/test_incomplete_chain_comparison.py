from __future__ import annotations

import json
import os
import py_compile
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "incomplete-chain-comparison"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave17"
    / "incomplete_chain_comparison.py"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "incomplete_chain_comparison"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"


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
            probe = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class IncompleteChainComparisonTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreter")

        script = r"""
import importlib.util
import logging
import os
import sys
from pathlib import Path
from slither import Slither

root = Path(sys.argv[1])
detector_path = Path(sys.argv[2])
fixture = Path(sys.argv[3])
pattern = sys.argv[4]
sys.path.insert(0, str(root / "detectors"))

spec = importlib.util.spec_from_file_location("incomplete_chain_comparison", detector_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
slither = Slither(str(fixture))
hits = 0
logger = logging.getLogger(f"auditooor.{pattern}.test")
for compilation_unit in slither.compilation_units:
    detector = module.IncompleteChainComparison(compilation_unit, slither, logger)
    hits += len(detector.detect())
print(hits)
"""
        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        proc = subprocess.run(
            [slither_python, "-c", script, str(ROOT), str(DETECTOR), str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        return int(proc.stdout.strip().splitlines()[-1])

    def test_detector_compiles_and_reference_points_at_owned_fixtures(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        reference = REFERENCE.read_text(encoding="utf-8")
        self.assertIn("vuln: detectors/fixtures/incomplete_chain_comparison/positive.sol", reference)
        self.assertIn("clean: detectors/fixtures/incomplete_chain_comparison/clean.sol", reference)
        self.assertIn("Fixture-smoke/source-shape proof only", reference)

    def test_smoke_metadata_marks_not_submit_ready(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["detector_slug"], "incomplete_chain_comparison")
        self.assertEqual(payload["detector_path"], "detectors/wave17/incomplete_chain_comparison.py")
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertIn("detectors/run_custom.py", payload["positive_command"])
        self.assertIn("detectors/run_custom.py", payload["clean_command"])
        self.assertIn("detectors/fixtures/incomplete_chain_comparison/positive.sol", payload["positive_command"])
        self.assertIn("detectors/fixtures/incomplete_chain_comparison/clean.sol", payload["clean_command"])
        self.assertIn("python3 detectors/run_custom.py", payload["positive_command"])
        self.assertIn("python3 detectors/run_custom.py", payload["clean_command"])
        self.assertNotIn("/opt/homebrew", payload["positive_command"])
        self.assertNotIn("/opt/homebrew", payload["clean_command"])
        self.assertIn("source-shape proof only", payload["limitation_note"])

    def test_fixture_pair_models_missing_vs_present_chain_comparison(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("tokenset[i].tokenAddress == addressList[i]", positive)
        self.assertNotIn("tokenset[i].chain", positive)
        self.assertIn("keccak256(bytes(tokenset[i].chain)) == keccak256(bytes(expectedChain))", clean)
        self.assertNotIn("_same(tokenset[i].chain, expectedChain)", clean)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
