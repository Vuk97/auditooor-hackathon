from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "impossible-quorum-in-dao-governance"
DETECTOR = ROOT / "detectors" / "wave_graveyard" / "wave13_broken" / "impossible_quorum_in_dao_governance.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "impossible_quorum_in_dao_governance"
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


class ImpossibleQuorumInDaoGovernanceTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
                "--include-graveyard",
                "--tier=ALL",
                str(fixture),
                PATTERN,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_compiles_and_reference_yaml_wires_fixture_pair(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        reference = REFERENCE.read_text(encoding="utf-8")
        self.assertIn(f"pattern: {PATTERN}", reference)
        self.assertIn(
            "vuln: detectors/fixtures/impossible_quorum_in_dao_governance/positive.sol",
            reference,
        )
        self.assertIn(
            "clean: detectors/fixtures/impossible_quorum_in_dao_governance/clean.sol",
            reference,
        )
        self.assertIn("Fixture-smoke approximation only", reference)

    def test_fixture_pair_models_missing_and_present_guard_calls(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("contract ImpossibleQuorumGovernorPositive", positive)
        self.assertIn("function totalSupply() public view returns (uint256)", positive)
        self.assertIn("return totalsuppl + fixedNftVotingPower;", positive)
        self.assertNotIn("return syncQuorumInputs();", positive)

        self.assertIn("contract ImpossibleQuorumGovernorClean", clean)
        self.assertIn("function syncQuorumInputs() internal view returns (uint256)", clean)
        self.assertIn("return syncQuorumInputs();", clean)

    def test_smoke_record_keeps_not_submit_ready_posture(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertIn("Fixture-smoke/source-shape proof only", payload["limitation_note"])
        self.assertIn("--include-graveyard", payload["positive_command"])
        self.assertIn("--include-graveyard", payload["clean_command"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
