from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import unittest
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
TOOL = ROOT / "tools" / "pattern-compile.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "a_malicious_staker_can_delay_the_increase_of_any_delegator_s_vot"
PATTERN = "a-malicious-staker-can-delay-the-increase-of-any-delegator-s-vot"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave17" / "a_malicious_staker_can_delay_the_increase_of_any_delegator_s_vot.py"
POSITIVE = FIXTURE_DIR / "ssi-fix-033_positive.sol"
CLEAN = FIXTURE_DIR / "ssi-fix-033_clean.sol"
SMOKE = FIXTURE_DIR / "ssi-fix-033_smoke.json"


def _load_pattern_compile():
    spec = importlib.util.spec_from_file_location("pattern_compile", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _slither_python() -> str | None:
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


class MaliciousStakerVoteDelaySmokeTests(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _slither_python()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
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
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_pattern_compile_round_trip_matches_generated_detector(self) -> None:
        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(
            prefix=".pattern_compile_a_malicious_staker_vote_delay_",
            dir=ROOT,
        ) as tmp:
            out_dir = Path(tmp) / "wave17"
            compiled = compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=False,
            )
            self.assertTrue(compiled)
            generated = out_dir / DETECTOR.name
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")
            self.assertEqual(
                DETECTOR.read_text(encoding="utf-8"),
                generated.read_text(encoding="utf-8"),
            )

    def test_reference_yaml_points_at_owned_fixture_pair(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")
        self.assertIn(
            "vuln: detectors/fixtures/a_malicious_staker_can_delay_the_increase_of_any_delegator_s_vot/ssi-fix-033_positive.sol",
            text,
        )
        self.assertIn(
            "clean: detectors/fixtures/a_malicious_staker_can_delay_the_increase_of_any_delegator_s_vot/ssi-fix-033_clean.sol",
            text,
        )

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)

    def test_smoke_record_is_consistent(self) -> None:
        self.assertTrue(SMOKE.is_file(), f"missing smoke record: {SMOKE}")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertGreater(payload.get("positive_hits", 0), 0)
        self.assertEqual(payload.get("clean_hits"), 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")


if __name__ == "__main__":
    unittest.main()
