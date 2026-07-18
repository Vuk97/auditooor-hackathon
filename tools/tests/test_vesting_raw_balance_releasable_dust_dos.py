from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "pattern-compile.py"
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "vesting-raw-balance-releasable-dust-dos"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave17" / "vesting_raw_balance_releasable_dust_dos.py"
POSITIVE = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"
SOLODIT_POSITIVE = (
    ROOT
    / "detectors"
    / "fixtures"
    / "a_malicious_user_could_dos_a_vesting_schedule_by_sending_only_1"
    / "ssi-fix-041_positive.sol"
)
SOLODIT_CLEAN = (
    ROOT
    / "detectors"
    / "fixtures"
    / "a_malicious_user_could_dos_a_vesting_schedule_by_sending_only_1"
    / "ssi-fix-041_clean.sol"
)


def _load_pattern_compile():
    spec = importlib.util.spec_from_file_location("pattern_compile", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
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


class VestingRawBalanceReleasableDustDosTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_pattern_compile_strict_round_trip(self) -> None:
        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(prefix=".pattern_compile_vesting_raw_balance_", dir=ROOT) as tmp:
            out_dir = Path(tmp) / "wave17"
            compiled = compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(compiled)
            generated = out_dir / "vesting_raw_balance_releasable_dust_dos.py"
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")
            py_compile.compile(str(generated), doraise=True)
            self.assertTrue(DETECTOR.is_file())
            py_compile.compile(str(DETECTOR), doraise=True)

    def test_fixture_sources_model_the_source_backed_shape(self) -> None:
        reference = REFERENCE.read_text(encoding="utf-8")
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("Solodit #7003", reference)
        self.assertIn("promotion_allowed: false", reference)
        self.assertIn("token.balanceOf(address(this)) * elapsed", positive)
        self.assertIn("schedule.totalAllocated * elapsed", clean)
        self.assertIn("rescueUnaccountedDust", clean)

    def test_positive_fixture_fires_and_clean_fixture_is_silent(self) -> None:
        positive_hits, positive_output = self._hits(POSITIVE)
        clean_hits, clean_output = self._hits(CLEAN)

        self.assertGreaterEqual(positive_hits, 1, positive_output)
        self.assertEqual(clean_hits, 0, clean_output)

    def test_solodit_7003_fixture_pair_replays(self) -> None:
        positive_hits, positive_output = self._hits(SOLODIT_POSITIVE)
        clean_hits, clean_output = self._hits(SOLODIT_CLEAN)

        self.assertGreaterEqual(positive_hits, 1, positive_output)
        self.assertEqual(clean_hits, 0, clean_output)


if __name__ == "__main__":
    unittest.main()
