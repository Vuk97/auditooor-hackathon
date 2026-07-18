from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "glider-enumerable-set-remove-iteration-skip"
DETECTOR = ROOT / "detectors" / "wave17" / "glider_enumerable_set_remove_iteration_skip.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
CLASS_MAP = ROOT / "reference" / "detector_class_map_complete.yaml"
CANONICAL_POSITIVE = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CANONICAL_CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"
UMBRELLA_DIR = ROOT / "detectors" / "fixtures" / "missing_last_element_validation_umbrella"
CACHED_LEN_POSITIVE = UMBRELLA_DIR / "cached_length_enumerable_set_remove_vuln.sol"
CACHED_LEN_CLEAN = UMBRELLA_DIR / "cached_length_enumerable_set_remove_clean.sol"
NESTED_UINT_POSITIVE = UMBRELLA_DIR / "nested_at_remove_uintset_vuln.sol"
NESTED_UINT_CLEAN = UMBRELLA_DIR / "nested_at_remove_uintset_clean.sol"
BYTES32_CACHED_POSITIVE = UMBRELLA_DIR / "bytes32_cached_length_remove_vuln.sol"
BYTES32_CACHED_CLEAN = UMBRELLA_DIR / "bytes32_cached_length_remove_clean.sol"


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


class MissingLastElementValidationRecallLiftTest(unittest.TestCase):
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
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def _assert_pair(self, positive: Path, clean: Path) -> None:
        positive_hits, positive_stdout = self._hits(positive)
        clean_hits, clean_stdout = self._hits(clean)
        self.assertGreaterEqual(positive_hits, 1, positive_stdout)
        self.assertEqual(clean_hits, 0, clean_stdout)

    def test_detector_reference_wiring_mentions_cached_length_variant(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        class_map_text = CLASS_MAP.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("swap-pop EnumerableSet", detector_text)
        self.assertIn("stale cached bound", detector_text)
        self.assertIn("uint(?:256)?", detector_text)
        self.assertIn("length\\\\s*\\\\(\\\\s*\\\\)\\\\s*;\\\\s*for", detector_text)

        self.assertIn(f"pattern: {PATTERN}", reference_text)
        self.assertIn("keep the cursor on the current", reference_text)
        self.assertIn("caches `uint256 len = set.length();`", reference_text)
        self.assertIn("Bytes32Set", reference_text)
        self.assertIn(f"{PATTERN}:", class_map_text)
        self.assertIn("attack_class: missing-last-element-validation", class_map_text)

    def test_canonical_fixture_pair_still_behaves(self) -> None:
        self._assert_pair(CANONICAL_POSITIVE, CANONICAL_CLEAN)

    def test_cached_length_variant_fires_without_broad_clean_fp(self) -> None:
        self._assert_pair(CACHED_LEN_POSITIVE, CACHED_LEN_CLEAN)

    def test_nested_remove_at_index_variant_fires_for_uintset_only_on_vuln(self) -> None:
        self._assert_pair(NESTED_UINT_POSITIVE, NESTED_UINT_CLEAN)

    def test_bytes32_cached_length_variant_fires_without_two_phase_fp(self) -> None:
        self._assert_pair(BYTES32_CACHED_POSITIVE, BYTES32_CACHED_CLEAN)


if __name__ == "__main__":
    unittest.main()
