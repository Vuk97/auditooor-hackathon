from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "missing-zero-check-on-vaultaddress-in-depositandstake"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "syntax_broken"
    / "missing_zero_check_on_vaultaddress_in_depositandstake.py"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "missing_zero_check_on_vaultaddress_in_depositandstake"
HYPHEN_FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "missing-zero-check-on-vaultaddress-in-depositandstake"
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


class MissingZeroCheckOnVaultaddressInDepositandstakeTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        script = textwrap.dedent(
            """
            import importlib.util
            import logging
            import sys
            from pathlib import Path

            from slither import Slither

            root = Path(sys.argv[1])
            fixture = Path(sys.argv[2])
            detector_path = Path(sys.argv[3])
            sys.path.insert(0, str(root / "detectors"))

            spec = importlib.util.spec_from_file_location("zero_vault_row_detector", detector_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            slither = Slither(str(fixture))
            hits = 0
            logger = logging.getLogger("auditooor.fixture-smoke")
            for compilation_unit in slither.compilation_units:
                detector = module.MissingZeroCheckOnVaultaddressInDepositandstake(
                    compilation_unit,
                    slither,
                    logger,
                )
                hits += len(detector.detect())
            print(f"total hits: {hits}")
            """
        )
        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, "-c", script, str(ROOT), str(fixture), str(DETECTOR)],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_compiles_and_declares_not_submit_ready_posture(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{PATTERN}"', text)
        self.assertIn("NOT_SUBMIT_READY", text)
        self.assertIn("fixture-smoke/source-shape proof only", text)
        self.assertIn("_POOL_TOKEN_ASSERT", text)
        self.assertIn("_ZERO_ADDRESS_GUARD", text)

    def test_reference_yaml_points_at_owned_fixture_mirrors(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")
        self.assertIn(str(POSITIVE.relative_to(ROOT)), text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), text)
        self.assertIn(str((HYPHEN_FIXTURE_DIR / "positive.sol").relative_to(ROOT)), text)
        self.assertIn(str((HYPHEN_FIXTURE_DIR / "clean.sol").relative_to(ROOT)), text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", text)

    def test_fixture_mirrors_and_smoke_record_capture_posture(self) -> None:
        self.assertEqual(
            POSITIVE.read_text(encoding="utf-8"),
            (HYPHEN_FIXTURE_DIR / "positive.sol").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            CLEAN.read_text(encoding="utf-8"),
            (HYPHEN_FIXTURE_DIR / "clean.sol").read_text(encoding="utf-8"),
        )

        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("vaultAddress != address(0)", payload["limitation_note"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
