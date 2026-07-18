from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "lang-detect.py"
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-rounding-direction-fee-fire32.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-rounding-direction-fee-fire32"
POSITIVE = FIXTURE_DIR / f"{PATTERN}_positive.go"
NEGATIVE = FIXTURE_DIR / f"{PATTERN}_negative.go"


def _python_with_go_parser() -> str | None:
    candidates = [
        os.environ.get("AUDITOOOR_PYTHON_AST"),
        sys.executable,
        "python3",
        "python3.14",
        "python3.13",
        "python3.12",
        "python3.11",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [
                    candidate,
                    "-c",
                    "from tree_sitter_language_pack import get_parser; get_parser('go')",
                ],
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


class GoRoundingDirectionFeeFire32Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_rounding_direction_fee_fire32_", suffix=".log") as tmp:
            proc = subprocess.run(
                [
                    python_ast,
                    str(TOOL),
                    "--lang",
                    "go",
                    str(FIXTURE_DIR),
                    "--only",
                    PATTERN,
                    "--file",
                    str(fixture),
                    "--log",
                    tmp.name,
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            match = re.search(r"total hits:\s*(\d+)", proc.stdout)
            self.assertIsNotNone(match, proc.stdout)
            log_text = Path(tmp.name).read_text(encoding="utf-8")
            return int(match.group(1)), proc.stdout + "\n" + log_text

    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_stdout = self._hits(POSITIVE)
        negative_hits, negative_stdout = self._hits(NEGATIVE)
        self.assertEqual(positive_hits, 3, positive_stdout)
        self.assertEqual(negative_hits, 0, negative_stdout)
        self.assertIn("user-favorable rounding direction", positive_stdout)
        self.assertIn("class: rounding-direction-attack", positive_stdout)

    def test_fixtures_lock_rounding_and_guard_boundaries(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        detector = DETECTOR.read_text(encoding="utf-8")
        self.assertIn("fee := notional * ProtocolFeeBps / 10_000", positive)
        self.assertIn("penaltyDebt := pos.Debt * 105 / 100", positive)
        self.assertIn("requiredDebt := pos.Debt * pos.MaintenanceBps / 10_000", positive)
        self.assertIn("ceilDiv(notional*ProtocolFeeBps, 10_000)", negative)
        self.assertIn("(pos.Debt*105)%100 != 0", negative)
        self.assertIn("requiredDebt == 0", negative)
        self.assertIn("attack_class: rounding-direction-attack", detector)


if __name__ == "__main__":
    unittest.main()
