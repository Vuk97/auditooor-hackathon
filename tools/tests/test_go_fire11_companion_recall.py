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
DETECTOR_DIR = ROOT / "detectors" / "go_wave1"
FIXTURE_DIR = DETECTOR_DIR / "test_fixtures"

CASES = [
    (
        "go-consensus-param-authority-msgserver-fire11",
        "go-consensus-param-authority-msgserver-fire11_positive.go",
        "go-consensus-param-authority-msgserver-fire11_negative.go",
        "consensus-param-corruption",
    ),
    (
        "go-ibc-rate-limit-transfer-scope-fire11",
        "go-ibc-rate-limit-transfer-scope-fire11_positive.go",
        "go-ibc-rate-limit-transfer-scope-fire11_negative.go",
        "ibc-rate-limit-bypass",
    ),
    (
        "go-rounding-direction-accounting-clamp-fire11",
        "go-rounding-direction-accounting-clamp-fire11_positive.go",
        "go-rounding-direction-accounting-clamp-fire11_negative.go",
        "rounding-direction-attack",
    ),
]


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
                [candidate, "-c", "from tree_sitter_language_pack import get_parser; get_parser('go')"],
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


class GoFire11CompanionRecallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.python_ast = _python_with_go_parser()
        if cls.python_ast is None:
            raise unittest.SkipTest("no Python interpreter can load the Go tree-sitter parser")

    def _hits(self, detector: str, fixture: str) -> tuple[int, str]:
        with tempfile.NamedTemporaryFile(prefix=".go_fire11_companion_", suffix=".log") as tmp:
            proc = subprocess.run(
                [
                    self.python_ast,
                    str(TOOL),
                    "--lang",
                    "go",
                    str(FIXTURE_DIR),
                    "--only",
                    detector,
                    "--file",
                    str(FIXTURE_DIR / fixture),
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
            log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")
            return int(match.group(1)), log_text

    def test_detectors_compile(self) -> None:
        for detector, _positive, _negative, _attack_class in CASES:
            with self.subTest(detector=detector):
                py_compile.compile(str(DETECTOR_DIR / f"{detector}.py"), doraise=True)

    def test_positive_fixtures_fire_and_negatives_are_silent(self) -> None:
        for detector, positive, negative, attack_class in CASES:
            with self.subTest(detector=detector):
                positive_hits, positive_log = self._hits(detector, positive)
                negative_hits, negative_log = self._hits(detector, negative)
                self.assertGreaterEqual(positive_hits, 1, positive_log)
                self.assertEqual(negative_hits, 0, negative_log)
                self.assertIn(attack_class, positive_log)


if __name__ == "__main__":
    unittest.main()
