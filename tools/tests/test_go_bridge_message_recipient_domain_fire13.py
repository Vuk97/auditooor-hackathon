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
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-bridge-message-recipient-domain-fire13.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-bridge-message-recipient-domain-fire13"
POSITIVE = FIXTURE_DIR / f"{PATTERN}_positive.go"
CLEAN = FIXTURE_DIR / f"{PATTERN}_negative.go"
HELD_OUT_POSITIVE = (
    FIXTURE_DIR / "go-bridge-message-recipient-validation-missing_positive.go"
)
HELD_OUT_NEGATIVE = (
    FIXTURE_DIR / "go-bridge-message-recipient-validation-missing_negative.go"
)


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


class GoBridgeMessageRecipientDomainFire13Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_bridge_domain_fire13_", suffix=".log") as tmp:
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
            return int(match.group(1)), proc.stdout

    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_and_clean_fixture_is_silent(self) -> None:
        positive_hits, positive_stdout = self._hits(POSITIVE)
        clean_hits, clean_stdout = self._hits(CLEAN)
        self.assertEqual(positive_hits, 1, positive_stdout)
        self.assertEqual(clean_hits, 0, clean_stdout)

    def test_pre_existing_held_out_miss_fires(self) -> None:
        held_out_hits, held_out_stdout = self._hits(HELD_OUT_POSITIVE)
        clean_hits, clean_stdout = self._hits(HELD_OUT_NEGATIVE)
        self.assertEqual(held_out_hits, 1, held_out_stdout)
        self.assertEqual(clean_hits, 0, clean_stdout)

    def test_duplicate_context_is_locked_to_nearby_detectors(self) -> None:
        existing = [
            "go-bridge-message-recipient-validation-missing.py",
            "go-bridge-transferout-recipient-binding-missing.py",
            "go-bridge-daemon-event-domain-binding-missing.py",
        ]
        for name in existing:
            self.assertTrue((ROOT / "detectors" / "go_wave1" / name).exists(), name)


if __name__ == "__main__":
    unittest.main()
