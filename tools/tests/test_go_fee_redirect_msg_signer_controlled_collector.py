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
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-fee-redirect-msg-signer-controlled-collector.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-fee-redirect-msg-signer-controlled-collector"
EXISTING_SINK_PATTERN = "go-fee-redirect-user-controlled-sink"
POSITIVE = FIXTURE_DIR / f"{PATTERN}_positive.go"
CLEAN = FIXTURE_DIR / f"{PATTERN}_negative.go"


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


class GoFeeRedirectMsgSignerControlledCollectorTest(unittest.TestCase):
    def _hits(self, fixture: Path, pattern: str = PATTERN) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_fee_redirect_signer_", suffix=".log") as tmp:
            proc = subprocess.run(
                [
                    python_ast,
                    str(TOOL),
                    "--lang",
                    "go",
                    str(FIXTURE_DIR),
                    "--only",
                    pattern,
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

    def test_existing_user_controlled_sink_detector_does_not_catch_positive(self) -> None:
        existing_hits, existing_stdout = self._hits(POSITIVE, EXISTING_SINK_PATTERN)
        self.assertEqual(existing_hits, 0, existing_stdout)

    def test_fixtures_lock_signer_sink_and_configured_collector_controls(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")
        self.assertIn("msg.GetSigners()", positive)
        self.assertIn("collector := signers[0]", positive)
        self.assertIn("protocolFee", positive)
        self.assertIn("params.FeeCollector", clean)
        self.assertIn("params.Treasury", clean)


if __name__ == "__main__":
    unittest.main()
