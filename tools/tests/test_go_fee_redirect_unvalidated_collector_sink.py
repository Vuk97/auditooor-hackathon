from __future__ import annotations

import importlib.util
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
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-fee-redirect-unvalidated-collector-sink.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-fee-redirect-unvalidated-collector-sink"
SIGNER_POSITIVE = FIXTURE_DIR / "go-fee-redirect-msg-signer-controlled-collector_positive.go"
SIGNER_NEGATIVE = FIXTURE_DIR / "go-fee-redirect-msg-signer-controlled-collector_negative.go"
USER_SINK_POSITIVE = FIXTURE_DIR / "go-fee-redirect-user-controlled-sink_positive.go"
USER_SINK_NEGATIVE = FIXTURE_DIR / "go-fee-redirect-user-controlled-sink_negative.go"


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


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GoFeeRedirectUnvalidatedCollectorSinkTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_fee_redirect_shared_", suffix=".log") as tmp:
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

    def test_shared_detector_fires_on_both_fee_redirect_positives(self) -> None:
        signer_hits, signer_stdout = self._hits(SIGNER_POSITIVE)
        user_sink_hits, user_sink_stdout = self._hits(USER_SINK_POSITIVE)
        self.assertEqual(signer_hits, 1, signer_stdout)
        self.assertEqual(user_sink_hits, 1, user_sink_stdout)

    def test_shared_detector_misses_both_paired_negatives(self) -> None:
        signer_hits, signer_stdout = self._hits(SIGNER_NEGATIVE)
        user_sink_hits, user_sink_stdout = self._hits(USER_SINK_NEGATIVE)
        self.assertEqual(signer_hits, 0, signer_stdout)
        self.assertEqual(user_sink_hits, 0, user_sink_stdout)

    def test_slug_derives_fee_redirect_attack_class(self) -> None:
        backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest_go_fee_redirect")
        self.assertEqual(backtest.derive_attack_class(PATTERN, None), "fee-redirect")

    def test_detector_text_encodes_both_source_shapes(self) -> None:
        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn("msg.FeeRecipient", USER_SINK_POSITIVE.read_text(encoding="utf-8"))
        self.assertIn("msg.GetSigners()", SIGNER_POSITIVE.read_text(encoding="utf-8"))
        self.assertIn("_SIGNER_SOURCE_RE", detector_text)
        self.assertIn("_USER_FIELD_RE", detector_text)
        self.assertIn("class: fee-redirect", detector_text)


if __name__ == "__main__":
    unittest.main()
