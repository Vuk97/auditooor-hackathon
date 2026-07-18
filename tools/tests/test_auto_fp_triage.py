"""auto-fp-triage.py unit tests — parser + classifier coverage.

Background — quoted from auto-improvement queue iter 3
(2026-04-25_23:12:58), Minimax idea 3:

    File: tools/auto-fp-triage.py
    What: Check if `auto-fp-triage.py` has any test file. Likely zero
    coverage on the "mark-as-FP" path. Add tests/test_auto_fp_triage.py
    covering ...
    Success criterion: pytest tests/test_auto_fp_triage.py -v green ...

Kimi precheck (GAP-CONFIRMED):
    `tools/auto-fp-triage.py` exists (9727 bytes). The `tests/` tree holds
    zero Python files (`find /Users/wolf/Downloads/auditooor/tests -name
    '*.py'` returned none). No `test_auto_fp_triage.py` ...

Calibration: Kimi-grep-prechecked. Kimi has a 0/3 audit-style FP rate but a
much higher rate on idea-prechecks; supervisor verified the test gap by
inspection (`find tools/tests -iname "*fp*triage*"` empty) before shipping.

Note on framing: the Minimax idea proposed testing a "mark-as-FP idempotent
retry" / "fp-triage state transition" — those workflows do not exist in
this file, which is a one-shot markdown-table parser → classifier →
markdown-summary writer. We test the actual surface:
  1. `parse_report` extracts (detector, total_hits) from the calibration
     report's "Per-detector FP counts" table.
  2. `classify` maps hit counts to OK / WHITELIST / TIGHTEN / GRAVEYARD
     using the documented thresholds.
  3. `remediation` produces the expected `action` key per verdict.
  4. `main(--calibration-report=<missing>)` returns 0 (graceful skip),
     not a traceback — the documented CI behavior.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "auto-fp-triage.py"


def _load_module() -> types.ModuleType:
    tools_dir = str(REPO / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("auto_fp_triage", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ClassifyTest(unittest.TestCase):
    """Pure-function thresholds: see tool docstring."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_zero_hits_is_ok(self) -> None:
        self.assertEqual(self.t.classify(0), "OK")

    def test_low_hits_is_whitelist(self) -> None:
        # 1..TIGHTEN_THRESHOLD-1 (i.e. 1..4 by default 5).
        for n in range(1, self.t.TIGHTEN_THRESHOLD):
            self.assertEqual(self.t.classify(n), "WHITELIST",
                             f"hits={n} should be WHITELIST")

    def test_mid_hits_is_tighten(self) -> None:
        # TIGHTEN_THRESHOLD..GRAVEYARD_THRESHOLD inclusive.
        self.assertEqual(self.t.classify(self.t.TIGHTEN_THRESHOLD), "TIGHTEN")
        self.assertEqual(self.t.classify(self.t.GRAVEYARD_THRESHOLD), "TIGHTEN")
        mid = (self.t.TIGHTEN_THRESHOLD + self.t.GRAVEYARD_THRESHOLD) // 2
        self.assertEqual(self.t.classify(mid), "TIGHTEN")

    def test_high_hits_is_graveyard(self) -> None:
        self.assertEqual(self.t.classify(self.t.GRAVEYARD_THRESHOLD + 1),
                         "GRAVEYARD")
        self.assertEqual(self.t.classify(self.t.GRAVEYARD_THRESHOLD * 10),
                         "GRAVEYARD")


class ParseReportTest(unittest.TestCase):
    """Markdown-table parsing with the documented row shape."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_parses_per_detector_table_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "FP_CALIBRATION_REPORT.md"
            # Realistic shape: prose section, then "Per-detector FP counts"
            # header, then the table, then a closing section that should be
            # ignored.
            report.write_text(
                "# Calibration Report\n"
                "\n"
                "Some preamble.\n"
                "\n"
                "## Per-detector FP counts\n"
                "\n"
                "| Detector | OZ | Solady | Solmate | Total |\n"
                "|---|---|---|---|---|\n"
                "| `noisy-detector` | 12 | 9 | 4 | 25 |\n"
                "| `tight-detector` | 0 | 0 | 0 | 0 |\n"
                "| `mid-detector`   | 3 | 4 | 1 | 8 |\n"
                "\n"
                "## Notes\n"
                "\n"
                "| Should | Be | Ignored | After | 999 |\n"
            )
            rows = self.t.parse_report(report)
        # Sorted by total desc.
        self.assertEqual(rows[0], ("noisy-detector", 25))
        self.assertEqual(rows[1], ("mid-detector", 8))
        self.assertEqual(rows[2], ("tight-detector", 0))
        # Closing section's row must NOT be present.
        names = [r[0] for r in rows]
        self.assertNotIn("Should", names)

    def test_missing_table_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.md"
            report.write_text("# Report\nNo table here.\n")
            rows = self.t.parse_report(report)
        self.assertEqual(rows, [])


class RemediationActionTest(unittest.TestCase):
    """`remediation()` returns a dict with an `action` key matching the
    verdict. We only assert the key shape — the suggested-shell / fixture
    paths are formatting concerns covered by the markdown rendering path."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_each_verdict_emits_matching_action(self) -> None:
        for verdict, expected_action in [
            ("OK", "OK"),
            ("WHITELIST", "WHITELIST"),
            ("TIGHTEN", "TIGHTEN"),
            ("GRAVEYARD", "GRAVEYARD"),
        ]:
            rem = self.t.remediation("some-detector", 1, verdict)
            self.assertEqual(rem["action"], expected_action)


class MissingReportSkipTest(unittest.TestCase):
    """`main()` must return 0 (graceful CI skip) when the calibration
    report file is absent, per the tool's documented contract."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_main_skips_gracefully_on_missing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "no-such-report.md"
            output = Path(tmp) / "out.md"
            rc = self.t.main([
                "--calibration-report", str(missing),
                "--output", str(output),
            ])
        self.assertEqual(rc, 0)
        self.assertFalse(output.exists(),
                         "no output should be written when the input is absent")

    def test_default_report_matches_fp_calibration_output_path(self) -> None:
        self.assertEqual(
            self.t.DEFAULT_REPORT,
            REPO / "docs" / "archive" / "FP_CALIBRATION_REPORT.md",
        )


if __name__ == "__main__":
    unittest.main()
