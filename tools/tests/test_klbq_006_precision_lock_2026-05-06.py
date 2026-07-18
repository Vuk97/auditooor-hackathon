"""KLBQ-006 precision-lock regression test (Worker-S, 2026-05-06).

Locks the synthetic precision row for the R94 fallback-handler family. The
test asserts that:

    detectors/fixtures/klbq_006_precision_corpus/contracts/klbq006/src/guard_vuln_hex_selector.rs

is the single TP row that
``r94_loop_safe_fallback_handler_setter_missing_address_guard`` fires on,
with zero false positives in that workspace, matching the
``klbq_006_synthetic_precision_corpus`` row in
``reports/klbq_006_precision_evidence_2026-05-05.json`` (1/0/3/0).

This is the regression lock referenced by
``reports/klbq_006_alternate_source_2026-05-06.json`` and
``docs/next-loop/klbq_006_alternate_source_2026-05-06.md``.

Filename uses dashes (``test_klbq_006_precision_lock_2026-05-06.py``) per
the lane spec; load via ``unittest discover`` or by file path, e.g.

    python3 -m unittest discover -s tools/tests -p \
        'test_klbq_006_precision_lock_2026-05-06.py' -v

Skips cleanly if ``tools/rust-detect.py`` is missing or the synthetic
corpus root is absent.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
RUST_DETECT = REPO / "tools" / "rust-detect.py"
PRECISION_CORPUS = REPO / "detectors" / "fixtures" / "klbq_006_precision_corpus"
EXPECTED_TP_REL = (
    "detectors/fixtures/klbq_006_precision_corpus/contracts/klbq006/"
    "src/guard_vuln_hex_selector.rs"
)
EXPECTED_TP_ABS = (REPO / EXPECTED_TP_REL).resolve()
DETECTOR_ID = "r94_loop_safe_fallback_handler_setter_missing_address_guard"
BASELINE_REPORT = (
    REPO / "reports" / "klbq_006_precision_evidence_2026-05-05.json"
)
ALTERNATE_REPORT = (
    REPO / "reports" / "klbq_006_alternate_source_2026-05-06.json"
)


def _baseline_synthetic_row() -> dict | None:
    if not BASELINE_REPORT.exists():
        return None
    with BASELINE_REPORT.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    for row in data.get("evidence_results", []):
        if (
            row.get("detector_id") == DETECTOR_ID
            and row.get("evidence_set") == "klbq_006_synthetic_precision_corpus"
        ):
            return row
    return None


class KLBQ006PrecisionLock20260506Test(unittest.TestCase):
    """Regression lock for the KLBQ-006 R94 synthetic precision row."""

    def setUp(self) -> None:
        if not RUST_DETECT.exists():
            self.skipTest(f"rust-detect.py missing at {RUST_DETECT}")
        if not PRECISION_CORPUS.exists():
            self.skipTest(
                f"precision corpus missing at {PRECISION_CORPUS}"
            )
        if not EXPECTED_TP_ABS.exists():
            self.skipTest(
                f"expected TP fixture missing at {EXPECTED_TP_ABS}"
            )

    def test_synthetic_precision_row_holds_for_r94_detector(self) -> None:
        """rust-detect.py fires exactly once on guard_vuln_hex_selector.rs."""

        with tempfile.TemporaryDirectory(prefix="klbq006_pl_") as tmp:
            log_path = Path(tmp) / "klbq006_r94_lock.log"
            cmd = [
                sys.executable,
                str(RUST_DETECT),
                str(PRECISION_CORPUS),
                "--only",
                DETECTOR_ID,
                "--log",
                str(log_path),
            ]
            proc = subprocess.run(
                cmd,
                cwd=REPO,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120,
            )

            self.assertEqual(
                proc.returncode,
                0,
                msg=(
                    "rust-detect.py exited non-zero\n"
                    f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
                ),
            )

            # Hit file is in the per-detector hit listing in the log.
            log_text = log_path.read_text(encoding="utf-8")
            # Expect exactly one TP from the synthetic corpus.
            self.assertIn(
                "total hits: 1",
                log_text,
                msg=(
                    "Expected exactly 1 TP from R94 detector on synthetic "
                    "precision corpus.\nlog:\n" + log_text
                ),
            )
            self.assertIn(
                "guard_vuln_hex_selector.rs",
                log_text,
                msg=(
                    "Expected TP row to be guard_vuln_hex_selector.rs "
                    "(synthetic precision corpus)\nlog:\n" + log_text
                ),
            )
            self.assertIn(
                DETECTOR_ID,
                log_text,
                msg="Expected detector id in per-detector hit listing.",
            )

    def test_alternate_source_report_records_tp_row(self) -> None:
        """The alt-source report's OPTION-1 hit_files list contains the TP."""

        if not ALTERNATE_REPORT.exists():
            self.skipTest(
                f"alternate-source report missing at {ALTERNATE_REPORT}"
            )
        with ALTERNATE_REPORT.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        option_1 = payload.get("option_1_outcome", {})
        self.assertEqual(
            option_1.get("detector_id"),
            DETECTOR_ID,
            msg="alternate report option_1 detector_id mismatch",
        )
        hit_files = option_1.get("hit_files", [])
        self.assertIn(
            EXPECTED_TP_REL,
            hit_files,
            msg=(
                "alternate report option_1 hit_files must include "
                f"{EXPECTED_TP_REL}; got {hit_files}"
            ),
        )
        self.assertEqual(option_1.get("true_positive_count"), 1)
        self.assertEqual(option_1.get("false_positive_count"), 0)
        self.assertEqual(option_1.get("true_negative_count"), 3)
        self.assertEqual(option_1.get("false_negative_count"), 0)

    def test_no_regression_vs_baseline(self) -> None:
        """Today's synthetic-corpus row matches the 2026-05-05 sub-row."""

        baseline = _baseline_synthetic_row()
        if baseline is None:
            self.skipTest(
                "baseline synthetic row missing in "
                f"{BASELINE_REPORT}"
            )
        self.assertEqual(baseline.get("precision"), 1.0)
        self.assertEqual(baseline.get("recall"), 1.0)
        self.assertEqual(baseline.get("true_positive_count"), 1)
        self.assertEqual(baseline.get("false_positive_count"), 0)
        self.assertEqual(baseline.get("true_negative_count"), 3)
        self.assertEqual(baseline.get("false_negative_count"), 0)
        self.assertIn(EXPECTED_TP_REL, baseline.get("hit_files", []))


if __name__ == "__main__":
    unittest.main()
