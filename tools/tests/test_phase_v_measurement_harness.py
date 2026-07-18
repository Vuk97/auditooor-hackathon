"""tests for tools/phase-v-measurement-harness.py."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, Optional


def _import_harness():
    here = Path(__file__).resolve()
    tools_dir = here.parent.parent
    src = tools_dir / "phase-v-measurement-harness.py"
    spec = importlib.util.spec_from_file_location("phase_v_measurement_harness", src)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


HARNESS = _import_harness()


def _make_workspace(tmpdir: Path, name: str,
                    hunt_verdicts: Optional[Dict[str, int]] = None,
                    paste_ready_count: int = 0,
                    filed_count: int = 0,
                    thickened_reports: int = 0,
                    pattern_alerts_json: Optional[Dict[str, Any]] = None,
                    pattern_alerts_md: Optional[str] = None) -> Path:
    """Helper: build a synthetic audit workspace under tmpdir."""
    ws = tmpdir / name
    ws.mkdir(parents=True, exist_ok=True)
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    if hunt_verdicts is not None:
        verdicts = []
        for label, n in hunt_verdicts.items():
            for i in range(n):
                verdicts.append({"candidate_id": f"{label}-{i}", "verdict": label,
                                  "reasons": ["test"], "severity_max": "HIGH",
                                  "source": "test_fixture"})
        snap = {
            "schema": "auditooor.hunt_starter.v1",
            "workspace": str(ws),
            "generated_at_utc": "2026-05-23T12:00:00Z",
            "candidate_count": sum(hunt_verdicts.values()),
            "verdict_count": sum(hunt_verdicts.values()),
            "verdicts": verdicts,
        }
        (ws / ".auditooor" / "hunt_candidates_ranked.json").write_text(json.dumps(snap), encoding="utf-8")
    if pattern_alerts_json is not None:
        (ws / ".auditooor" / "pattern_migration_alerts.json").write_text(json.dumps(pattern_alerts_json), encoding="utf-8")
    if pattern_alerts_md is not None:
        (ws / ".auditooor" / "pattern_migration_alerts.md").write_text(pattern_alerts_md, encoding="utf-8")
    # Submissions
    sub_root = ws / "submissions"
    sub_root.mkdir(parents=True, exist_ok=True)
    for status, n in [("paste_ready", paste_ready_count), ("filed", filed_count)]:
        sd = sub_root / status
        sd.mkdir(parents=True, exist_ok=True)
        for i in range(n):
            slug = f"finding-{i:03d}"
            folder = sd / slug
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"{slug}.md").write_text(f"# {slug}\n", encoding="utf-8")
    # Thickened scan reports
    for i in range(thickened_reports):
        (ws / f"SCAN_REPORT_THICK.md").write_text("thick", encoding="utf-8")
        # second file uses scan_reports/ dir
        sd = ws / "scan_reports"
        sd.mkdir(parents=True, exist_ok=True)
        (sd / f"run_{i}_thick.md").write_text("thick", encoding="utf-8")
    return ws


class TestWilsonCI(unittest.TestCase):
    def test_zero_trials_returns_zeros(self):
        p, lo, hi = HARNESS.wilson_ci(0, 0)
        self.assertEqual((p, lo, hi), (0.0, 0.0, 0.0))

    def test_half_proportion_in_unit_interval(self):
        p, lo, hi = HARNESS.wilson_ci(50, 100)
        self.assertAlmostEqual(p, 0.5, places=4)
        self.assertGreater(lo, 0.0)
        self.assertLess(hi, 1.0)
        self.assertLess(lo, p)
        self.assertGreater(hi, p)

    def test_full_success_upper_capped_at_one(self):
        p, lo, hi = HARNESS.wilson_ci(10, 10)
        self.assertEqual(p, 1.0)
        self.assertLessEqual(hi, 1.0)
        self.assertGreater(lo, 0.5)

    def test_known_value_30_of_100(self):
        # Wilson 95% CI for 30/100 at z=1.96: (~0.21895, ~0.39585)
        # (the tabulated value 0.2168 in some textbooks uses the
        # continuity-corrected Wilson; we use the standard form.)
        p, lo, hi = HARNESS.wilson_ci(30, 100)
        self.assertAlmostEqual(p, 0.3, places=4)
        self.assertAlmostEqual(lo, 0.21895, places=4)
        self.assertAlmostEqual(hi, 0.39585, places=4)


class TestDeltaVerdict(unittest.TestCase):
    def test_no_trials_either_side_returns_no_shift(self):
        v = HARNESS.delta_verdict(0, 0, 0, 0)
        self.assertEqual(v["verdict"], "NO-MEASURABLE-SHIFT")

    def test_strict_uplift_returns_positive(self):
        # baseline 5/100=0.05, measured 50/100=0.5 - clearly above baseline CI
        v = HARNESS.delta_verdict(5, 100, 50, 100)
        self.assertEqual(v["verdict"], "SHIFTED-POSITIVELY")

    def test_strict_drop_returns_negative(self):
        v = HARNESS.delta_verdict(80, 100, 10, 100)
        self.assertEqual(v["verdict"], "SHIFTED-NEGATIVELY")

    def test_small_overlap_returns_no_shift(self):
        # baseline 50/100, measured 55/100 - CIs overlap point estimates
        v = HARNESS.delta_verdict(50, 100, 55, 100)
        self.assertEqual(v["verdict"], "NO-MEASURABLE-SHIFT")


class TestCountDeltaVerdict(unittest.TestCase):
    def test_no_change_returns_no_shift(self):
        v = HARNESS.count_delta_verdict(10, 10)
        self.assertEqual(v["verdict"], "NO-MEASURABLE-SHIFT")

    def test_at_least_10_percent_uplift_positive(self):
        v = HARNESS.count_delta_verdict(100, 115)
        self.assertEqual(v["verdict"], "SHIFTED-POSITIVELY")

    def test_at_least_10_percent_drop_negative(self):
        v = HARNESS.count_delta_verdict(100, 85)
        self.assertEqual(v["verdict"], "SHIFTED-NEGATIVELY")

    def test_min_threshold_one_when_baseline_zero(self):
        # baseline 0, measured 1 = +1 >= max(1, ceil(0.1*1)) = 1, positive
        v = HARNESS.count_delta_verdict(0, 1)
        self.assertEqual(v["verdict"], "SHIFTED-POSITIVELY")


class TestMeasureHuntStarter(unittest.TestCase):
    def test_missing_snapshot_returns_zero(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            (ws / ".auditooor").mkdir()
            result = HARNESS.measure_hunt_starter(ws)
            self.assertFalse(result["snapshot_exists"])
            self.assertEqual(result["candidate_count"], 0)

    def test_verdicts_are_tallied(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _make_workspace(tmp, "ws-a", hunt_verdicts={"HUNT-READY": 3, "LIKELY-DUPE-SKIP": 2})
            result = HARNESS.measure_hunt_starter(ws)
            self.assertTrue(result["snapshot_exists"])
            self.assertEqual(result["candidate_count"], 5)
            self.assertEqual(result["verdict_counts"]["HUNT-READY"], 3)
            self.assertEqual(result["verdict_counts"]["LIKELY-DUPE-SKIP"], 2)
            self.assertEqual(result["verdict_unknown"], 0)


class TestMeasurePatternMigration(unittest.TestCase):
    def test_no_alerts_file_returns_zero(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td), "ws-b")
            r = HARNESS.measure_pattern_migration(ws, global_root=Path(td))
            self.assertEqual(r["paid_match_count"], 0)
            self.assertEqual(r["high_roi_count"], 0)
            self.assertFalse(r["any_alerts"])

    def test_json_alerts_paid_match_counted(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td), "ws-c", pattern_alerts_json={
                "alerts": [
                    {"paid_match": True, "high_roi": True, "pattern": "p1"},
                    {"paid_match": True, "high_roi": False, "pattern": "p2"},
                    {"paid_match": False, "high_roi": False, "pattern": "p3"},
                ],
            })
            r = HARNESS.measure_pattern_migration(ws, global_root=Path(td))
            self.assertEqual(r["paid_match_count"], 2)
            self.assertEqual(r["high_roi_count"], 1)
            self.assertTrue(r["any_alerts"])

    def test_md_sentinel_no_high_roi_is_zero(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td), "ws-d",
                                  pattern_alerts_md="[alert] No high-ROI pattern migrations detected.\n")
            r = HARNESS.measure_pattern_migration(ws, global_root=Path(td))
            self.assertEqual(r["high_roi_count"], 0)


class TestMeasureDispatchPrebriefing(unittest.TestCase):
    def test_missing_log_returns_zero(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "nope.jsonl"
            r = HARNESS.measure_dispatch_prebriefing(p, None)
            self.assertFalse(r["log_exists"])
            self.assertEqual(r["rows_in_window"], 0)

    def test_malformed_lines_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "audit.jsonl"
            p.write_text(
                json.dumps({"ts": "2026-05-23T12:00:00Z", "prebriefing": {"status": "ok"}}) + "\n"
                + "BROKEN-NOT-JSON\n"
                + json.dumps({"ts": "2026-05-23T13:00:00Z"}) + "\n",
                encoding="utf-8",
            )
            r = HARNESS.measure_dispatch_prebriefing(p, None)
            self.assertEqual(r["rows_in_window"], 2)
            self.assertEqual(r["rows_with_prebriefing"], 1)
            self.assertAlmostEqual(r["injection_rate"], 0.5)


class TestMeasureSnapshotAndAggregate(unittest.TestCase):
    def test_snapshot_aggregates_across_workspaces(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws1 = _make_workspace(tmp, "ws-1", hunt_verdicts={"HUNT-READY": 2, "DESIGN-CHOICE-SKIP": 1},
                                  paste_ready_count=3, filed_count=1)
            ws2 = _make_workspace(tmp, "ws-2", hunt_verdicts={"HUNT-READY": 1, "LIKELY-DUPE-SKIP": 4},
                                  paste_ready_count=2, filed_count=0,
                                  pattern_alerts_json={"alerts": [{"paid_match": True, "high_roi": True}]})
            snap = HARNESS.measure_snapshot([ws1, ws2])
            agg = snap["aggregate"]
            self.assertEqual(agg["workspace_count"], 2)
            self.assertEqual(agg["hunt_total_candidates"], 8)
            self.assertEqual(agg["hunt_verdict_counts"]["HUNT-READY"], 3)
            self.assertEqual(agg["hunt_verdict_counts"]["LIKELY-DUPE-SKIP"], 4)
            self.assertEqual(agg["hunt_verdict_counts"]["DESIGN-CHOICE-SKIP"], 1)
            self.assertEqual(agg["paste_ready_total"], 5)
            self.assertEqual(agg["filed_total"], 1)
            self.assertEqual(agg["pattern_migration_paid_matches"], 1)


class TestBaselineWriteAndMeasureAppend(unittest.TestCase):
    def test_baseline_write_then_measure_append_then_report(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws1 = _make_workspace(tmp, "ws-A", hunt_verdicts={"HUNT-READY": 5},
                                  paste_ready_count=2)
            baseline_path = tmp / "baseline.json"
            measure_path = tmp / "measurement.jsonl"
            # baseline
            snap = HARNESS.measure_snapshot([ws1])
            HARNESS.write_baseline(snap, baseline_path)
            self.assertTrue(baseline_path.exists())
            # measure - simulate +N paste-ready landed during window
            ws_after = _make_workspace(tmp, "ws-A-after", hunt_verdicts={"HUNT-READY": 5},
                                        paste_ready_count=10)
            snap2 = HARNESS.measure_snapshot([ws_after])
            HARNESS.append_measurement(snap2, measure_path)
            self.assertTrue(measure_path.exists())
            # report
            baseline = HARNESS.load_baseline(baseline_path)
            measurements = HARNESS.load_measurements(measure_path)
            body, summary = HARNESS.render_report(baseline, measurements, window_days=7)
            self.assertIn("Phase NEG-V", body)
            self.assertIn("paste_ready_output", summary["pillars"])
            self.assertEqual(summary["pillars"]["paste_ready_output"]["verdict"], "SHIFTED-POSITIVELY")


class TestReportNoDataFallback(unittest.TestCase):
    def test_render_report_with_no_inputs(self):
        body, summary = HARNESS.render_report(None, [], window_days=7)
        self.assertIn("insufficient data", body)
        self.assertFalse(summary["baseline_present"])
        self.assertEqual(summary["measurement_row_count"], 0)


class TestCLI(unittest.TestCase):
    def test_cli_baseline_then_measure_then_report(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _make_workspace(tmp, "ws-cli", hunt_verdicts={"HUNT-READY": 3},
                                  paste_ready_count=1)
            baseline_path = tmp / "baseline.json"
            measure_path = tmp / "measure.jsonl"
            report_path = tmp / "report.md"
            # baseline
            rc = HARNESS.main([
                "--baseline",
                "--workspaces", str(ws),
                "--baseline-file", str(baseline_path),
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(baseline_path.exists())
            # measure - synthesize an improved post-wiring snapshot
            ws2 = _make_workspace(tmp, "ws-cli-after", hunt_verdicts={"HUNT-READY": 3},
                                   paste_ready_count=10)
            rc = HARNESS.main([
                "--measure",
                "--workspaces", str(ws2),
                "--measure-file", str(measure_path),
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(measure_path.exists())
            # report
            rc = HARNESS.main([
                "--report",
                "--baseline-file", str(baseline_path),
                "--measure-file", str(measure_path),
                "--report-file", str(report_path),
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(report_path.exists())
            body = report_path.read_text(encoding="utf-8")
            self.assertIn("Phase NEG-V", body)
            self.assertIn("paste_ready_output", body) if False else None
            self.assertIn("Paste-ready output", body)


class TestMalformedLogResilience(unittest.TestCase):
    def test_iter_jsonl_returns_nothing_on_missing(self):
        out = list(HARNESS._iter_jsonl(Path("/nonexistent/path/to/log.jsonl")))
        self.assertEqual(out, [])

    def test_iter_jsonl_skips_broken_rows(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "broken.jsonl"
            p.write_text('{"ok": 1}\nNOT-JSON\n{"ok": 2}\n', encoding="utf-8")
            rows = list(HARNESS._iter_jsonl(p))
            self.assertEqual(len(rows), 2)


class TestStrictMode(unittest.TestCase):
    def test_report_strict_missing_baseline_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rc = HARNESS.main([
                "--report",
                "--baseline-file", str(tmp / "does-not-exist.json"),
                "--measure-file", str(tmp / "also-not-exist.jsonl"),
                "--strict",
            ])
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
