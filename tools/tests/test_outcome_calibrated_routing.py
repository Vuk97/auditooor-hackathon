"""Tests for tools/outcome-calibrated-routing.py.

Coverage:
  - Low filing rate -> raise-proof-shell-bar recommendation
  - High dupe rate -> down-weight-dupe-classes recommendation
  - Empty / zeroed benchmark -> graceful no-op (status=no-data or healthy, no crash)
  - Schema field presence in output
  - Tool NEVER mutates any live config file
  - Missing benchmark file -> graceful no-op (benchmark_loaded=False)
  - Workspace filter selects correct row
  - Healthy benchmark (all signals within thresholds) -> no recommendations
  - High inconclusive rate -> require-truth-table-early recommendation
  - High OOS rate -> raise-scope-check-gate recommendation
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_TOOL_PATH  = _REPO_ROOT / "tools" / "outcome-calibrated-routing.py"


def _load_module():
    """Load the hyphen-named tool as a module."""
    spec = importlib.util.spec_from_file_location(
        "outcome_calibrated_routing", str(_TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


_mod = _load_module()

SCHEMA                   = _mod.SCHEMA
LOW_FILING_RATE_THRESHOLD = _mod.LOW_FILING_RATE_THRESHOLD
HIGH_DUPE_RATE_THRESHOLD  = _mod.HIGH_DUPE_RATE_THRESHOLD
HIGH_OOS_RATE_THRESHOLD   = _mod.HIGH_OOS_RATE_THRESHOLD
HIGH_INCONCLUSIVE_THRESHOLD = _mod.HIGH_INCONCLUSIVE_THRESHOLD
build_routing_report      = _mod.build_routing_report
compute_signals           = _mod.compute_signals

_BENCHMARK_SCHEMA = "auditooor.exploit_conversion_benchmark.v1"


def _make_benchmark(workspaces: list[dict]) -> dict:
    """Build a minimal benchmark dict that the tool will accept."""
    return {
        "schema": _BENCHMARK_SCHEMA,
        "generated_at_utc": "2026-05-19T00:00:00Z",
        "_metric_is_not_detector_count": True,
        "summary": {
            "workspace_count": len(workspaces),
            "total_queue_rows": sum(w.get("queue_rows_generated", 0) for w in workspaces),
            "total_rows_proved": 0,
            "total_rows_killed": 0,
            "total_rows_filed": sum(w.get("rows_filed", 0) for w in workspaces),
            "total_rows_accepted": 0,
            "total_rows_paste_ready": 0,
            "total_provider_tokens": 0,
            "total_provider_calls": 0,
        },
        "workspaces": workspaces,
    }


def _make_ws(
    name: str = "test_ws",
    queue_rows: int = 10,
    proved: int = 0,
    killed: int = 0,
    inconclusive: int = 10,
    paste_ready: int = 0,
    filed: int = 0,
    accepted: int = 0,
    rejected: int = 0,
    duplicate: int = 0,
    oos: int = 0,
    runnable_proof: int = 0,
    attacker_control: int = 0,
    tpuv: float | None = None,
) -> dict:
    """Build a minimal workspace benchmark row."""
    return {
        "schema": _BENCHMARK_SCHEMA,
        "workspace": name,
        "workspace_path": f"/fake/{name}",
        "queue_rows_generated": queue_rows,
        "rows_proved": proved,
        "rows_killed": killed,
        "rows_inconclusive": inconclusive,
        "rows_paste_ready": paste_ready,
        "rows_filed": filed,
        "rows_accepted": accepted,
        "rows_rejected": rejected,
        "rows_duplicate": duplicate,
        "rows_oos": oos,
        "rows_with_runnable_proof_path": runnable_proof,
        "rows_with_plausible_attacker_control": attacker_control,
        "provider_tokens_per_useful_verdict": tpuv,
        "provider_tokens_total": 0,
        "provider_calls_total": 0,
        "provider_breakdown": {},
        "capability_lessons_mined": [],
        "artifacts_found": [],
        "artifacts_missing": [],
        "_metric_is_not_detector_count": True,
    }


class TestComputeSignals(unittest.TestCase):
    """Unit tests for the signal computation layer."""

    def test_filing_rate_computed(self):
        ws = _make_ws(queue_rows=10, filed=1)
        signals = compute_signals(ws)
        self.assertAlmostEqual(signals["filing_rate"], 0.1, places=4)

    def test_dupe_rate_computed(self):
        ws = _make_ws(queue_rows=10, filed=4, duplicate=2)
        signals = compute_signals(ws)
        self.assertAlmostEqual(signals["dupe_rate"], 0.5, places=4)

    def test_zero_queue_rows_no_crash(self):
        ws = _make_ws(queue_rows=0, filed=0)
        signals = compute_signals(ws)
        self.assertIsNone(signals["filing_rate"])
        self.assertIsNone(signals["proof_gap"])
        self.assertIsNone(signals["attacker_control_gap"])

    def test_proof_gap_full(self):
        # All 10 rows lack runnable proof
        ws = _make_ws(queue_rows=10, runnable_proof=0)
        signals = compute_signals(ws)
        self.assertAlmostEqual(signals["proof_gap"], 1.0, places=4)

    def test_proof_gap_partial(self):
        ws = _make_ws(queue_rows=10, runnable_proof=5)
        signals = compute_signals(ws)
        self.assertAlmostEqual(signals["proof_gap"], 0.5, places=4)


class TestLowFilingRate(unittest.TestCase):
    """Low filing rate should trigger raise-proof-shell-bar recommendation."""

    def setUp(self):
        # filing_rate = 1/10 = 0.10 which is exactly at the threshold.
        # Use 0 filed (0.0 rate) to ensure it's strictly below.
        self.ws = _make_ws(name="low_filer", queue_rows=10, filed=0, inconclusive=10)
        benchmark = _make_benchmark([self.ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            self.report = build_routing_report(bench_path)

    def test_recommendation_emitted(self):
        ids = self.report["recommendation_ids"]
        self.assertIn("raise-proof-shell-bar", ids)

    def test_recommendation_is_advisory(self):
        rec = next(r for r in self.report["recommendations"]
                   if r["recommendation_id"] == "raise-proof-shell-bar")
        self.assertTrue(rec["advisory_only"])
        self.assertEqual(rec["affected_dimension"], "exploit-queue-enqueue-gate")

    def test_status_set_correctly(self):
        self.assertEqual(self.report["status"], "recommendations-emitted")

    def test_schema_present(self):
        self.assertEqual(self.report["schema"], SCHEMA)

    def test_advisory_only_top_level(self):
        self.assertTrue(self.report["advisory_only"])

    def test_mutation_guard_present(self):
        self.assertIn("mutation_guard", self.report)
        self.assertIn("NEVER", self.report["mutation_guard"])


class TestHighDupeRate(unittest.TestCase):
    """High dupe rate (>30%) should trigger down-weight-dupe-classes recommendation."""

    def setUp(self):
        # dupe_rate = 2/4 = 0.50 > HIGH_DUPE_RATE_THRESHOLD (0.30)
        self.ws = _make_ws(
            name="dupe_ws", queue_rows=10, filed=4, duplicate=2, inconclusive=10
        )
        benchmark = _make_benchmark([self.ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            self.report = build_routing_report(bench_path)

    def test_recommendation_emitted(self):
        ids = self.report["recommendation_ids"]
        self.assertIn("down-weight-dupe-classes", ids)

    def test_advisory_flag(self):
        rec = next(r for r in self.report["recommendations"]
                   if r["recommendation_id"] == "down-weight-dupe-classes")
        self.assertTrue(rec["advisory_only"])
        self.assertEqual(rec["signal"], "dupe_rate")
        self.assertEqual(rec["direction"], "above")

    def test_suggested_value_numeric(self):
        rec = next(r for r in self.report["recommendations"]
                   if r["recommendation_id"] == "down-weight-dupe-classes")
        # Suggested dupe_risk_score_weight should be lower than current 0.10
        self.assertLess(rec["suggested_value"], 0.10)


class TestEmptyZeroedBenchmark(unittest.TestCase):
    """Empty or zeroed benchmark -> graceful no-op, no crash."""

    def test_zero_workspace_list(self):
        """Benchmark with no workspaces emits status=no-data or healthy."""
        benchmark = _make_benchmark([])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            report = build_routing_report(bench_path)
        self.assertIn(report["status"], ("healthy", "no-data"))
        self.assertEqual(report["recommendation_count"], 0)
        self.assertIsInstance(report["recommendations"], list)

    def test_zeroed_workspace_row(self):
        """Workspace with all-zero metrics -> no crash, minimal output."""
        ws = _make_ws(name="zeroed", queue_rows=0, filed=0)
        benchmark = _make_benchmark([ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            report = build_routing_report(bench_path)
        self.assertIsNotNone(report)
        self.assertIn("recommendations", report)
        # Zero-row workspace should not trigger high-inconclusive recommendation
        ids = report["recommendation_ids"]
        self.assertNotIn("require-truth-table-early", ids)


class TestMissingBenchmarkFile(unittest.TestCase):
    """Missing benchmark file -> graceful no-op (benchmark_loaded=False, status=no-data)."""

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nonexistent = Path(tmpdir) / "does_not_exist.json"
            report = build_routing_report(nonexistent)
        self.assertFalse(report["benchmark_loaded"])
        self.assertIsNotNone(report["benchmark_error"])
        self.assertEqual(report["status"], "no-data")
        self.assertEqual(report["recommendation_count"], 0)

    def test_wrong_schema(self):
        """Wrong schema string -> benchmark_loaded=False."""
        bad_benchmark = {"schema": "some.other.schema.v1", "workspaces": []}
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "bad.json"
            bench_path.write_text(json.dumps(bad_benchmark))
            report = build_routing_report(bench_path)
        self.assertFalse(report["benchmark_loaded"])


class TestSchemaFieldPresence(unittest.TestCase):
    """All required top-level schema fields must be present."""

    REQUIRED_FIELDS = [
        "schema",
        "generated_at_utc",
        "advisory_only",
        "mutation_guard",
        "benchmark_source",
        "benchmark_loaded",
        "benchmark_error",
        "workspace_filter",
        "status",
        "thresholds_used",
        "workspace_signals",
        "recommendations",
        "recommendation_count",
        "recommendation_ids",
    ]

    def test_all_required_fields_present(self):
        ws = _make_ws(name="schema_check", queue_rows=5, filed=1)
        benchmark = _make_benchmark([ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            report = build_routing_report(bench_path)
        for field in self.REQUIRED_FIELDS:
            self.assertIn(field, report, f"Missing required field: {field}")

    def test_thresholds_block_has_all_keys(self):
        ws = _make_ws(name="thresh_check")
        benchmark = _make_benchmark([ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            report = build_routing_report(bench_path)
        thresh = report["thresholds_used"]
        expected = {
            "low_filing_rate", "high_dupe_rate", "high_oos_rate",
            "high_inconclusive_rate", "high_proof_gap", "high_attacker_control_gap",
        }
        self.assertEqual(set(thresh.keys()), expected)

    def test_schema_value_correct(self):
        ws = _make_ws(name="schema_val")
        benchmark = _make_benchmark([ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            report = build_routing_report(bench_path)
        self.assertEqual(report["schema"], SCHEMA)


class TestNoMutationOfLiveConfig(unittest.TestCase):
    """Tool must NEVER write to exploit-queue.py, llm_budget_log, or routing config."""

    # Paths that must NOT be touched
    _FORBIDDEN_PATHS = [
        _REPO_ROOT / "tools" / "exploit-queue.py",
        _REPO_ROOT / "tools" / "calibration" / "llm_budget_log.jsonl",
        _REPO_ROOT / "tools" / "source-mining-campaign.py",
    ]

    def _mtime(self, path: Path) -> float | None:
        try:
            return path.stat().st_mtime
        except FileNotFoundError:
            return None

    def test_live_config_files_not_mutated(self):
        """Running build_routing_report does not change mtime of forbidden paths."""
        before = {p: self._mtime(p) for p in self._FORBIDDEN_PATHS}

        ws = _make_ws(name="mutcheck", queue_rows=10, filed=0)
        benchmark = _make_benchmark([ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            # Run into a tmpdir output so no real files are touched
            out_path = Path(tmpdir) / "out.json"
            report = build_routing_report(bench_path)
            out_path.write_text(json.dumps(report))

        after = {p: self._mtime(p) for p in self._FORBIDDEN_PATHS}
        for p in self._FORBIDDEN_PATHS:
            self.assertEqual(
                before[p], after[p],
                f"Live config file was modified: {p}"
            )

    def test_all_recommendations_marked_advisory_only(self):
        """Every recommendation dict has advisory_only=True."""
        # Generate a scenario that triggers multiple recommendations
        ws = _make_ws(
            name="advisory_check",
            queue_rows=10,
            filed=0,           # low filing rate
            duplicate=0,
            inconclusive=10,   # high inconclusive rate
            runnable_proof=0,  # high proof gap
        )
        benchmark = _make_benchmark([ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            report = build_routing_report(bench_path)

        for rec in report["recommendations"]:
            self.assertTrue(
                rec.get("advisory_only"),
                f"Recommendation {rec.get('recommendation_id')} missing advisory_only=True",
            )


class TestHealthyBenchmark(unittest.TestCase):
    """Benchmark with all signals within thresholds should produce no recommendations."""

    def test_no_recommendations_when_healthy(self):
        # filing_rate = 4/10 = 0.40 (above LOW_FILING_RATE_THRESHOLD 0.10)
        # dupe_rate = 1/4 = 0.25 (at threshold boundary, NOT above HIGH_DUPE_RATE_THRESHOLD 0.30)
        # oos_rate = 0/4 = 0 (below HIGH_OOS_RATE_THRESHOLD 0.25)
        # inconclusive_rate = 3/10 = 0.30 (below HIGH_INCONCLUSIVE_THRESHOLD 0.70)
        # proof_gap = 2/10 = 0.20 (below HIGH_PROOF_GAP_THRESHOLD 0.80)
        # attacker_control_gap = 2/10 = 0.20 (below HIGH_CTRL_GAP_THRESHOLD 0.60)
        ws = _make_ws(
            name="healthy_ws",
            queue_rows=10,
            filed=4,
            duplicate=1,    # dupe_rate = 1/4 = 0.25, NOT > 0.30
            oos=0,
            inconclusive=3,
            runnable_proof=8,    # proof_gap = 2/10 = 0.20
            attacker_control=8,  # ctrl_gap = 2/10 = 0.20
        )
        benchmark = _make_benchmark([ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            report = build_routing_report(bench_path)
        self.assertEqual(report["recommendation_count"], 0, report["recommendation_ids"])
        self.assertEqual(report["status"], "healthy")


class TestHighInconclusiveRate(unittest.TestCase):
    """High inconclusive rate triggers require-truth-table-early recommendation."""

    def test_high_inconclusive_triggers_recommendation(self):
        # inconclusive_rate = 9/10 = 0.90 > HIGH_INCONCLUSIVE_THRESHOLD (0.70)
        ws = _make_ws(
            name="inconc_ws",
            queue_rows=10,
            filed=2,       # filing_rate=0.20, above threshold -> no raise-proof-shell-bar
            duplicate=0,
            oos=0,
            inconclusive=9,
            runnable_proof=5,  # proof_gap=0.50, below HIGH_PROOF_GAP_THRESHOLD
            attacker_control=5,
        )
        benchmark = _make_benchmark([ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            report = build_routing_report(bench_path)
        self.assertIn("require-truth-table-early", report["recommendation_ids"])
        rec = next(r for r in report["recommendations"]
                   if r["recommendation_id"] == "require-truth-table-early")
        self.assertEqual(rec["signal"], "inconclusive_rate")
        self.assertTrue(rec["advisory_only"])


class TestHighOOSRate(unittest.TestCase):
    """High OOS rate triggers raise-scope-check-gate recommendation."""

    def test_high_oos_triggers_recommendation(self):
        # oos_rate = 2/4 = 0.50 > HIGH_OOS_RATE_THRESHOLD (0.25)
        ws = _make_ws(
            name="oos_ws",
            queue_rows=10,
            filed=4,
            oos=2,
            duplicate=0,
            inconclusive=3,  # inconclusive_rate=0.30 < 0.70
            runnable_proof=5,
            attacker_control=5,
        )
        benchmark = _make_benchmark([ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            report = build_routing_report(bench_path)
        self.assertIn("raise-scope-check-gate", report["recommendation_ids"])
        rec = next(r for r in report["recommendations"]
                   if r["recommendation_id"] == "raise-scope-check-gate")
        self.assertEqual(rec["signal"], "oos_rate")
        self.assertTrue(rec["advisory_only"])


class TestWorkspaceFilter(unittest.TestCase):
    """Workspace filter selects only the matching workspace row."""

    def test_filter_selects_correct_workspace(self):
        ws_a = _make_ws(name="alpha", queue_rows=10, filed=0)  # low filing rate
        ws_b = _make_ws(name="beta",  queue_rows=10, filed=5)  # healthy filing rate
        benchmark = _make_benchmark([ws_a, ws_b])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            # Filter to beta only
            report = build_routing_report(bench_path, workspace_filter="beta")
        # Only beta should appear in signals
        ws_names = [s["workspace"] for s in report["workspace_signals"]]
        self.assertNotIn("alpha", ws_names)
        self.assertIn("beta", ws_names)
        # Beta has good filing rate -> no raise-proof-shell-bar
        self.assertNotIn("raise-proof-shell-bar", report["recommendation_ids"])


class TestOutputIsValidJSON(unittest.TestCase):
    """The output written to disk is valid JSON and matches the report dict."""

    def test_output_json_roundtrip(self):
        ws = _make_ws(name="json_rt", queue_rows=5, filed=0)
        benchmark = _make_benchmark([ws])
        with tempfile.TemporaryDirectory() as tmpdir:
            bench_path = Path(tmpdir) / "benchmark.json"
            bench_path.write_text(json.dumps(benchmark))
            report = build_routing_report(bench_path)
            out_path = Path(tmpdir) / "out.json"
            out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            # Read back and verify
            reloaded = json.loads(out_path.read_text())
        self.assertEqual(reloaded["schema"], SCHEMA)
        self.assertEqual(reloaded["recommendation_count"], report["recommendation_count"])


if __name__ == "__main__":
    unittest.main()
