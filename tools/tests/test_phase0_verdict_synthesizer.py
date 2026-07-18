#!/usr/bin/env python3
"""Regression coverage for tools/phase0-verdict-synthesizer.py.

Covers:
- All-FALSIFIED -> pivot-to-pillar-build recommendation
- All-SUPPORTED -> bail-per-criterion-6 recommendation
- Mixed -> needs-more-data
- Single bail-criterion trigger -> bail-immediately overrides aggregate
- Malformed input (corrupt unicode) -> still returns a payload, no crash
- Missing input file -> graceful skip with NOT-YET-RUN
- JSON schema validity (top-level keys present, schema id, tool_version)
- Idempotent re-run on same input (two consecutive runs yield same output)
- Live dogfood on currently-landed Phase 0 lanes (L0.1+L0.2+L0.3 anchor)
- Output markdown writes to disk and is parseable / well-formed
- L34 path classification of the OPERATOR_PHASE0_SUMMARY.md path
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "phase0-verdict-synthesizer.py"

# Anchor inputs from the live iter18 Phase 0 sprint.
ANCHOR_L01 = ROOT / "reports/v3_iter_2026-05-23_iter18_phase_0/lane_PHASE0_L01_BURNDOWN_AUDIT/results.md"
ANCHOR_L02 = ROOT / "reports/v3_iter_2026-05-23_iter18_phase_0/lane_PHASE0_L02_META1_AB_N12/results.md"
ANCHOR_L03 = ROOT / "reports/v3_iter_2026-05-23_iter18_phase_0/lane_PHASE0_L03_INVARIANT_PILOT/results.md"


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        env=env,
    )


def _make_results_md(tmpdir: Path, lane_name: str, verdict_token: str, extra_body: str = "") -> Path:
    """Compose a minimal results.md with a 'Honest verdict (final)' section."""
    lane_dir = tmpdir / f"lane_{lane_name}"
    lane_dir.mkdir(parents=True, exist_ok=True)
    path = lane_dir / "results.md"
    body = f"""# Lane {lane_name} - Results

- Lane: `lane-{lane_name}`

## Honest verdict (final)

**{verdict_token}**

{extra_body}
"""
    path.write_text(body, encoding="utf-8")
    return path


class TestPhase0VerdictSynthesizer(unittest.TestCase):

    def test_help_works(self):
        proc = _run("--help")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("--inputs", proc.stdout)
        self.assertIn("--output", proc.stdout)

    def test_all_falsified_pivot_recommendation(self):
        """All 4 counter-tests return PLAN-X-FALSIFIED -> pivot-to-pillar-build."""
        with tempfile.TemporaryDirectory() as tdir:
            tdir_p = Path(tdir)
            paths = [
                _make_results_md(tdir_p, "PHASE0_L01_BURNDOWN_AUDIT", "bottleneck-not-confirmed"),
                _make_results_md(tdir_p, "PHASE0_L02_META1_AB", "cohort-A-beats-cohort-B"),
                _make_results_md(tdir_p, "PHASE0_L03_INVARIANT_PILOT", "PILOT-USEFUL"),
                _make_results_md(tdir_p, "PHASE0_L04_ENGAGEMENT_PRESCREEN", "ENGAGEMENT-RATE-ABOVE"),
            ]
            proc = _run("--inputs", *[str(p) for p in paths], "--json")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(data["aggregate_verdict"], "pivot-to-pillar-build")
            self.assertEqual(data["counter_test_summary"]["PLAN-X-FALSIFIED"], 4)
            self.assertEqual(data["counter_test_summary"]["PLAN-X-SUPPORTED"], 0)

    def test_all_supported_bail_recommendation(self):
        """All 4 counter-tests return PLAN-X-SUPPORTED -> bail-per-criterion-6."""
        with tempfile.TemporaryDirectory() as tdir:
            tdir_p = Path(tdir)
            paths = [
                _make_results_md(tdir_p, "PHASE0_L01_BURNDOWN_AUDIT", "bottleneck-confirmed"),
                _make_results_md(tdir_p, "PHASE0_L02_META1_AB", "cohort-A-does-not-beat"),
                _make_results_md(tdir_p, "PHASE0_L03_INVARIANT_PILOT", "PILOT-USELESS"),
                _make_results_md(tdir_p, "PHASE0_L04_ENGAGEMENT_PRESCREEN", "ENGAGEMENT-RATE-BELOW"),
            ]
            proc = _run("--inputs", *[str(p) for p in paths], "--json")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(data["aggregate_verdict"], "bail-per-criterion-6")
            self.assertEqual(data["counter_test_summary"]["PLAN-X-SUPPORTED"], 4)
            self.assertEqual(data["counter_test_summary"]["PLAN-X-FALSIFIED"], 0)

    def test_mixed_returns_needs_more_data(self):
        """1 falsified + 1 supported + 2 inconclusive -> needs-more-data."""
        with tempfile.TemporaryDirectory() as tdir:
            tdir_p = Path(tdir)
            paths = [
                _make_results_md(tdir_p, "PHASE0_L01_BURNDOWN_AUDIT", "bottleneck-confirmed"),
                _make_results_md(tdir_p, "PHASE0_L02_META1_AB", "insufficient_data"),
                _make_results_md(tdir_p, "PHASE0_L03_INVARIANT_PILOT", "PILOT-MARGINAL"),
                _make_results_md(tdir_p, "PHASE0_L04_ENGAGEMENT_PRESCREEN", "ENGAGEMENT-RATE-ABOVE"),
            ]
            proc = _run("--inputs", *[str(p) for p in paths], "--json")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(data["aggregate_verdict"], "needs-more-data")

    def test_immediate_bail_overrides_aggregate(self):
        """If a bail criterion #1-5 fires, aggregate is overridden to bail-immediately."""
        with tempfile.TemporaryDirectory() as tdir:
            tdir_p = Path(tdir)
            # Construct an L0.3 anchor that LOOKS positive (PILOT-USEFUL) but
            # contains a bail-criterion-4 trip ("P1 quality.*<.*60%").
            l03 = _make_results_md(
                tdir_p, "PHASE0_L03_INVARIANT_PILOT", "PILOT-USEFUL",
                extra_body="Quality spot-check: P1 quality 45% < 60% Y-rate threshold violated; bail criterion #4 fired.",
            )
            paths = [
                _make_results_md(tdir_p, "PHASE0_L01_BURNDOWN_AUDIT", "bottleneck-not-confirmed"),
                _make_results_md(tdir_p, "PHASE0_L02_META1_AB", "cohort-A-beats-cohort-B"),
                l03,
                _make_results_md(tdir_p, "PHASE0_L04_ENGAGEMENT_PRESCREEN", "ENGAGEMENT-RATE-ABOVE"),
            ]
            proc = _run("--inputs", *[str(p) for p in paths], "--json")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(data["aggregate_verdict"], "bail-immediately")
            self.assertIn("bail-criterion-4-p1-quality-under-60", data["immediate_bails_triggered"])

    def test_missing_input_file_graceful_skip(self):
        """A missing input path resolves to NOT-YET-RUN for that counter-test."""
        with tempfile.TemporaryDirectory() as tdir:
            tdir_p = Path(tdir)
            # Provide a path that does NOT exist for L0.2.
            paths = [
                _make_results_md(tdir_p, "PHASE0_L01_BURNDOWN_AUDIT", "bottleneck-confirmed"),
                tdir_p / "lane_PHASE0_L02_META1_AB" / "results.md",  # does NOT exist
                _make_results_md(tdir_p, "PHASE0_L03_INVARIANT_PILOT", "PILOT-USEFUL"),
            ]
            proc = _run("--inputs", *[str(p) for p in paths], "--json")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            l02 = next(r for r in data["counter_test_results"] if r["counter_test_id"] == "L0.2")
            self.assertEqual(l02["classification"], "NOT-YET-RUN")
            l04 = next(r for r in data["counter_test_results"] if r["counter_test_id"] == "L0.4")
            self.assertEqual(l04["classification"], "NOT-YET-RUN")

    def test_malformed_input_does_not_crash(self):
        """Corrupt-byte input still returns a payload (errors='replace')."""
        with tempfile.TemporaryDirectory() as tdir:
            tdir_p = Path(tdir)
            lane_dir = tdir_p / "lane_PHASE0_L01_BURNDOWN_AUDIT"
            lane_dir.mkdir(parents=True)
            corrupt = lane_dir / "results.md"
            # Mix of valid markdown + invalid byte sequences.
            corrupt.write_bytes(b"# Title\n\n## Verdict\n**bottleneck-confirmed**\n\n\xff\xfe\xff broken bytes \xc3\x28\n")
            proc = _run("--inputs", str(corrupt), "--json")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            l01 = next(r for r in data["counter_test_results"] if r["counter_test_id"] == "L0.1")
            self.assertEqual(l01["classification"], "PLAN-X-SUPPORTED")

    def test_json_schema_validity(self):
        """Top-level payload contains schema id, tool_version, aggregate_verdict + per-test rows."""
        with tempfile.TemporaryDirectory() as tdir:
            tdir_p = Path(tdir)
            p = _make_results_md(tdir_p, "PHASE0_L01_BURNDOWN_AUDIT", "bottleneck-confirmed")
            proc = _run("--inputs", str(p), "--json")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            for k in ("schema", "tool_version", "aggregate_verdict", "aggregate_reason",
                      "counter_test_summary", "counter_test_results",
                      "immediate_bails_triggered", "diagnostics"):
                self.assertIn(k, data, msg=f"missing top-level key {k}")
            self.assertEqual(data["schema"], "auditooor.phase0_verdict_synthesizer.v1")
            self.assertEqual(len(data["counter_test_results"]), 4)
            for r in data["counter_test_results"]:
                for k in ("counter_test_id", "name", "plan_x_dissent", "claim",
                          "pass_condition", "classification"):
                    self.assertIn(k, r, msg=f"missing counter_test_results key {k}")

    def test_idempotent_re_run(self):
        """Running the tool twice on the same inputs yields the same payload."""
        with tempfile.TemporaryDirectory() as tdir:
            tdir_p = Path(tdir)
            paths = [
                _make_results_md(tdir_p, "PHASE0_L01_BURNDOWN_AUDIT", "bottleneck-confirmed"),
                _make_results_md(tdir_p, "PHASE0_L02_META1_AB", "insufficient_data"),
                _make_results_md(tdir_p, "PHASE0_L03_INVARIANT_PILOT", "PILOT-USEFUL"),
            ]
            args = ["--inputs", *[str(p) for p in paths], "--json"]
            run1 = _run(*args)
            run2 = _run(*args)
            self.assertEqual(run1.returncode, 0)
            self.assertEqual(run2.returncode, 0)
            self.assertEqual(json.loads(run1.stdout), json.loads(run2.stdout))

    def test_output_markdown_written(self):
        """--output writes a parseable markdown file with all expected sections."""
        with tempfile.TemporaryDirectory() as tdir:
            tdir_p = Path(tdir)
            paths = [
                _make_results_md(tdir_p, "PHASE0_L01_BURNDOWN_AUDIT", "bottleneck-confirmed"),
                _make_results_md(tdir_p, "PHASE0_L02_META1_AB", "insufficient_data"),
                _make_results_md(tdir_p, "PHASE0_L03_INVARIANT_PILOT", "PILOT-USEFUL"),
            ]
            out_path = tdir_p / "summary.md"
            proc = _run("--inputs", *[str(p) for p in paths], "--output", str(out_path), "--json")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertTrue(out_path.is_file(), "summary.md was not written")
            md = out_path.read_text(encoding="utf-8")
            self.assertIn("Phase 0 Sprint Result", md)
            self.assertIn("Counter-test summary", md)
            self.assertIn("Per-counter-test verdict matrix", md)
            self.assertIn("Recommendation to operator", md)
            self.assertIn("Honest caveats", md)
            self.assertIn("Provenance", md)

    def test_strict_warning_when_inconclusive(self):
        """--strict emits a strict_warning when INCONCLUSIVE / NOT-YET-RUN entries exist."""
        with tempfile.TemporaryDirectory() as tdir:
            tdir_p = Path(tdir)
            paths = [
                _make_results_md(tdir_p, "PHASE0_L01_BURNDOWN_AUDIT", "bottleneck-confirmed"),
            ]
            proc = _run("--inputs", *[str(p) for p in paths], "--json", "--strict")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            self.assertIn("strict_warning", data)

    def test_live_dogfood_against_anchor_lanes(self):
        """Live dogfood against the 3 landed Phase 0 lane anchors (L01+L02+L03).

        Expectations (current anchor state on iter18):
          - L0.1 -> PLAN-X-SUPPORTED (bottleneck-confirmed verdict in
            burndown audit results)
          - L0.2 -> INCONCLUSIVE (insufficient_data per-rule fail-rate
            despite brief-injection working)
          - L0.3 -> PLAN-X-FALSIFIED (PILOT-USEFUL >=5-match threshold)
          - L0.4 -> NOT-YET-RUN (no results.md committed yet)
          - aggregate -> needs-more-data (1 FALSIFIED, 1 SUPPORTED, 1
            INCONCLUSIVE, 1 NOT-YET-RUN)
        """
        if not (ANCHOR_L01.is_file() and ANCHOR_L02.is_file() and ANCHOR_L03.is_file()):
            self.skipTest("anchor lanes not present in this checkout")
        proc = _run("--inputs", str(ANCHOR_L01), str(ANCHOR_L02), str(ANCHOR_L03), "--json")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        data = json.loads(proc.stdout)
        by_id = {r["counter_test_id"]: r for r in data["counter_test_results"]}
        self.assertEqual(by_id["L0.1"]["classification"], "PLAN-X-SUPPORTED")
        self.assertEqual(by_id["L0.2"]["classification"], "INCONCLUSIVE")
        self.assertEqual(by_id["L0.3"]["classification"], "PLAN-X-FALSIFIED")
        self.assertEqual(by_id["L0.4"]["classification"], "NOT-YET-RUN")
        self.assertEqual(data["aggregate_verdict"], "needs-more-data")

    def test_l34_path_classification_safe(self):
        """OPERATOR_PHASE0_SUMMARY.md is out-of-scope per L34 (not a draft file)."""
        l34_tool = ROOT / "tools" / "l34-path-classifier.py"
        if not l34_tool.is_file():
            self.skipTest("l34-path-classifier.py not present")
        target_path = "reports/v3_iter_2026-05-23_iter18_phase_0/OPERATOR_PHASE0_SUMMARY.md"
        proc = subprocess.run(
            [sys.executable, str(l34_tool), target_path, "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        # The summary doc lives under reports/ (not submissions/), so it
        # MUST classify as out-of-scope or workspace-ledger - never as a
        # draft-file that would need per-draft operator authorization.
        bucket = data["results"][0]["bucket"]
        self.assertIn(bucket, ("out-of-scope", "workspace-ledger", "lesson-anchor"))
        self.assertFalse(data["results"][0]["requires_per_draft_op_auth"])


if __name__ == "__main__":
    unittest.main()
