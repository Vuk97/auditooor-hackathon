"""test_meta1_ab_measurement.py - tests for the iter17 Lane VVVVV A/B
controlled re-measurement harness:

  - ``tools/meta1-ab-measurement-dispatch.py`` (writes the JSONL log)
  - ``tools/meta1-ab-measurement-analyze.py`` (reads the log + drafts +
    rule gates, computes per-rule fail-rate deltas)

Coverage
--------

1. Single-cohort dispatch records correctly tagged "A".
2. Single-cohort dispatch records correctly tagged "B".
3. Matched-pair writes two records sharing trial_id.
4. Matched-pair ordering is deterministic per --seed (different seeds
   may differ; same seed always same order).
5. Cohort A injects a META-1 wrapper block (fallback or real); cohort
   B emits NO META-1 markers.
6. Brief sha256 of cohort A differs from B for the same lane spec.
7. Rules-pin SHAs are recorded.
8. Analyzer correctly groups by trial_id.
9. Analyzer reports orphans when a cohort is missing.
10. Analyzer empty-log path returns insufficient_data.
11. Analyzer per-rule fail-rate calculation with mock rule runner.
12. Analyzer classifies helpful / inert / harmful correctly via
    delta CI.
13. Analyzer inventory-only mode reports counts without running gates.
14. Wilson-score and delta CI helpers behave at edge cases (n=0,
    p=0, p=1).
15. analyzer skips drafts that resolve to None.
"""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import random
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DISPATCH_TOOL = REPO_ROOT / "tools" / "meta1-ab-measurement-dispatch.py"
ANALYZE_TOOL = REPO_ROOT / "tools" / "meta1-ab-measurement-analyze.py"


def _load_module(path: pathlib.Path, mod_name: str):
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


dispatch_mod = _load_module(DISPATCH_TOOL, "meta1_ab_measurement_dispatch")
analyze_mod = _load_module(ANALYZE_TOOL, "meta1_ab_measurement_analyze")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeCompletedProcess:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _runner_returning_a_block(argv: List[str]) -> _FakeCompletedProcess:
    """Simulates dispatch-agent-with-prebriefing.py emitting a valid
    META-1 block with skeleton_unavailable=False (real mode)."""
    block = (
        "<!-- BEGIN dispatch-agent-with-prebriefing META-1 block -->\n"
        "\n"
        "## Section 15a - Lane-specific R-rules you MUST address\n"
        "R29, R42, R43\n"
        "\n"
        "## Section 15b - Rule-section skeleton templates\n"
        "<<TEMPLATE BODY>>\n"
        "\n"
        "<!-- END dispatch-agent-with-prebriefing META-1 block -->\n"
        "\n"
        "ORIGINAL PROMPT BODY\n"
    )
    meta = {
        "schema": "auditooor.dispatch_agent_with_prebriefing.v1",
        "lane_type": "hunt",
        "severity": "HIGH",
        "skeleton_pack_id": "fake-pack-001",
        "skeleton_unavailable": False,
    }
    return _FakeCompletedProcess(
        stdout=block,
        stderr=json.dumps(meta),
        returncode=0,
    )


def _runner_returning_fallback_block(argv: List[str]) -> _FakeCompletedProcess:
    """Simulates the wrapper in fallback mode (PPPPP unlanded)."""
    block = (
        "<!-- BEGIN dispatch-agent-with-prebriefing META-1 block -->\n"
        "\n"
        "## Section 15a - Lane-specific R-rules you MUST address\n"
        "_(warn: vault_dispatch_brief_skeleton unavailable - paste section "
        "verbatim from CLAUDE.md if R-rule context is needed)_\n"
        "\n"
        "## Section 15b - Rule-section skeleton templates\n"
        "_(warn: vault_dispatch_brief_skeleton unavailable - no skeleton "
        "templates injected)_\n"
        "\n"
        "<!-- END dispatch-agent-with-prebriefing META-1 block -->\n"
        "\n"
        "ORIGINAL PROMPT BODY\n"
    )
    meta = {
        "schema": "auditooor.dispatch_agent_with_prebriefing.v1",
        "lane_type": "hunt",
        "severity": "HIGH",
        "skeleton_pack_id": None,
        "skeleton_unavailable": True,
    }
    return _FakeCompletedProcess(
        stdout=block,
        stderr=json.dumps(meta),
        returncode=0,
    )


def _make_rule_runner(
    verdict_map: Dict[str, str],
) -> Any:
    """Given a mapping (draft_path_str, rule_id_via_tool_name) ->
    verdict token, returns a runner that emulates pre-submit rule
    gates."""

    def runner(argv: List[str]) -> _FakeCompletedProcess:
        tool_path = argv[1]
        draft_path = argv[2]
        # tool_path may end with /tools/<rule-tool>.py
        # Map back to rule id using last path component.
        rule_id = None
        for rid, rel in dispatch_mod.RULES_PIN_FILES:
            if rel in tool_path or tool_path.endswith(
                rel.split("/")[-1]
            ):
                rule_id = rid
                break
        key = (draft_path, rule_id)
        verdict = verdict_map.get(key, "pass-out-of-scope")
        out = json.dumps({"verdict": verdict})
        return _FakeCompletedProcess(stdout=out, returncode=0)

    return runner


def _write_lane_spec(tmpdir: pathlib.Path, text: str = "echo-back-section-15a\n") -> pathlib.Path:
    p = tmpdir / "lane_spec.md"
    p.write_text(text, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Dispatch tool tests
# ---------------------------------------------------------------------------

class DispatchSingleCohortTest(unittest.TestCase):

    def test_01_single_cohort_a_record_tagged_A(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            spec = _write_lane_spec(tdp)
            ws = tdp / "ws"
            ws.mkdir()
            rec = dispatch_mod.run_single_cohort(
                "A",
                trial_id="t-001",
                lane_spec_path=spec,
                lane_spec_text=spec.read_text(encoding="utf-8"),
                lane_type="hunt",
                severity="HIGH",
                workspace_path=ws,
                target_finding_class="",
                expected_draft_id="t-001-draft",
                head_sha="deadbeef",
                rules_pin_shas={"R42": "abc"},
                runner=_runner_returning_a_block,
            )
        self.assertEqual(rec["cohort"], "A")
        self.assertEqual(rec["trial_id"], "t-001")
        self.assertEqual(rec["meta1_invocation_status"], "real")
        self.assertEqual(rec["skeleton_pack_id"], "fake-pack-001")
        self.assertFalse(rec["skeleton_unavailable"])

    def test_02_single_cohort_b_record_tagged_B(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            spec = _write_lane_spec(tdp)
            ws = tdp / "ws"
            ws.mkdir()
            rec = dispatch_mod.run_single_cohort(
                "B",
                trial_id="t-002",
                lane_spec_path=spec,
                lane_spec_text=spec.read_text(encoding="utf-8"),
                lane_type="hunt",
                severity="HIGH",
                workspace_path=ws,
                target_finding_class="",
                expected_draft_id="t-002-draft",
                head_sha="deadbeef",
                rules_pin_shas={"R42": "abc"},
            )
        self.assertEqual(rec["cohort"], "B")
        # Cohort B should NOT invoke the wrapper.
        self.assertEqual(rec["meta1_invocation_status"], "disabled")
        self.assertIsNone(rec["skeleton_pack_id"])

    def test_03_cohort_a_emits_meta1_markers_in_brief_sha(self):
        """Brief SHA differs between A (with block) and B (raw)."""
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            spec = _write_lane_spec(tdp)
            ws = tdp / "ws"
            ws.mkdir()
            text = spec.read_text(encoding="utf-8")
            rec_a = dispatch_mod.run_single_cohort(
                "A",
                trial_id="t",
                lane_spec_path=spec,
                lane_spec_text=text,
                lane_type="hunt",
                severity="HIGH",
                workspace_path=ws,
                target_finding_class="",
                expected_draft_id="d",
                head_sha="x",
                rules_pin_shas={},
                runner=_runner_returning_a_block,
            )
            rec_b = dispatch_mod.run_single_cohort(
                "B",
                trial_id="t",
                lane_spec_path=spec,
                lane_spec_text=text,
                lane_type="hunt",
                severity="HIGH",
                workspace_path=ws,
                target_finding_class="",
                expected_draft_id="d",
                head_sha="x",
                rules_pin_shas={},
            )
        self.assertNotEqual(rec_a["brief_sha256"], rec_b["brief_sha256"])
        # Cohort A brief is bigger (contains the wrapper block).
        self.assertGreater(rec_a["brief_chars"], rec_b["brief_chars"])


class DispatchMatchedPairTest(unittest.TestCase):

    def test_04_matched_pair_writes_two_records(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            spec = _write_lane_spec(tdp)
            ws = tdp / "ws"
            ws.mkdir()
            recs = dispatch_mod.run_matched_pair(
                trial_id="trial-x",
                lane_spec_path=spec,
                lane_spec_text=spec.read_text(encoding="utf-8"),
                lane_type="hunt",
                severity="HIGH",
                workspace_path=ws,
                target_finding_class="",
                expected_draft_id_a="trial-x-A",
                expected_draft_id_b="trial-x-B",
                head_sha="x",
                rules_pin_shas={},
                seed=42,
                runner=_runner_returning_fallback_block,
            )
        self.assertEqual(len(recs), 2)
        self.assertEqual({r["cohort"] for r in recs}, {"A", "B"})
        self.assertTrue(all(r["trial_id"] == "trial-x" for r in recs))

    def test_05_matched_pair_seed_is_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            spec = _write_lane_spec(tdp)
            ws = tdp / "ws"
            ws.mkdir()
            text = spec.read_text(encoding="utf-8")
            # Run twice with same seed and assert order is identical.
            recs_seed_a1 = dispatch_mod.run_matched_pair(
                trial_id="t",
                lane_spec_path=spec,
                lane_spec_text=text,
                lane_type="hunt",
                severity="HIGH",
                workspace_path=ws,
                target_finding_class="",
                expected_draft_id_a="A",
                expected_draft_id_b="B",
                head_sha="x",
                rules_pin_shas={},
                seed=7,
                runner=_runner_returning_fallback_block,
            )
            recs_seed_a2 = dispatch_mod.run_matched_pair(
                trial_id="t",
                lane_spec_path=spec,
                lane_spec_text=text,
                lane_type="hunt",
                severity="HIGH",
                workspace_path=ws,
                target_finding_class="",
                expected_draft_id_a="A",
                expected_draft_id_b="B",
                head_sha="x",
                rules_pin_shas={},
                seed=7,
                runner=_runner_returning_fallback_block,
            )
        order1 = [r["cohort"] for r in recs_seed_a1]
        order2 = [r["cohort"] for r in recs_seed_a2]
        self.assertEqual(order1, order2)


class DispatchLogPersistenceTest(unittest.TestCase):

    def test_06_rules_pin_shas_recorded(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            spec = _write_lane_spec(tdp)
            ws = tdp / "ws"
            ws.mkdir()
            rec = dispatch_mod.run_single_cohort(
                "A",
                trial_id="t",
                lane_spec_path=spec,
                lane_spec_text=spec.read_text(encoding="utf-8"),
                lane_type="hunt",
                severity="HIGH",
                workspace_path=ws,
                target_finding_class="",
                expected_draft_id="d",
                head_sha="x",
                rules_pin_shas={"R42": "deadbeef", "R45": "cafebabe"},
                runner=_runner_returning_fallback_block,
            )
        self.assertIn("R42", rec["rules_pin_shas"])
        self.assertEqual(rec["rules_pin_shas"]["R42"], "deadbeef")

    def test_07_append_record_creates_jsonl(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            log_path = tdp / ".auditooor" / "meta1_ab_log.jsonl"
            rec = {"schema": "test", "trial_id": "t", "cohort": "A"}
            dispatch_mod.append_record(log_path, rec)
            self.assertTrue(log_path.is_file())
            lines = log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["trial_id"], "t")


# ---------------------------------------------------------------------------
# Analyzer tests
# ---------------------------------------------------------------------------

def _seed_log(
    log_path: pathlib.Path,
    rows: List[Dict[str, Any]],
) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def _row(
    *,
    trial: str,
    cohort: str,
    workspace: str,
    draft_id: str,
    severity: str = "HIGH",
    lane_type: str = "hunt",
    meta1_status: str = "real",
) -> Dict[str, Any]:
    return {
        "schema": "auditooor.meta1_ab_dispatch_record.v1",
        "ts": "2026-05-23T00:00:00Z",
        "tool": "meta1-ab-measurement-dispatch.py",
        "tool_version": "0.1.0",
        "trial_id": trial,
        "cohort": cohort,
        "lane_spec_path": "/tmp/x",
        "lane_spec_sha256": "abc",
        "lane_type": lane_type,
        "severity": severity,
        "workspace_path": workspace,
        "target_finding_class": "",
        "head_sha": "x",
        "rules_pin_shas": {},
        "brief_chars": 100,
        "brief_sha256": "def",
        "meta1_invocation_status": meta1_status,
        "skeleton_pack_id": None,
        "skeleton_unavailable": meta1_status == "fallback",
        "expected_draft_id": draft_id,
    }


class AnalyzerGroupingTest(unittest.TestCase):

    def test_08_group_by_trial(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            log = tdp / "log.jsonl"
            _seed_log(
                log,
                [
                    _row(trial="t1", cohort="A", workspace=str(tdp), draft_id="t1-A"),
                    _row(trial="t1", cohort="B", workspace=str(tdp), draft_id="t1-B"),
                    _row(trial="t2", cohort="A", workspace=str(tdp), draft_id="t2-A"),
                ],
            )
            records = analyze_mod.load_log(log)
            groups, orphans = analyze_mod.group_by_trial(records)
        self.assertEqual(len(groups), 2)
        self.assertIn("A", groups["t1"])
        self.assertIn("B", groups["t1"])
        self.assertEqual(orphans, [("t2", "missing-B")])

    def test_09_inventory_reports_orphans(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            log = tdp / "log.jsonl"
            _seed_log(
                log,
                [
                    _row(trial="t1", cohort="A", workspace=str(tdp), draft_id="t1-A"),
                    _row(trial="t1", cohort="B", workspace=str(tdp), draft_id="t1-B"),
                    _row(trial="t2", cohort="A", workspace=str(tdp), draft_id="t2-A"),
                ],
            )
            inv = analyze_mod.inventory(log)
        self.assertEqual(inv["record_count"], 3)
        self.assertEqual(inv["trial_count"], 2)
        self.assertEqual(inv["matched_pair_count"], 1)
        self.assertEqual(inv["orphan_count"], 1)
        self.assertEqual(inv["meta1_status_breakdown"]["real"], 3)


class AnalyzerEmptyLogTest(unittest.TestCase):

    def test_10_empty_log_returns_insufficient_data(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            log = tdp / "empty.jsonl"
            log.write_text("", encoding="utf-8")
            out = analyze_mod.analyze(
                log,
                drafts_dir=None,
            )
        self.assertEqual(out["matched_pair_count"], 0)
        self.assertEqual(out["overall_verdict"], "insufficient_data")


class AnalyzerRuleScoringTest(unittest.TestCase):

    def test_11_per_rule_fail_rate_calculation(self):
        """With 12 matched pairs and a mock rule runner, the analyzer
        computes fail-rates correctly."""
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            ws = tdp / "ws"
            (ws / ".auditooor" / "meta1_ab_drafts").mkdir(parents=True)
            log = tdp / "log.jsonl"
            verdict_map: Dict[Any, str] = {}
            rows: List[Dict[str, Any]] = []
            # 12 matched pairs. Cohort A: 2/12 fail R42 (~16.7%).
            # Cohort B: 8/12 fail R42 (~66.7%). Delta -50%, helpful.
            for i in range(12):
                a_id = f"trial-{i:02d}-A"
                b_id = f"trial-{i:02d}-B"
                draft_a = ws / ".auditooor" / "meta1_ab_drafts" / f"{a_id}.md"
                draft_b = ws / ".auditooor" / "meta1_ab_drafts" / f"{b_id}.md"
                draft_a.write_text("draft body A\n", encoding="utf-8")
                draft_b.write_text("draft body B\n", encoding="utf-8")
                rows.append(_row(trial=f"trial-{i:02d}", cohort="A", workspace=str(ws), draft_id=a_id))
                rows.append(_row(trial=f"trial-{i:02d}", cohort="B", workspace=str(ws), draft_id=b_id))
                verdict_map[(str(draft_a), "R42")] = (
                    "fail-no-configured-impact-trace" if i < 2 else "pass-configured-impact-traced"
                )
                verdict_map[(str(draft_b), "R42")] = (
                    "fail-no-configured-impact-trace" if i < 8 else "pass-configured-impact-traced"
                )
            _seed_log(log, rows)
            out = analyze_mod.analyze(
                log,
                drafts_dir=ws / ".auditooor" / "meta1_ab_drafts",
                rule_filter=["R42"],
                rule_runner=_make_rule_runner(verdict_map),
            )
        r42 = out["per_rule_results"][0]
        self.assertEqual(r42["rule_id"], "R42")
        self.assertEqual(r42["cohort_a"]["n"], 12)
        self.assertEqual(r42["cohort_a"]["fails"], 2)
        self.assertEqual(r42["cohort_b"]["n"], 12)
        self.assertEqual(r42["cohort_b"]["fails"], 8)
        self.assertAlmostEqual(r42["delta_fail_rate"], (2 / 12) - (8 / 12), places=4)
        self.assertEqual(r42["verdict"], "helpful")
        self.assertEqual(out["overall_verdict"], "helpful")

    def test_12_inert_and_harmful_classification(self):
        """When delta CI straddles 0 verdict is inert; when A > B and
        CI excludes 0 verdict is harmful."""
        # Inert: equal fail-rates.
        verdict, _ = analyze_mod.classify_rule_result(10, 5, 10, 5)
        self.assertEqual(verdict, "inert")
        # Harmful: A 9/10 fail, B 1/10 fail.
        verdict, _ = analyze_mod.classify_rule_result(10, 9, 10, 1)
        self.assertEqual(verdict, "harmful")
        # Helpful: A 1/10, B 9/10.
        verdict, _ = analyze_mod.classify_rule_result(10, 1, 10, 9)
        self.assertEqual(verdict, "helpful")
        # Small sample: A n=5.
        verdict, _ = analyze_mod.classify_rule_result(5, 0, 10, 5)
        self.assertEqual(verdict, "insufficient_data")


class AnalyzerInventoryTest(unittest.TestCase):

    def test_13_inventory_mode_skips_rule_runs(self):
        """Inventory mode reports counts without invoking rule gates."""
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            log = tdp / "log.jsonl"
            _seed_log(
                log,
                [
                    _row(trial="t1", cohort="A", workspace=str(tdp), draft_id="d1", lane_type="hunt"),
                    _row(trial="t1", cohort="B", workspace=str(tdp), draft_id="d2", lane_type="hunt"),
                    _row(trial="t2", cohort="A", workspace=str(tdp), draft_id="d3", lane_type="dispute"),
                    _row(trial="t2", cohort="B", workspace=str(tdp), draft_id="d4", lane_type="dispute"),
                ],
            )
            inv = analyze_mod.inventory(log)
        self.assertEqual(inv["matched_pair_count"], 2)
        self.assertEqual(inv["lane_type_breakdown"]["hunt"], 2)
        self.assertEqual(inv["lane_type_breakdown"]["dispute"], 2)


class CIHelperTest(unittest.TestCase):

    def test_14_wilson_and_delta_edge_cases(self):
        low, high = analyze_mod.wilson_score_interval(0, 0)
        self.assertEqual(low, 0.0)
        self.assertEqual(high, 1.0)
        low, high = analyze_mod.wilson_score_interval(0, 10)
        self.assertLess(low, 0.05)
        self.assertGreater(high, 0.0)
        low, high = analyze_mod.wilson_score_interval(10, 10)
        self.assertLessEqual(high, 1.0)
        self.assertGreater(low, 0.5)
        # delta_ci with n=0 returns the full range.
        dl, dh = analyze_mod.delta_ci(0, 0, 5, 10)
        self.assertEqual((dl, dh), (-1.0, 1.0))


class AnalyzerMissingDraftTest(unittest.TestCase):

    def test_15_skips_drafts_that_resolve_to_none(self):
        """If neither cohort has a draft on disk, all rules report
        insufficient_data and overall verdict is insufficient_data."""
        with tempfile.TemporaryDirectory() as td:
            tdp = pathlib.Path(td)
            ws = tdp / "ws"
            ws.mkdir()
            log = tdp / "log.jsonl"
            rows = [
                _row(
                    trial="t1",
                    cohort="A",
                    workspace=str(ws),
                    draft_id="missing-A",
                ),
                _row(
                    trial="t1",
                    cohort="B",
                    workspace=str(ws),
                    draft_id="missing-B",
                ),
            ]
            _seed_log(log, rows)
            out = analyze_mod.analyze(
                log,
                drafts_dir=tdp / "nonexistent",
                rule_filter=["R42"],
                rule_runner=_make_rule_runner({}),
            )
        self.assertEqual(out["matched_pair_count"], 1)
        r42 = out["per_rule_results"][0]
        self.assertEqual(r42["cohort_a"]["n"], 0)
        self.assertEqual(r42["cohort_b"]["n"], 0)
        self.assertEqual(r42["verdict"], "insufficient_data")
        self.assertEqual(out["overall_verdict"], "insufficient_data")


if __name__ == "__main__":
    unittest.main()
