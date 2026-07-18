"""
Tests for tools/temporal-state-provenance.py (G5 temporal live-state provenance runner).
Schema: auditooor.temporal_state_provenance.v1

All tests are OFFLINE-SAFE: no network calls are made. Fixtures are built
synthetically in a tempdir.

Run with: python3 -m unittest tools.tests.test_temporal_state_provenance -v
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Load tool module
# ---------------------------------------------------------------------------

TOOL_PATH = Path(__file__).resolve().parents[1] / "temporal-state-provenance.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("temporal_state_provenance", TOOL_PATH)
    assert spec and spec.loader, f"Cannot load {TOOL_PATH}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


TOOL = _load_tool()

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _make_ws(tmp: Path) -> Path:
    """Create a minimal workspace skeleton and return the ws path."""
    ws = tmp / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / ".auditooor").mkdir(exist_ok=True)
    return ws


def _write_exploit_queue(ws: Path, items: list[dict[str, Any]]) -> None:
    """Write a real-workspace-shaped exploit_queue.json (dict wrapper)."""
    data = {
        "schema": "auditooor.exploit_queue.v1",
        "context_pack_id": "test-pack-001",
        "context_pack_hash": "abc123",
        "generated_at_utc": "2026-05-22T00:00:00Z",
        "queue": items,
        "total_candidates": len(items),
        "top_n": len(items),
        "workspace": str(ws),
        "benchmark": {},
        "source_artifacts_consumed": [],
    }
    (ws / ".auditooor" / "exploit_queue.json").write_text(
        json.dumps(data, indent=2), encoding="utf-8"
    )


def _write_timeline(ws: Path, lead_id: str, events: list[dict[str, Any]]) -> None:
    """Write a filled timeline for a candidate."""
    timeline_dir = ws / ".auditooor" / "temporal_timelines"
    timeline_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "schema": "auditooor.temporal_state_provenance.v1",
        "lead_id": lead_id,
        "template_unfilled": False,
        "events": events,
    }
    (timeline_dir / f"{lead_id}.json").write_text(
        json.dumps(data, indent=2), encoding="utf-8"
    )


def _high_candidate(lead_id: str = "EQ-001", title: str = "Test finding") -> dict[str, Any]:
    return {
        "lead_id": lead_id,
        "title": title,
        "likely_severity": "high",
        "attack_class": "reentrancy",
        "proof_status": "needs_harness",
    }


def _critical_candidate(lead_id: str = "EQ-002", title: str = "Critical finding") -> dict[str, Any]:
    return {
        "lead_id": lead_id,
        "title": title,
        "likely_severity": "critical",
        "attack_class": "access-control",
        "proof_status": "needs_harness",
    }


def _medium_candidate(lead_id: str = "EQ-003") -> dict[str, Any]:
    return {
        "lead_id": lead_id,
        "title": "Medium finding",
        "likely_severity": "medium",
        "attack_class": "precision-loss",
        "proof_status": "needs_harness",
    }


# ---------------------------------------------------------------------------
# Test 1: Empty workspace (no exploit_queue.json)
# ---------------------------------------------------------------------------

class TestEmptyWorkspace(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_ws(self.tmp)

    def tearDown(self):
        self._tmp.cleanup()

    def test_empty_workspace_no_crash(self):
        """Empty workspace with no exploit_queue.json must not crash."""
        result = TOOL.build_check_report(self.ws)
        self.assertIsInstance(result, dict)

    def test_empty_workspace_missing_artifact_flagged(self):
        """Missing exploit_queue.json is reported as missing_artifact."""
        result = TOOL.build_check_report(self.ws)
        self.assertIn("exploit_queue.json", result.get("missing_artifacts", []))

    def test_empty_workspace_no_high_critical_candidates(self):
        """No candidates when queue is absent."""
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result.get("high_critical_candidates", 0), 0)

    def test_empty_workspace_gate_not_fail(self):
        """Acceptance gate is not FAIL when no candidates exist."""
        result = TOOL.build_check_report(self.ws)
        self.assertNotEqual(result.get("acceptance_gate"), "FAIL")

    def test_empty_workspace_queue_loaded_false(self):
        result = TOOL.build_check_report(self.ws)
        self.assertFalse(result.get("queue_loaded"))


# ---------------------------------------------------------------------------
# Test 2: High/Critical candidate with no timeline (check flags it)
# ---------------------------------------------------------------------------

class TestHighCandidateNoTimeline(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_ws(self.tmp)
        _write_exploit_queue(self.ws, [_high_candidate("EQ-001")])

    def tearDown(self):
        self._tmp.cleanup()

    def test_candidate_counted(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["high_critical_candidates"], 1)

    def test_no_timeline_means_fail(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["passed"], 0)

    def test_acceptance_gate_is_fail(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["acceptance_gate"], "FAIL")

    def test_candidate_status_fail(self):
        result = TOOL.build_check_report(self.ws)
        cands = result.get("candidates", [])
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["status"], "fail")

    def test_medium_not_included(self):
        """Medium candidates are not in the acceptance gate check."""
        _write_exploit_queue(self.ws, [_high_candidate("EQ-001"), _medium_candidate("EQ-099")])
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["high_critical_candidates"], 1)

    def test_verdict_mentions_scaffold(self):
        result = TOOL.build_check_report(self.ws)
        verdict = result["candidates"][0]["verdict"]
        self.assertIn("scaffold", verdict.lower())


# ---------------------------------------------------------------------------
# Test 3: Candidate with a complete filled timeline (passes)
# ---------------------------------------------------------------------------

class TestCandidateWithFilledTimeline(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_ws(self.tmp)
        _write_exploit_queue(self.ws, [_high_candidate("EQ-001")])
        _write_timeline(self.ws, "EQ-001", [
            {"kind": "deployment_tx", "block": 12345678, "tx_hash": "0xabc", "deployer": "0x1234"},
            {"kind": "upgrade", "block": 13000000, "old_impl": "0xOLD", "new_impl": "0xNEW"},
        ])

    def tearDown(self):
        self._tmp.cleanup()

    def test_candidate_passes(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["passed"], 1)
        self.assertEqual(result["failed"], 0)

    def test_acceptance_gate_pass(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["acceptance_gate"], "PASS")

    def test_candidate_status_pass(self):
        result = TOOL.build_check_report(self.ws)
        cands = result["candidates"]
        self.assertEqual(cands[0]["status"], "pass")

    def test_event_count_reported(self):
        result = TOOL.build_check_report(self.ws)
        cands = result["candidates"]
        self.assertEqual(cands[0]["event_count"], 2)

    def test_evidence_present_true(self):
        result = TOOL.build_check_report(self.ws)
        self.assertTrue(result["candidates"][0]["evidence_present"])


# ---------------------------------------------------------------------------
# Test 4: Candidate with NO_TEMPORAL_STATE_RELEVANCE marker (passes)
# ---------------------------------------------------------------------------

class TestCandidateWithNTSRMarker(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_ws(self.tmp)
        candidate = _critical_candidate("EQ-002")
        candidate["NO_TEMPORAL_STATE_RELEVANCE"] = (
            "Contract is non-upgradeable and has no oracle or role-grant history; "
            "all relevant state is encoded at deploy time."
        )
        _write_exploit_queue(self.ws, [candidate])

    def tearDown(self):
        self._tmp.cleanup()

    def test_ntsr_candidate_passes(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["passed"], 1)
        self.assertEqual(result["failed"], 0)

    def test_status_is_no_temporal_state_relevance(self):
        result = TOOL.build_check_report(self.ws)
        cands = result["candidates"]
        self.assertEqual(cands[0]["status"], "no_temporal_state_relevance")

    def test_acceptance_gate_pass(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["acceptance_gate"], "PASS")

    def test_ntsr_evidence_present_in_result(self):
        result = TOOL.build_check_report(self.ws)
        cands = result["candidates"]
        self.assertTrue(len(cands[0]["no_tsri_evidence"]) > 0)


# ---------------------------------------------------------------------------
# Test 5: Strict mode exits non-zero when candidate fails
# ---------------------------------------------------------------------------

class TestStrictMode(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_ws(self.tmp)
        _write_exploit_queue(self.ws, [_high_candidate("EQ-001")])

    def tearDown(self):
        self._tmp.cleanup()

    def test_strict_nonzero_on_fail(self):
        """--strict exits non-zero when a candidate has no timeline."""
        ret = TOOL.main(["--workspace", str(self.ws), "--strict", "--no-file"])
        self.assertNotEqual(ret, 0)

    def test_strict_zero_when_all_pass(self):
        """--strict exits 0 when all candidates pass."""
        _write_timeline(self.ws, "EQ-001", [
            {"kind": "deployment_tx", "block": 100, "tx_hash": "0xaaa"}
        ])
        ret = TOOL.main(["--workspace", str(self.ws), "--strict", "--no-file"])
        self.assertEqual(ret, 0)

    def test_nonstrict_zero_even_on_fail(self):
        """Without --strict, tool exits 0 even when candidates fail gate."""
        ret = TOOL.main(["--workspace", str(self.ws), "--no-file"])
        self.assertEqual(ret, 0)

    def test_nonexistent_workspace_returns_2(self):
        ret = TOOL.main(["--workspace", "/nonexistent/path/xyz123", "--no-file"])
        self.assertEqual(ret, 2)


# ---------------------------------------------------------------------------
# Test 6: --scaffold template emission
# ---------------------------------------------------------------------------

class TestScaffold(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_ws(self.tmp)
        _write_exploit_queue(self.ws, [
            _high_candidate("EQ-001"),
            _critical_candidate("EQ-002"),
        ])

    def tearDown(self):
        self._tmp.cleanup()

    def test_scaffold_emits_timelines(self):
        result = TOOL.build_scaffold(self.ws)
        self.assertIn("EQ-001", result.get("timelines", {}))
        self.assertIn("EQ-002", result.get("timelines", {}))

    def test_scaffold_is_template_unfilled(self):
        result = TOOL.build_scaffold(self.ws)
        for lead_id, scaffold in result["timelines"].items():
            self.assertTrue(
                scaffold.get("template_unfilled"),
                f"{lead_id} scaffold should be template_unfilled"
            )

    def test_scaffold_has_all_event_kinds(self):
        result = TOOL.build_scaffold(self.ws)
        scaffold = result["timelines"]["EQ-001"]
        kinds = {ev["kind"] for ev in scaffold["events"]}
        expected = set(TOOL.EVENT_KINDS)
        self.assertEqual(kinds, expected)

    def test_scaffold_events_have_query_hint(self):
        result = TOOL.build_scaffold(self.ws)
        scaffold = result["timelines"]["EQ-001"]
        for ev in scaffold["events"]:
            self.assertIn(
                "query_hint", ev,
                f"Event kind {ev['kind']} missing query_hint"
            )

    def test_scaffold_skips_filled_candidate(self):
        """A candidate with a filled timeline is skipped in scaffold mode."""
        _write_timeline(self.ws, "EQ-001", [
            {"kind": "deployment_tx", "block": 1, "tx_hash": "0xfill"}
        ])
        result = TOOL.build_scaffold(self.ws)
        self.assertNotIn("EQ-001", result.get("timelines", {}))
        self.assertIn("EQ-001", result.get("skipped_already_filled", []))

    def test_scaffold_note_says_not_real_evidence(self):
        result = TOOL.build_scaffold(self.ws)
        scaffold = result["timelines"]["EQ-001"]
        note = scaffold.get("note", "")
        self.assertIn("TEMPLATE", note.upper())
        self.assertIn("NOT REAL EVIDENCE", note.upper())

    def test_scaffold_mode_field(self):
        result = TOOL.build_scaffold(self.ws)
        self.assertEqual(result["mode"], "scaffold")

    def test_scaffold_emitted_list(self):
        result = TOOL.build_scaffold(self.ws)
        self.assertIn("EQ-001", result["scaffolds_emitted"])
        self.assertIn("EQ-002", result["scaffolds_emitted"])

    def test_scaffold_cli_exits_zero(self):
        ret = TOOL.main(["--workspace", str(self.ws), "--scaffold", "--no-file"])
        self.assertEqual(ret, 0)


# ---------------------------------------------------------------------------
# Test 7: JSON schema field presence
# ---------------------------------------------------------------------------

class TestJsonSchemaFields(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_ws(self.tmp)
        _write_exploit_queue(self.ws, [_high_candidate("EQ-001")])

    def tearDown(self):
        self._tmp.cleanup()

    def test_top_level_required_check_fields(self):
        result = TOOL.build_check_report(self.ws)
        required = {
            "schema", "schema_version", "workspace", "generated_at",
            "mode", "offline_safe", "queue_loaded",
            "high_critical_candidates", "passed", "failed",
            "acceptance_gate", "candidates",
        }
        missing = required - set(result.keys())
        self.assertFalse(missing, f"Missing required check fields: {missing}")

    def test_schema_value(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["schema"], "auditooor.temporal_state_provenance.v1")

    def test_schema_version_is_1(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["schema_version"], "1")

    def test_offline_safe_true(self):
        result = TOOL.build_check_report(self.ws)
        self.assertTrue(result["offline_safe"])

    def test_generated_at_iso_format(self):
        result = TOOL.build_check_report(self.ws)
        ts = result["generated_at"]
        self.assertIn("T", ts)
        self.assertTrue(ts.endswith("Z"), f"Bad timestamp: {ts}")

    def test_candidate_row_required_fields(self):
        result = TOOL.build_check_report(self.ws)
        for cand in result["candidates"]:
            required_cand = {"lead_id", "title", "likely_severity", "status", "verdict"}
            missing = required_cand - set(cand.keys())
            self.assertFalse(missing, f"Missing candidate fields: {missing}")

    def test_json_stdout_mode_valid_json(self):
        captured = io.StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured
        try:
            ret = TOOL.main(["--workspace", str(self.ws), "--json", "--no-file"])
        finally:
            sys.stdout = original_stdout
        self.assertEqual(ret, 0)
        data = json.loads(captured.getvalue())
        self.assertEqual(data["schema"], "auditooor.temporal_state_provenance.v1")

    def test_scaffold_json_stdout_valid(self):
        captured = io.StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured
        try:
            ret = TOOL.main(["--workspace", str(self.ws), "--scaffold", "--json", "--no-file"])
        finally:
            sys.stdout = original_stdout
        self.assertEqual(ret, 0)
        data = json.loads(captured.getvalue())
        self.assertEqual(data["schema"], "auditooor.temporal_state_provenance.v1")
        self.assertEqual(data["mode"], "scaffold")


# ---------------------------------------------------------------------------
# Test 8: Template-unfilled timeline treated as fail
# ---------------------------------------------------------------------------

class TestTemplateUnfilledTimeline(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_ws(self.tmp)
        _write_exploit_queue(self.ws, [_high_candidate("EQ-001")])
        # Write a scaffold (template_unfilled=True) as if operator ran --scaffold
        # but did not fill it
        timeline_dir = self.ws / ".auditooor" / "temporal_timelines"
        timeline_dir.mkdir(parents=True, exist_ok=True)
        unfilled = {
            "schema": "auditooor.temporal_state_provenance.v1",
            "lead_id": "EQ-001",
            "template_unfilled": True,
            "events": [],
        }
        (timeline_dir / "EQ-001.json").write_text(json.dumps(unfilled), encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_unfilled_timeline_is_fail(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["candidates"][0]["status"], "fail")

    def test_unfilled_timeline_flag_in_candidate(self):
        result = TOOL.build_check_report(self.ws)
        self.assertTrue(result["candidates"][0]["timeline_unfilled"])


# ---------------------------------------------------------------------------
# Test 9: Candidate filter (--candidate)
# ---------------------------------------------------------------------------

class TestCandidateFilter(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_ws(self.tmp)
        _write_exploit_queue(self.ws, [
            _high_candidate("EQ-001"),
            _critical_candidate("EQ-002"),
        ])
        _write_timeline(self.ws, "EQ-001", [
            {"kind": "deployment_tx", "block": 1, "tx_hash": "0xfill"}
        ])

    def tearDown(self):
        self._tmp.cleanup()

    def test_candidate_filter_restricts_results(self):
        result = TOOL.build_check_report(self.ws, candidate_filter="EQ-001")
        self.assertEqual(result["high_critical_candidates"], 1)
        self.assertEqual(result["candidates"][0]["lead_id"], "EQ-001")

    def test_candidate_filter_on_failing_candidate(self):
        result = TOOL.build_check_report(self.ws, candidate_filter="EQ-002")
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["candidates"][0]["lead_id"], "EQ-002")


# ---------------------------------------------------------------------------
# Test 10: Monolithic temporal_state_provenance.json loaded
# ---------------------------------------------------------------------------

class TestMonolithicTimeline(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_ws(self.tmp)
        _write_exploit_queue(self.ws, [_high_candidate("EQ-001")])
        # Write monolithic file
        mono = {
            "schema": "auditooor.temporal_state_provenance.v1",
            "timelines": {
                "EQ-001": {
                    "template_unfilled": False,
                    "events": [
                        {"kind": "deployment_tx", "block": 10},
                        {"kind": "upgrade", "block": 20},
                    ],
                }
            }
        }
        (self.ws / ".auditooor" / "temporal_state_provenance.json").write_text(
            json.dumps(mono), encoding="utf-8"
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_monolithic_timeline_detected(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["passed"], 1)
        self.assertEqual(result["failed"], 0)

    def test_monolithic_event_count(self):
        result = TOOL.build_check_report(self.ws)
        self.assertEqual(result["candidates"][0]["event_count"], 2)


if __name__ == "__main__":
    unittest.main()
