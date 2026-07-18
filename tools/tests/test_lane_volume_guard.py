#!/usr/bin/env python3
"""test_lane_volume_guard.py - Hermetic unit tests for lane-volume-guard.py.

Test cases:
  (a) a lane emitting a confirmed-verdict record -> FAIL (verdict purity)
  (b) a lane exceeding --max -> FAIL (flood)
  (c) all-needs-fuzz under threshold -> PASS
  (d) missing lane sidecar / missing workspace -> skip-not-crash

All tests use in-memory fixtures via tempfile; no real workspace touched.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# lane-volume-guard.py uses hyphens in the filename; load via importlib.
import importlib.util as _ilu

_TOOLS_DIR = Path(__file__).parent.parent
_GUARD_PATH = _TOOLS_DIR / "lane-volume-guard.py"
_spec = _ilu.spec_from_file_location("lane_volume_guard", _GUARD_PATH)
_mod = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

VALID_VERDICTS = _mod.VALID_VERDICTS
check_lane_workspace = _mod.check_lane_workspace
run_checks = _mod.run_checks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ws(tmp_dir: str, records: list[dict], sidecar_name: str) -> Path:
    """Create a fake workspace with .auditooor/<sidecar_name> populated."""
    ws = Path(tmp_dir)
    auditooor_dir = ws / ".auditooor"
    auditooor_dir.mkdir(parents=True, exist_ok=True)
    sidecar = auditooor_dir / sidecar_name
    with sidecar.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    return ws


def _make_record(verdict: str) -> dict:
    return {
        "function": "foo",
        "file": "src/Foo.sol",
        "attack_class": "self-dealing",
        "verdict": verdict,
    }


# ---------------------------------------------------------------------------
# Test (a): confirmed-verdict record -> FAIL
# ---------------------------------------------------------------------------

class TestVerdict(unittest.TestCase):

    def test_confirmed_verdict_fails(self):
        """A lane that emits verdict='confirmed' must produce status='fail'."""
        with tempfile.TemporaryDirectory() as tmp:
            records = [
                _make_record("needs-fuzz"),
                _make_record("confirmed"),  # invalid
            ]
            ws = _make_ws(tmp, records, "self_dealing_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="self-dealing-hypothesis-lane",
                sidecar_file="self_dealing_hypotheses.jsonl",
                default_threshold=50,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "fail")
        self.assertFalse(result["verdict_ok"])
        self.assertIn("confirmed", result["bad_verdicts"])

    def test_proven_verdict_fails(self):
        """verdict='proven' is also invalid."""
        with tempfile.TemporaryDirectory() as tmp:
            records = [_make_record("proven")]
            ws = _make_ws(tmp, records, "callback_reentrancy_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="callback-reentrancy-composition",
                sidecar_file="callback_reentrancy_hypotheses.jsonl",
                default_threshold=200,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "fail")
        self.assertIn("proven", result["bad_verdicts"])

    def test_severity_string_verdict_fails(self):
        """verdict='high' (severity string) must fail."""
        with tempfile.TemporaryDirectory() as tmp:
            records = [_make_record("high")]
            ws = _make_ws(tmp, records, "access_control_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="access-control-coverage",
                sidecar_file="access_control_hypotheses.jsonl",
                default_threshold=200,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "fail")
        self.assertIn("high", result["bad_verdicts"])

    def test_typed_skip_is_valid(self):
        """verdict='typed-skip' is explicitly allowed (used by ACL-COV)."""
        with tempfile.TemporaryDirectory() as tmp:
            records = [_make_record("typed-skip"), _make_record("needs-fuzz")]
            ws = _make_ws(tmp, records, "access_control_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="access-control-coverage",
                sidecar_file="access_control_hypotheses.jsonl",
                default_threshold=200,
                workspace=ws,
                flood_threshold_override=None,
            )
        # Only 2 records, well under threshold; all valid verdicts
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["verdict_ok"])

    def test_needs_llm_is_valid(self):
        """verdict='needs-llm' is a valid verdict token."""
        with tempfile.TemporaryDirectory() as tmp:
            records = [_make_record("needs-llm")]
            ws = _make_ws(tmp, records, "self_dealing_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="self-dealing-hypothesis-lane",
                sidecar_file="self_dealing_hypotheses.jsonl",
                default_threshold=50,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["verdict_ok"])

    def test_empty_verdict_fails(self):
        """An empty string verdict must fail."""
        with tempfile.TemporaryDirectory() as tmp:
            rec = {"function": "f", "verdict": ""}
            ws = _make_ws(tmp, [rec], "mev_ordering_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="mev-ordering-lane",
                sidecar_file="mev_ordering_hypotheses.jsonl",
                default_threshold=200,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "fail")
        self.assertIn("<empty>", result["bad_verdicts"])


# ---------------------------------------------------------------------------
# Test (b): flood -> FAIL
# ---------------------------------------------------------------------------

class TestFlood(unittest.TestCase):

    def test_exceeding_max_override_fails(self):
        """When count > --max override, status must be fail with flood=True."""
        with tempfile.TemporaryDirectory() as tmp:
            records = [_make_record("needs-fuzz")] * 10
            ws = _make_ws(tmp, records, "rounding_drain_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="rounding-drain-lane",
                sidecar_file="rounding_drain_hypotheses.jsonl",
                default_threshold=50,
                workspace=ws,
                flood_threshold_override=5,  # override to 5, records=10
            )
        self.assertEqual(result["status"], "fail")
        self.assertTrue(result["flood"])
        self.assertEqual(result["count"], 10)
        self.assertEqual(result["flood_threshold_used"], 5)

    def test_exceeding_default_threshold_fails(self):
        """Exceeding the per-lane default threshold with no override -> fail."""
        with tempfile.TemporaryDirectory() as tmp:
            # SADL default = 50; emit 51 records
            records = [_make_record("needs-fuzz")] * 51
            ws = _make_ws(tmp, records, "self_dealing_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="self-dealing-hypothesis-lane",
                sidecar_file="self_dealing_hypotheses.jsonl",
                default_threshold=50,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "fail")
        self.assertTrue(result["flood"])

    def test_exactly_at_threshold_passes(self):
        """Count == threshold is NOT a flood (strictly greater-than rule)."""
        with tempfile.TemporaryDirectory() as tmp:
            records = [_make_record("needs-fuzz")] * 50
            ws = _make_ws(tmp, records, "self_dealing_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="self-dealing-hypothesis-lane",
                sidecar_file="self_dealing_hypotheses.jsonl",
                default_threshold=50,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["flood"])

    def test_flood_via_run_checks_cli_path(self):
        """run_checks end-to-end: flood in one lane -> overall_pass=False."""
        with tempfile.TemporaryDirectory() as tmp_ws:
            records = [_make_record("needs-fuzz")] * 3  # 3 > max=2
            _make_ws(tmp_ws, records, "self_dealing_hypotheses.jsonl")
            _, overall_pass = run_checks(
                workspaces=[tmp_ws],
                flood_threshold_override=2,
            )
        self.assertFalse(overall_pass)


# ---------------------------------------------------------------------------
# Test (c): all-needs-fuzz under threshold -> PASS
# ---------------------------------------------------------------------------

class TestCleanLane(unittest.TestCase):

    def test_all_needs_fuzz_under_threshold_passes(self):
        """All needs-fuzz records, count under threshold -> pass."""
        with tempfile.TemporaryDirectory() as tmp:
            records = [_make_record("needs-fuzz")] * 20
            ws = _make_ws(tmp, records, "oracle_reachability_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="oracle-reachability-lane",
                sidecar_file="oracle_reachability_hypotheses.jsonl",
                default_threshold=200,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["verdict_ok"])
        self.assertFalse(result["flood"])

    def test_empty_sidecar_passes(self):
        """Empty sidecar (0 records) -> pass (lane ran but found nothing)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp, [], "share_inflation_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="share-inflation-lane",
                sidecar_file="share_inflation_hypotheses.jsonl",
                default_threshold=50,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["count"], 0)

    def test_run_checks_all_clean(self):
        """run_checks with two clean workspaces -> overall_pass=True."""
        with (
            tempfile.TemporaryDirectory() as tmp_a,
            tempfile.TemporaryDirectory() as tmp_b,
        ):
            for tmp in [tmp_a, tmp_b]:
                _make_ws(tmp, [_make_record("needs-fuzz")] * 5,
                         "self_dealing_hypotheses.jsonl")
            _, overall_pass = run_checks(
                workspaces=[tmp_a, tmp_b],
                flood_threshold_override=None,
            )
        self.assertTrue(overall_pass)


# ---------------------------------------------------------------------------
# Test (d): missing lane / missing workspace -> skip-not-crash
# ---------------------------------------------------------------------------

class TestSkipBehavior(unittest.TestCase):

    def test_missing_workspace_skips(self):
        """A workspace path that does not exist -> status='skip', no crash."""
        result = check_lane_workspace(
            lane_name="self-dealing-hypothesis-lane",
            sidecar_file="self_dealing_hypotheses.jsonl",
            default_threshold=50,
            workspace=Path("/nonexistent/path/that/does/not/exist/12345"),
            flood_threshold_override=None,
        )
        self.assertEqual(result["status"], "skip")
        self.assertIsNotNone(result["skip_reason"])

    def test_missing_sidecar_skips(self):
        """Workspace exists but sidecar not yet generated -> skip."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            # Do NOT create the sidecar
            result = check_lane_workspace(
                lane_name="init-upgrade-lane",
                sidecar_file="init_upgrade_hypotheses.jsonl",
                default_threshold=200,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "skip")
        self.assertIn("sidecar not found", result["skip_reason"])

    def test_missing_auditooor_dir_skips(self):
        """Workspace exists but no .auditooor directory at all -> skip."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # No .auditooor dir
            result = check_lane_workspace(
                lane_name="mev-ordering-lane",
                sidecar_file="mev_ordering_hypotheses.jsonl",
                default_threshold=200,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "skip")

    def test_run_checks_skips_nonexistent(self):
        """run_checks with a nonexistent workspace path -> skips, no crash,
        overall_pass=True (skip is not a failure)."""
        _, overall_pass = run_checks(
            workspaces=["/no/such/path/exists/xyz9999"],
            flood_threshold_override=None,
        )
        # Skips are not failures
        self.assertTrue(overall_pass)

    def test_mixed_existing_missing_workspace(self):
        """One valid workspace (clean) + one nonexistent -> overall PASS."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_ws(tmp, [_make_record("needs-fuzz")],
                     "self_dealing_hypotheses.jsonl")
            _, overall_pass = run_checks(
                workspaces=[tmp, "/no/such/path/xyz"],
                flood_threshold_override=None,
            )
        self.assertTrue(overall_pass)


# ---------------------------------------------------------------------------
# Additional edge-case tests
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):

    def test_both_fail_conditions_reported(self):
        """When a lane both has bad verdicts AND floods, both are flagged."""
        with tempfile.TemporaryDirectory() as tmp:
            # 6 records, 5 bad, threshold=5 -> flood + bad verdict
            records = [_make_record("confirmed")] * 5 + [_make_record("needs-fuzz")]
            ws = _make_ws(tmp, records, "self_dealing_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="self-dealing-hypothesis-lane",
                sidecar_file="self_dealing_hypotheses.jsonl",
                default_threshold=50,
                workspace=ws,
                flood_threshold_override=5,
            )
        self.assertEqual(result["status"], "fail")
        self.assertTrue(result["flood"])
        self.assertFalse(result["verdict_ok"])

    def test_count_is_accurate(self):
        """count reflects actual number of non-empty lines parsed."""
        with tempfile.TemporaryDirectory() as tmp:
            records = [_make_record("needs-fuzz")] * 7
            ws = _make_ws(tmp, records, "oracle_reachability_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="oracle-reachability-lane",
                sidecar_file="oracle_reachability_hypotheses.jsonl",
                default_threshold=200,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["count"], 7)

    def test_auto_credit_verdict_fails(self):
        """verdict='auto-credit' must fail (explicitly mentioned in spec)."""
        with tempfile.TemporaryDirectory() as tmp:
            records = [_make_record("auto-credit")]
            ws = _make_ws(tmp, records, "rounding_drain_hypotheses.jsonl")
            result = check_lane_workspace(
                lane_name="rounding-drain-lane",
                sidecar_file="rounding_drain_hypotheses.jsonl",
                default_threshold=50,
                workspace=ws,
                flood_threshold_override=None,
            )
        self.assertEqual(result["status"], "fail")
        self.assertIn("auto-credit", result["bad_verdicts"])


if __name__ == "__main__":
    unittest.main()
