"""Unit tests for tools/audit-question-burndown.py."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from io import StringIO


REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "audit-question-burndown.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("audit_question_burndown", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


AQB = _load_module()


def _write_state(tmpdir: pathlib.Path, state: dict) -> pathlib.Path:
    p = tmpdir / "state.json"
    p.write_text(json.dumps(state), encoding="utf-8")
    return p


class ClassifyEntryTests(unittest.TestCase):
    """Cover each verdict_shape -> classification mapping."""

    def test_holds_with_invariant_cite_is_accepted(self):
        entry = {
            "lane": "W2-B-3",
            "verdict_shape": "HOLDS",
            "subject": "vault_engage_report MCP callable, RFC 9591 invariant pin",
        }
        cls, respawn, reason = AQB.classify_entry(entry, [])
        self.assertEqual(cls, AQB.CLS_ACCEPTED)
        self.assertFalse(respawn)
        self.assertIn("invariant", reason.lower())

    def test_holds_without_invariant_cite_flags_respawn(self):
        entry = {
            "lane": "X1",
            "verdict_shape": "HOLDS",
            "subject": "did some stuff",
            "note": "tests pass",
        }
        cls, respawn, reason = AQB.classify_entry(entry, [])
        self.assertEqual(cls, AQB.CLS_RESPAWN_HOLDS)
        self.assertTrue(respawn)

    def test_drop_justified_with_class_marker_is_accepted(self):
        entry = {
            "lane": "H7",
            "verdict_shape": "DROP-justified-(b)",
            "rationale": "non-mainnet impact, all CVEs OOS",
        }
        cls, respawn, reason = AQB.classify_entry(entry, [])
        self.assertEqual(cls, AQB.CLS_DROP_OK)
        self.assertFalse(respawn)

    def test_drop_without_justification_flags_respawn(self):
        entry = {
            "lane": "Y2",
            "verdict_shape": "DROP",
            "note": "didn't pan out",
        }
        cls, respawn, reason = AQB.classify_entry(entry, [])
        self.assertEqual(cls, AQB.CLS_RESPAWN_DROP)
        self.assertTrue(respawn)

    def test_genuine_drop_with_evidence_is_accepted(self):
        entry = {
            "lane": "H5-build-spark-rs-go",
            "verdict": "GENUINE_DROP",
            "build_evidence": "positive",
            "note": "zero in-tree callers; structurally immune; dead code at audit-pin",
        }
        cls, respawn, reason = AQB.classify_entry(entry, [])
        self.assertEqual(cls, AQB.CLS_DROP_OK)
        self.assertFalse(respawn)

    def test_needs_build_with_matching_queued_lead_is_absorbed(self):
        entry = {"lane": "H7-stale-dkg", "verdict_shape": "NEEDS-BUILD"}
        queued = [{"id": "H7-stale-dkg-state-retention"}]
        cls, respawn, reason = AQB.classify_entry(entry, queued)
        self.assertEqual(cls, AQB.CLS_NEEDS_BUILD)
        self.assertFalse(respawn)
        self.assertIn("absorbed", reason.lower())

    def test_needs_build_without_queued_lead_flags_respawn(self):
        entry = {"lane": "ORPHAN-LANE", "verdict_shape": "NEEDS-BUILD"}
        cls, respawn, reason = AQB.classify_entry(entry, [])
        self.assertEqual(cls, AQB.CLS_NEEDS_BUILD)
        self.assertTrue(respawn)
        self.assertIn("no matching", reason.lower())

    def test_missing_verdict_shape_flags_respawn_no_verdict(self):
        entry = {"lane": "M-A", "iteration": 1, "tests": "PASS"}
        cls, respawn, reason = AQB.classify_entry(entry, [])
        self.assertEqual(cls, AQB.CLS_RESPAWN_NO_VERDICT)
        self.assertTrue(respawn)
        self.assertIn("pre-w2", reason.lower())

    def test_legacy_negative_with_justification_is_accepted_drop(self):
        entry = {
            "lane": "H1-coop-exit",
            "verdict": "NEGATIVE",
            "note": "no rubric verbatim CRIT-1/CRIT-2/HIGH-1; class-(c) symptom-fix",
        }
        cls, respawn, reason = AQB.classify_entry(entry, [])
        self.assertEqual(cls, AQB.CLS_DROP_OK)
        self.assertFalse(respawn)

    def test_legacy_negative_without_justification_flags_respawn(self):
        entry = {"lane": "H7", "verdict": "NEGATIVE"}
        cls, respawn, reason = AQB.classify_entry(entry, [])
        self.assertEqual(cls, AQB.CLS_RESPAWN_NO_VERDICT)
        self.assertTrue(respawn)


class JSONOutputSchemaTests(unittest.TestCase):
    def test_json_schema_shape(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            state = {
                "pending_commits": [
                    {"lane": "A", "iter": 1, "verdict_shape": "HOLDS",
                     "subject": "RFC 9591 invariant cited"},
                    {"lane": "B", "iter": 1, "verdict_shape": "DROP-justified-(b)",
                     "rationale": "non-mainnet"},
                    {"lane": "C", "iter": 1},  # missing verdict
                ],
                "queued_leads": [],
            }
            sp = _write_state(tmp, state)
            buf = StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                rc = AQB.main(["--state-file", str(sp), "--json", "--quiet"])
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["schema"], AQB.SCHEMA)
            self.assertEqual(payload["total_pending"], 3)
            self.assertIn("by_classification", payload)
            self.assertIn("rows", payload)
            self.assertIn("respawn_queue", payload)
            self.assertEqual(len(payload["rows"]), 3)
            for cls in AQB.ALL_CLS:
                self.assertIn(cls, payload["by_classification"])
            # one accepted, one drop, one respawn_no_verdict
            self.assertEqual(payload["by_classification"][AQB.CLS_ACCEPTED], 1)
            self.assertEqual(payload["by_classification"][AQB.CLS_DROP_OK], 1)
            self.assertEqual(payload["by_classification"][AQB.CLS_RESPAWN_NO_VERDICT], 1)
            self.assertEqual(len(payload["respawn_queue"]), 1)
            self.assertEqual(payload["respawn_queue"][0]["lane"], "C")


class EmptyStateEdgeCaseTests(unittest.TestCase):
    def test_empty_pending_commits(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            sp = _write_state(tmp, {"pending_commits": [], "queued_leads": []})
            buf = StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                rc = AQB.main(["--state-file", str(sp), "--json", "--quiet"])
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["total_pending"], 0)
            self.assertEqual(payload["rows"], [])
            self.assertEqual(payload["respawn_queue"], [])
            for cls in AQB.ALL_CLS:
                self.assertEqual(payload["by_classification"][cls], 0)

    def test_missing_state_file_exits_nonzero(self):
        with self.assertRaises(SystemExit) as cm:
            AQB.load_state(pathlib.Path("/nonexistent/state.json"))
        # SystemExit raised with string message; just check it's not 0
        self.assertNotEqual(cm.exception.code, 0)


class WorkspacePathResolutionTests(unittest.TestCase):
    def test_workspace_default_path_resolution(self):
        """--workspace foo/ resolves state file at foo/.auditooor/spark_hunt_loop_state.json."""
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            (tmp / ".auditooor").mkdir()
            sp = tmp / ".auditooor" / "spark_hunt_loop_state.json"
            sp.write_text(
                json.dumps(
                    {
                        "pending_commits": [
                            {"lane": "T", "iter": 1, "verdict_shape": "HOLDS",
                             "subject": "audit-pin commit cite"}
                        ],
                        "queued_leads": [],
                    }
                ),
                encoding="utf-8",
            )
            buf = StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                rc = AQB.main(["--workspace", str(tmp), "--json", "--quiet"])
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["total_pending"], 1)
            self.assertEqual(payload["rows"][0]["classification"], AQB.CLS_ACCEPTED)


class HumanRenderTests(unittest.TestCase):
    def test_human_output_contains_table_headers(self):
        rows = [
            {
                "lane": "A",
                "iter": 1,
                "verdict_shape": "HOLDS",
                "classification": AQB.CLS_ACCEPTED,
                "re_spawn_flag": False,
                "reason": "ok",
            }
        ]
        out = AQB.render_human(rows, [], pathlib.Path("/tmp/ws"), pathlib.Path("/tmp/s.json"))
        self.assertIn("# Audit-question burndown", out)
        self.assertIn("Classification summary", out)
        self.assertIn("Burndown table", out)
        self.assertIn("Re-spawn queue", out)
        self.assertIn("`A`", out)
        self.assertIn(AQB.CLS_ACCEPTED, out)


class HelperFunctionTests(unittest.TestCase):
    def test_normalize_shape_prefers_verdict_shape(self):
        self.assertEqual(
            AQB._normalize_shape({"verdict_shape": "HOLDS", "verdict": "NEGATIVE"}),
            "HOLDS",
        )

    def test_normalize_shape_falls_back_to_legacy_verdict(self):
        self.assertEqual(
            AQB._normalize_shape({"verdict": "NEGATIVE"}),
            "NEGATIVE",
        )

    def test_normalize_shape_returns_empty_when_neither_set(self):
        self.assertEqual(AQB._normalize_shape({"lane": "X"}), "")

    def test_lane_absorbed_in_queued_leads_substring_match(self):
        self.assertTrue(
            AQB._lane_absorbed_in_queued_leads(
                "H7-stale-dkg", [{"id": "H7-stale-dkg-state-retention"}]
            )
        )
        self.assertFalse(
            AQB._lane_absorbed_in_queued_leads("Z9-orphan", [{"id": "H7-something"}])
        )
        self.assertFalse(AQB._lane_absorbed_in_queued_leads("H7", []))


if __name__ == "__main__":
    unittest.main()
