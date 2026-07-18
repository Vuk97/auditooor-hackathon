"""Tests for tools/hunter-packet-outcome-join.py (B9 - HACKERMAN V3 plan).

Covers:
1. Empty workspace (no sources present) - defensive, no crash
2. evidence_scope=proof assigned from proof_artifact_index
3. evidence_scope=OOS assigned from outcomes.jsonl outcome=oos
4. evidence_scope=dupe assigned from outcomes.jsonl outcome=duplicate
5. evidence_scope=economics assigned from outcomes.jsonl outcome=unprofitable
6. evidence_scope=severity_cap assigned from triager_patterns rejections
7. evidence_scope=team_position assigned from outcomes.jsonl outcome=acknowledged
8. evidence_scope=context_only assigned for pending outcomes
9. Row cap (bounded output - cap=3 with more rows available)
10. Single-source join (only outcomes.jsonl present)
11. Full join (all sources present) - schema field presence verification
12. JSON output schema id is correct
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Dynamic import of hunter-packet-outcome-join (hyphen in filename)
# ---------------------------------------------------------------------------

_TOOL_PATH = Path(__file__).resolve().parents[1] / "hunter-packet-outcome-join.py"


def _import_tool():
    spec = importlib.util.spec_from_file_location("hunter_packet_outcome_join", _TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_mod = _import_tool()
build_join = _mod.build_join
SCHEMA = _mod.SCHEMA
EVIDENCE_SCOPE_VOCAB = _mod.EVIDENCE_SCOPE_VOCAB


class TestHunterPacketOutcomeJoin(unittest.TestCase):
    """All tests use synthetic fixtures in a tempdir."""

    # ------------------------------------------------------------------
    # Helper: create a minimal fake repo + workspace layout
    # ------------------------------------------------------------------

    def _make_repo(self, tmp: Path) -> Path:
        """Return a repo_root with the canonical directory skeleton."""
        (tmp / "reference").mkdir(parents=True)
        (tmp / "audit" / "corpus_tags" / "derived").mkdir(parents=True)
        (tmp / "audit" / "corpus_tags" / "tags").mkdir(parents=True)
        return tmp

    def _write_jsonl(self, path: Path, rows: list[dict]) -> None:
        path.write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n",
            encoding="utf-8",
        )

    def _write_json(self, path: Path, obj) -> None:
        path.write_text(json.dumps(obj), encoding="utf-8")

    def _make_workspace(self, tmp: Path, name: str = "ws") -> Path:
        ws = tmp / name
        (ws / ".auditooor" / "agent_artifacts").mkdir(parents=True)
        return ws

    # ------------------------------------------------------------------
    # Test 1: Empty workspace - no sources - defensive no crash
    # ------------------------------------------------------------------

    def test_01_empty_workspace_no_crash(self):
        """build_join must not raise even when all sources are absent."""
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td) / "repo"
            repo_root.mkdir()
            # No reference dir, no derived dir
            packet = build_join(
                repo_root=repo_root,
                workspace_path=None,
                attack_class=None,
                bug_class=None,
            )
        self.assertEqual(packet["schema"], SCHEMA)
        self.assertIsInstance(packet["missing_sources"], list)
        self.assertGreater(len(packet["missing_sources"]), 0)
        self.assertIsInstance(packet["rows"], list)
        self.assertFalse(packet["capped"])

    # ------------------------------------------------------------------
    # Test 2: evidence_scope=proof from proof_artifact_index
    # ------------------------------------------------------------------

    def test_02_evidence_scope_proof_from_proof_index(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = self._make_repo(Path(td))
            self._write_jsonl(
                repo_root / "audit" / "corpus_tags" / "derived" / "proof_artifact_index.jsonl",
                [
                    {
                        "engagement": "test-eng",
                        "submission_title": "Re-entrancy in vault withdraw",
                        "candidate_proof_path": "poc/test.go",
                        "promotion_ready": True,
                        "promotion_review_status": "approved",
                        "attack_class": "reentrancy",
                    }
                ],
            )
            packet = build_join(repo_root=repo_root, workspace_path=None, attack_class=None, bug_class=None)
        proof_rows = [r for r in packet["rows"] if r["evidence_scope"] == "proof"]
        self.assertGreater(len(proof_rows), 0, "Expected at least one proof row")
        self.assertEqual(proof_rows[0]["source"], "proof_artifact_index.jsonl")

    # ------------------------------------------------------------------
    # Test 3: evidence_scope=OOS from outcomes.jsonl
    # ------------------------------------------------------------------

    def test_03_evidence_scope_oos_from_outcomes(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = self._make_repo(Path(td))
            self._write_jsonl(
                repo_root / "reference" / "outcomes.jsonl",
                [
                    {
                        "finding_id": "OOS-001",
                        "title": "Token transfer OOS",
                        "severity": "High",
                        "outcome": "oos",
                        "workspace": "test",
                        "date": "2026-05-01",
                    }
                ],
            )
            packet = build_join(repo_root=repo_root, workspace_path=None, attack_class=None, bug_class=None)
        oos_rows = [r for r in packet["rows"] if r["evidence_scope"] == "OOS"]
        self.assertGreater(len(oos_rows), 0)
        self.assertEqual(oos_rows[0]["finding_id"], "OOS-001")

    # ------------------------------------------------------------------
    # Test 4: evidence_scope=dupe from outcomes.jsonl
    # ------------------------------------------------------------------

    def test_04_evidence_scope_dupe_from_outcomes(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = self._make_repo(Path(td))
            self._write_jsonl(
                repo_root / "reference" / "outcomes.jsonl",
                [
                    {
                        "finding_id": "DUPE-001",
                        "title": "Flash loan dupe",
                        "severity": "Medium",
                        "outcome": "duplicate",
                        "workspace": "test",
                        "date": "2026-05-02",
                    }
                ],
            )
            packet = build_join(repo_root=repo_root, workspace_path=None, attack_class=None, bug_class=None)
        dupe_rows = [r for r in packet["rows"] if r["evidence_scope"] == "dupe"]
        self.assertGreater(len(dupe_rows), 0)
        self.assertEqual(dupe_rows[0]["finding_id"], "DUPE-001")

    # ------------------------------------------------------------------
    # Test 5: evidence_scope=economics from outcomes.jsonl
    # ------------------------------------------------------------------

    def test_05_evidence_scope_economics_from_outcomes(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = self._make_repo(Path(td))
            self._write_jsonl(
                repo_root / "reference" / "outcomes.jsonl",
                [
                    {
                        "finding_id": "ECON-001",
                        "title": "Unprofitable attack path",
                        "severity": "Low",
                        "outcome": "unprofitable",
                        "workspace": "test",
                        "date": "2026-05-03",
                    }
                ],
            )
            packet = build_join(repo_root=repo_root, workspace_path=None, attack_class=None, bug_class=None)
        econ_rows = [r for r in packet["rows"] if r["evidence_scope"] == "economics"]
        self.assertGreater(len(econ_rows), 0)
        self.assertEqual(econ_rows[0]["finding_id"], "ECON-001")

    # ------------------------------------------------------------------
    # Test 6: evidence_scope=severity_cap from triager_patterns rejections
    # ------------------------------------------------------------------

    def test_06_evidence_scope_severity_cap_from_triager_pattern(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = self._make_repo(Path(td))
            self._write_json(
                repo_root / "reference" / "triager_patterns.json",
                {
                    "version": "1",
                    "rejections": [
                        {
                            "id": "R6",
                            "name": "Missing proof of impact",
                            "description": "No PoC showing actual impact.",
                            "triager_language": ["no PoC", "unproven"],
                            "severity": "warn",
                            "examples": [],
                            "pre_submit_guard": "require PoC",
                        }
                    ],
                    "acceptances": [],
                    "in_review_risks": [],
                },
            )
            packet = build_join(repo_root=repo_root, workspace_path=None, attack_class=None, bug_class=None)
        cap_rows = [r for r in packet["rows"] if r["evidence_scope"] == "severity_cap"]
        self.assertGreater(len(cap_rows), 0, "Expected a severity_cap row from R6")

    # ------------------------------------------------------------------
    # Test 7: evidence_scope=team_position from outcomes.jsonl
    # ------------------------------------------------------------------

    def test_07_evidence_scope_team_position_from_outcomes(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = self._make_repo(Path(td))
            self._write_jsonl(
                repo_root / "reference" / "outcomes.jsonl",
                [
                    {
                        "finding_id": "TEAM-001",
                        "title": "Acknowledged by design",
                        "severity": "Medium",
                        "outcome": "acknowledged",
                        "workspace": "test",
                        "date": "2026-05-04",
                    }
                ],
            )
            packet = build_join(repo_root=repo_root, workspace_path=None, attack_class=None, bug_class=None)
        tp_rows = [r for r in packet["rows"] if r["evidence_scope"] == "team_position"]
        self.assertGreater(len(tp_rows), 0)
        self.assertEqual(tp_rows[0]["finding_id"], "TEAM-001")

    # ------------------------------------------------------------------
    # Test 8: evidence_scope=context_only for pending outcomes
    # ------------------------------------------------------------------

    def test_08_evidence_scope_context_only_for_pending(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = self._make_repo(Path(td))
            self._write_jsonl(
                repo_root / "reference" / "outcomes.jsonl",
                [
                    {
                        "finding_id": "PEND-001",
                        "title": "Pending finding",
                        "severity": "Medium",
                        "outcome": "pending",
                        "workspace": "test",
                        "date": "2026-05-05",
                    }
                ],
            )
            packet = build_join(repo_root=repo_root, workspace_path=None, attack_class=None, bug_class=None)
        co_rows = [r for r in packet["rows"] if r["evidence_scope"] == "context_only"]
        self.assertGreater(len(co_rows), 0)

    # ------------------------------------------------------------------
    # Test 9: Row cap is respected
    # ------------------------------------------------------------------

    def test_09_row_cap_respected(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = self._make_repo(Path(td))
            # Write 10 outcome rows
            self._write_jsonl(
                repo_root / "reference" / "outcomes.jsonl",
                [
                    {
                        "finding_id": f"ID-{i:03d}",
                        "title": f"Finding {i}",
                        "severity": "Medium",
                        "outcome": "pending",
                        "workspace": "test",
                        "date": "2026-05-05",
                    }
                    for i in range(10)
                ],
            )
            packet = build_join(
                repo_root=repo_root,
                workspace_path=None,
                attack_class=None,
                bug_class=None,
                row_cap=3,
            )
        self.assertEqual(packet["row_cap"], 3)
        self.assertLessEqual(len(packet["rows"]), 3)
        self.assertTrue(packet["capped"])
        self.assertEqual(packet["total_rows_before_cap"], 10)

    # ------------------------------------------------------------------
    # Test 10: Single-source join (only outcomes.jsonl, rest absent)
    # ------------------------------------------------------------------

    def test_10_single_source_join(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = self._make_repo(Path(td))
            self._write_jsonl(
                repo_root / "reference" / "outcomes.jsonl",
                [
                    {
                        "finding_id": "SOLO-001",
                        "title": "Solo source test",
                        "severity": "High",
                        "outcome": "confirmed",
                        "workspace": "test",
                        "date": "2026-05-06",
                    }
                ],
            )
            # Do NOT write triager_patterns.json or proof_artifact_index
            packet = build_join(repo_root=repo_root, workspace_path=None, attack_class=None, bug_class=None)
        self.assertIn("reference/triager_patterns.json", packet["missing_sources"])
        self.assertGreater(len(packet["rows"]), 0)
        self.assertEqual(packet["rows"][0]["finding_id"], "SOLO-001")

    # ------------------------------------------------------------------
    # Test 11: Full join - mandatory schema fields present
    # ------------------------------------------------------------------

    def test_11_full_join_schema_fields(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = self._make_repo(Path(td))
            ws = self._make_workspace(Path(td))

            # outcomes.jsonl
            self._write_jsonl(
                repo_root / "reference" / "outcomes.jsonl",
                [
                    {
                        "finding_id": "F001",
                        "title": "Test finding",
                        "severity": "Critical",
                        "outcome": "paid",
                        "workspace": "test",
                        "date": "2026-05-07",
                    }
                ],
            )

            # triager_patterns.json
            self._write_json(
                repo_root / "reference" / "triager_patterns.json",
                {
                    "version": "1",
                    "rejections": [
                        {
                            "id": "R1",
                            "name": "Event-Only",
                            "description": "desc",
                            "triager_language": [],
                            "severity": "warn",
                            "examples": [],
                            "pre_submit_guard": "",
                        }
                    ],
                    "acceptances": [
                        {
                            "id": "A1",
                            "name": "Confirmed Fund Loss",
                            "description": "confirmed impact",
                            "examples": [],
                            "key_lesson": "PoC required",
                        }
                    ],
                    "in_review_risks": [],
                },
            )

            # proof_artifact_index.jsonl
            self._write_jsonl(
                repo_root / "audit" / "corpus_tags" / "derived" / "proof_artifact_index.jsonl",
                [
                    {
                        "engagement": "test-eng",
                        "submission_title": "Reentrancy PoC",
                        "candidate_proof_path": "poc/test.go",
                        "promotion_ready": True,
                        "promotion_review_status": "approved",
                    }
                ],
            )

            # agent learning_ledger
            self._write_jsonl(
                ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl",
                [
                    {
                        "schema": "auditooor.agent_learning_ledger.v1",
                        "task_id": "t-001",
                        "terminal_kind": "hacker_question",
                        "status": "needs_local_verification",
                        "quarantine": True,
                        "ts": "2026-05-07T10:00:00+00:00",
                    }
                ],
            )

            packet = build_join(
                repo_root=repo_root,
                workspace_path=ws,
                attack_class=None,
                bug_class=None,
            )

        # Required top-level fields
        for field in (
            "schema", "generated_at", "workspace", "filters", "row_cap",
            "total_rows_before_cap", "rows_emitted", "capped",
            "missing_sources", "scope_summary", "rows",
        ):
            self.assertIn(field, packet, f"Missing top-level field: {field}")

        self.assertEqual(packet["schema"], SCHEMA)
        self.assertIsInstance(packet["rows"], list)

        # Each row must have evidence_scope from the canonical vocab
        for row in packet["rows"]:
            self.assertIn("evidence_scope", row)
            self.assertIn(row["evidence_scope"], EVIDENCE_SCOPE_VOCAB)
            self.assertIn("source", row)
            self.assertIn("outcome", row)

    # ------------------------------------------------------------------
    # Test 12: JSON output schema id is correct
    # ------------------------------------------------------------------

    def test_12_json_schema_id(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = self._make_repo(Path(td))
            self._write_jsonl(
                repo_root / "reference" / "outcomes.jsonl",
                [
                    {
                        "finding_id": "SCH-001",
                        "title": "Schema check",
                        "severity": "Low",
                        "outcome": "pending",
                        "workspace": "test",
                        "date": "2026-05-08",
                    }
                ],
            )
            packet = build_join(repo_root=repo_root, workspace_path=None, attack_class=None, bug_class=None)

        self.assertEqual(packet["schema"], "auditooor.hunter_packet_outcome_join.v1")


if __name__ == "__main__":
    unittest.main()
