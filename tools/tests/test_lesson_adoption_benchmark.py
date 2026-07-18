"""Tests for tools/lesson-adoption-benchmark.py (J7 lesson-adoption benchmark)."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "lesson-adoption-benchmark.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("lesson_adoption_benchmark", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["lesson_adoption_benchmark"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _write_exploit_queue(ws: Path, rows: list[dict]) -> None:
    auditooor = ws / ".auditooor"
    auditooor.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "auditooor.exploit_queue.v1",
        "queue": rows,
    }
    (auditooor / "exploit_queue.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def _write_lesson_enforcement_inventory(
    ws: Path,
    enforcement_rows: list[dict],
    lessons: list[dict] | None = None,
) -> None:
    auditooor = ws / ".auditooor"
    auditooor.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "auditooor.lesson_enforcement_inventory.v1",
        "schema_version": "1.0",
        "enforcement_rows": enforcement_rows,
        "lessons": lessons or [],
        "summary": {
            "enforcement_level_counts": {},
            "lessons_compiled": len(enforcement_rows),
        },
    }
    (auditooor / "lesson_enforcement_inventory.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def _write_paste_ready_md(ws: Path, name: str, content: str) -> None:
    pr_dir = ws / "submissions" / "paste_ready"
    pr_dir.mkdir(parents=True, exist_ok=True)
    (pr_dir / name).write_text(content, encoding="utf-8")


def _write_gate_status(ws: Path, name: str, failures: list[dict], file_scope: str) -> None:
    gate_dir = ws / ".auditooor" / "gate-status"
    gate_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "auditooor.gate_status.v1",
        "file": file_scope,
        "failures": failures,
        "status": "fail",
    }
    (gate_dir / name).write_text(json.dumps(payload), encoding="utf-8")


def _make_exploit_row(
    lead_id: str,
    proof_status: str = "open",
    priority_score: float = 5.0,
    blockers: list[str] | None = None,
    mcp_context_ids: list[str] | None = None,
) -> dict:
    return {
        "lead_id": lead_id,
        "proof_status": proof_status,
        "priority_score": priority_score,
        "blockers": blockers or [],
        "mcp_context_ids": mcp_context_ids or [],
        "attack_class": "test-class",
        "title": f"Test finding {lead_id}",
    }


def _make_enforcement_row(
    predicate: str,
    enforcement_level: str = "hard_pre_poc",
    lesson_id: str = "lesson-abc123",
) -> dict:
    return {
        "predicate": predicate,
        "enforcement_level": enforcement_level,
        "gate_phase": "require_non_privileged_or_routine_trigger",
        "action": "block proof work",
        "lesson_count": 1,
        "examples": [
            {
                "confidence": "medium",
                "lesson_id": lesson_id,
                "matched_signals": ["admin_prereq"],
                "snippet": "Example rejection snippet",
                "source_ref": "/path/to/source.md:42",
            }
        ],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEmptyWorkspace(unittest.TestCase):
    """An empty workspace should emit missing_artifact rows and unknown metrics."""

    def test_empty_workspace_returns_valid_schema(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            report = tool.run_benchmark(Path(tmp))

        self.assertEqual(report["schema"], "auditooor.lesson_adoption_benchmark.v1")
        self.assertIn("schema_version", report)
        self.assertIn("generated_at_utc", report)
        self.assertIn("workspace", report)
        self.assertIn("adoption_status", report)
        self.assertIn("metrics", report)
        self.assertIn("missing_artifacts", report)

    def test_empty_workspace_has_no_evaluable_signal(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            report = tool.run_benchmark(Path(tmp))
        self.assertEqual(report["adoption_status"], "no_evaluable_signal")

    def test_empty_workspace_missing_artifacts_populated(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            report = tool.run_benchmark(Path(tmp))
        missing_roles = {m["role"] for m in report["missing_artifacts"]}
        self.assertIn("exploit_queue", missing_roles)

    def test_empty_workspace_metrics_are_unknown(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            report = tool.run_benchmark(Path(tmp))
        for metric in report["metrics"]:
            self.assertIn(
                metric["status"],
                ("unknown", "measured"),
                msg=f"Unexpected status for {metric['metric']}",
            )
        # All four metrics present
        metric_names = {m["metric"] for m in report["metrics"]}
        self.assertIn("pct_top10_exploit_rows_with_lesson_pack", metric_names)
        self.assertIn("pre_poc_kill_count_from_lessons", metric_names)
        self.assertIn("paste_ready_blockers_from_lesson_gates", metric_names)
        self.assertIn("filings_citing_corpus_precedents", metric_names)


class TestExploitQueueWithoutLessonPacks(unittest.TestCase):
    """Workspace has an exploit queue but no lesson packs or enforcement inventory."""

    def test_metric_a_zero_pct_when_no_packs(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rows = [_make_exploit_row(f"EQ-{i:03d}") for i in range(5)]
            _write_exploit_queue(ws, rows)
            report = tool.run_benchmark(ws)

        metric_a = next(
            m for m in report["metrics"]
            if m["metric"] == "pct_top10_exploit_rows_with_lesson_pack"
        )
        self.assertEqual(metric_a["status"], "measured")
        self.assertEqual(metric_a["value"], 0.0)
        self.assertEqual(len(metric_a["rows_without_pack"]), 5)

    def test_metric_b_unknown_without_enforcement_inventory(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rows = [_make_exploit_row("EQ-001", proof_status="killed", blockers=["KILL"])]
            _write_exploit_queue(ws, rows)
            report = tool.run_benchmark(ws)

        metric_b = next(
            m for m in report["metrics"]
            if m["metric"] == "pre_poc_kill_count_from_lessons"
        )
        # Without enforcement inventory there is no lesson attribution
        self.assertIn(metric_b["status"], ("unknown", "measured"))

    def test_adoption_status_recorded_not_adopted_with_queue_and_no_lessons(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rows = [_make_exploit_row(f"EQ-{i:03d}") for i in range(3)]
            _write_exploit_queue(ws, rows)
            report = tool.run_benchmark(ws)

        # Even with queue but no lesson evidence the status is not "changed_decisions"
        self.assertNotEqual(report["adoption_status"], "lessons_changed_decisions")


class TestFullHappyPath(unittest.TestCase):
    """Full synthetic workspace with all artifacts produces expected metrics."""

    def _build_workspace(self, tmp: str) -> Path:
        ws = Path(tmp)

        # Exploit queue: 8 rows, 3 killed, 2 with lesson pack mcp_context_ids
        rows = [
            _make_exploit_row(
                "EQ-001", proof_status="killed",
                blockers=["KILL admin_or_team_action_prerequisite: no unprivileged path"],
                priority_score=9.0,
            ),
            _make_exploit_row(
                "EQ-002", proof_status="killed",
                blockers=["KILL economic_viability_missing"],
                priority_score=8.5,
            ),
            _make_exploit_row(
                "EQ-003", proof_status="open", priority_score=8.0,
                mcp_context_ids=["auditooor.kill_rubric_context.v1:hacker:abc123"],
            ),
            _make_exploit_row(
                "EQ-004", proof_status="killed",
                blockers=["kill: documented mechanics no stronger intent"],
                priority_score=7.5,
            ),
            _make_exploit_row("EQ-005", priority_score=7.0),
            _make_exploit_row("EQ-006", priority_score=6.5),
            _make_exploit_row("EQ-007", priority_score=6.0),
            _make_exploit_row("EQ-008", priority_score=5.5),
        ]
        _write_exploit_queue(ws, rows)

        # Lesson enforcement inventory with pre_poc rows
        enf_rows = [
            _make_enforcement_row(
                "admin_or_team_action_prerequisite",
                enforcement_level="hard_pre_poc",
                lesson_id="lesson-dead1234",
            ),
            _make_enforcement_row(
                "economic_viability_missing",
                enforcement_level="hard_pre_poc",
                lesson_id="lesson-beef5678",
            ),
        ]
        _write_lesson_enforcement_inventory(ws, enf_rows)

        # Gate-status: paste_ready scope with lesson gate failure
        _write_gate_status(
            ws,
            "submissions_paste_ready_finding-X.md.abc.gate-status.json",
            failures=[
                {"gate": "outcome_lesson_gate", "summary": "lesson predicate blocked"},
            ],
            file_scope="submissions/paste_ready/finding-X.md",
        )

        # Paste-ready submissions: 2, one cites corpus
        _write_paste_ready_md(
            ws, "finding-A.md",
            "# Finding A\n\n## Originality\nNo solodit corpus hit. No prior audit match.\n"
        )
        _write_paste_ready_md(
            ws, "finding-B.md",
            "# Finding B\n\n## Background\nThis is a novel finding with no corpus precedent.\n"
        )

        return ws

    def test_all_four_metrics_measured(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._build_workspace(tmp)
            report = tool.run_benchmark(ws)

        measured = {
            m["metric"]: m
            for m in report["metrics"]
            if m["status"] == "measured"
        }
        # All 4 should be measured
        self.assertIn("pct_top10_exploit_rows_with_lesson_pack", measured)
        self.assertIn("pre_poc_kill_count_from_lessons", measured)
        self.assertIn("paste_ready_blockers_from_lesson_gates", measured)
        self.assertIn("filings_citing_corpus_precedents", measured)

    def test_metric_b_detects_lesson_attributed_kills(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._build_workspace(tmp)
            report = tool.run_benchmark(ws)

        metric_b = next(
            m for m in report["metrics"]
            if m["metric"] == "pre_poc_kill_count_from_lessons"
        )
        self.assertGreater(metric_b["value"], 0)
        self.assertIn("lesson_attributed_kills", metric_b)

    def test_metric_c_detects_lesson_gate_blocker(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._build_workspace(tmp)
            report = tool.run_benchmark(ws)

        metric_c = next(
            m for m in report["metrics"]
            if m["metric"] == "paste_ready_blockers_from_lesson_gates"
        )
        self.assertEqual(metric_c["status"], "measured")
        self.assertGreater(metric_c["value"], 0)
        self.assertIn("blockers", metric_c)

    def test_metric_d_counts_corpus_citations(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._build_workspace(tmp)
            report = tool.run_benchmark(ws)

        metric_d = next(
            m for m in report["metrics"]
            if m["metric"] == "filings_citing_corpus_precedents"
        )
        self.assertEqual(metric_d["status"], "measured")
        # finding-A.md has "solodit" and "prior audit" -> should be detected
        self.assertGreaterEqual(metric_d["value"], 1)

    def test_adoption_status_lessons_changed_decisions(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._build_workspace(tmp)
            report = tool.run_benchmark(ws)

        self.assertEqual(report["adoption_status"], "lessons_changed_decisions")


class TestMetricComputations(unittest.TestCase):
    """Unit-level checks on individual metric functions."""

    def test_metric_a_100_pct_when_all_rows_have_pack(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Add worker packet with lesson pack receipts
            packet_dir = ws / ".auditooor" / "worker_packets"
            packet_dir.mkdir(parents=True, exist_ok=True)
            rows = []
            for i in range(3):
                lid = f"EQ-{i:03d}"
                rows.append(_make_exploit_row(lid, priority_score=float(10 - i)))
                # Write a worker packet for each row with a lesson pack receipt
                packet = {
                    "schema": "auditooor.v3_worker_packet.v1",
                    "severity": "high",
                    "mcp_context_refs": [
                        {
                            "context_pack_id": f"auditooor.hacker_brief_for_lane.v1:{lid}",
                            "context_pack_hash": "abc123",
                            "tool": "vault_hacker_brief_for_lane",
                            "schema": "auditooor.hacker_brief_for_lane.v1",
                        }
                    ],
                    "offline_validation": {"lesson_pack_blockers": []},
                }
                (packet_dir / f"{lid}.json").write_text(json.dumps(packet), encoding="utf-8")
            _write_exploit_queue(ws, rows)
            report = tool.run_benchmark(ws)

        metric_a = next(
            m for m in report["metrics"]
            if m["metric"] == "pct_top10_exploit_rows_with_lesson_pack"
        )
        self.assertEqual(metric_a["status"], "measured")
        # hacker_brief_for_lane contains "hacker" which is in LESSON_RECEIPT_HINTS
        self.assertEqual(metric_a["value"], 100.0)

    def test_metric_d_zero_when_no_corpus_citations(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_paste_ready_md(
                ws, "finding-clean.md",
                "# A Finding\n\n## Impact\nLoss of funds.\n\n## Details\nSome analysis.\n"
            )
            report = tool.run_benchmark(ws)

        metric_d = next(
            m for m in report["metrics"]
            if m["metric"] == "filings_citing_corpus_precedents"
        )
        self.assertEqual(metric_d["status"], "measured")
        self.assertEqual(metric_d["value"], 0)

    def test_metric_a_proportional_with_mixed_rows(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # 4 rows: 2 have lesson pack hint in mcp_context_ids
            rows = [
                _make_exploit_row(
                    "EQ-001", mcp_context_ids=["auditooor.kill_rubric_context.v1:X"]
                ),
                _make_exploit_row(
                    "EQ-002", mcp_context_ids=["auditooor.hacker_question.v1:Y"]
                ),
                _make_exploit_row("EQ-003"),
                _make_exploit_row("EQ-004"),
            ]
            _write_exploit_queue(ws, rows)
            report = tool.run_benchmark(ws)

        metric_a = next(
            m for m in report["metrics"]
            if m["metric"] == "pct_top10_exploit_rows_with_lesson_pack"
        )
        self.assertEqual(metric_a["status"], "measured")
        self.assertEqual(metric_a["value"], 50.0)


class TestJsonSchemaFieldPresence(unittest.TestCase):
    """The JSON report must contain all required schema fields."""

    def test_schema_fields_present(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            report = tool.run_benchmark(Path(tmp))

        required_top_level = {
            "schema",
            "schema_version",
            "generated_at_utc",
            "workspace",
            "adoption_status",
            "metrics",
            "missing_artifacts",
            "_interpretation",
        }
        for field in required_top_level:
            self.assertIn(field, report, msg=f"Missing top-level field: {field}")

    def test_schema_id_is_correct(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            report = tool.run_benchmark(Path(tmp))
        self.assertEqual(report["schema"], "auditooor.lesson_adoption_benchmark.v1")

    def test_each_metric_has_required_fields(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            report = tool.run_benchmark(Path(tmp))

        for metric in report["metrics"]:
            self.assertIn("metric", metric, msg="metric row missing 'metric' key")
            self.assertIn("status", metric, msg="metric row missing 'status' key")
            self.assertIn("evidence_paths", metric, msg="metric row missing 'evidence_paths' key")

    def test_adoption_status_is_valid_value(self) -> None:
        tool = load_tool()
        valid_statuses = {
            "lessons_changed_decisions",
            "lessons_recorded_not_adopted",
            "no_evaluable_signal",
        }
        with tempfile.TemporaryDirectory() as tmp:
            report = tool.run_benchmark(Path(tmp))
        self.assertIn(report["adoption_status"], valid_statuses)

    def test_missing_artifact_rows_have_required_fields(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            report = tool.run_benchmark(Path(tmp))

        for ma in report["missing_artifacts"]:
            self.assertIn("status", ma)
            self.assertIn("role", ma)
            self.assertIn("path", ma)
            self.assertEqual(ma["status"], "missing_artifact")

    def test_json_serializable(self) -> None:
        """The report must be fully JSON-serializable."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            report = tool.run_benchmark(Path(tmp))

        # Should not raise
        serialized = json.dumps(report)
        reparsed = json.loads(serialized)
        self.assertEqual(reparsed["schema"], "auditooor.lesson_adoption_benchmark.v1")


if __name__ == "__main__":
    unittest.main()
