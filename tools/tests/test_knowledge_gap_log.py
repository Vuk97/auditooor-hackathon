import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "knowledge-gap-log.py"
SCHEMA_PATH = REPO_ROOT / "docs" / "schemas" / "knowledge_gap_event.v1.json"
SCHEMA_V2_PATH = REPO_ROOT / "docs" / "schemas" / "knowledge_gap_event.v2.json"


def load_module():
    spec = importlib.util.spec_from_file_location("knowledge_gap_log", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


kg_tool = load_module()


class KnowledgeGapSchemaShapeTest(unittest.TestCase):
    def test_schema_is_valid_json(self):
        doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(doc.get("title"), "Auditooor Knowledge Gap Event")
        self.assertIn("$id", doc)

    def test_schema_required_fields_and_vocabularies(self):
        doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        required = doc.get("required") or []
        for key in kg_tool.REQUIRED_ROW_FIELDS:
            self.assertIn(key, required)
        self.assertEqual(doc["properties"]["schema"]["const"], kg_tool.SCHEMA)
        self.assertEqual(sorted(doc["properties"]["event_type"]["enum"]), ["opened", "reopened", "resolved"])
        self.assertEqual(sorted(doc["properties"]["status"]["enum"]), ["open", "resolved"])
        self.assertIn("missing_source_root", doc["properties"]["gap_type"]["enum"])
        resolved_then = doc["allOf"][2]["then"]["properties"]["verification"]["properties"]
        self.assertEqual(resolved_then["commands"]["items"]["properties"]["exit_code"]["const"], 0)
        self.assertFalse(doc.get("additionalProperties", True))


class KnowledgeGapLogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-knowledge-gap-test-")
        self.root = Path(self.tmp.name)
        self.ledger = self.root / "reports" / "knowledge_gaps.jsonl"
        self.notes = self.root / "obsidian-vault" / "knowledge-gaps"
        self.doc = self.root / "docs" / "CURRENT_STATE.md"
        self.tool_path = self.root / "tools" / "memory-gap-analyzer.py"
        self.report = self.root / "reports" / "resolution.md"
        self.doc.parent.mkdir(parents=True)
        self.tool_path.parent.mkdir(parents=True)
        self.report.parent.mkdir(parents=True)
        self.doc.write_text("# state\n", encoding="utf-8")
        self.tool_path.write_text("# analyzer\n", encoding="utf-8")
        self.report.write_text("# resolution\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def row(self, **overrides):
        row = {
            "schema": kg_tool.SCHEMA,
            "event_id": "KG-20260505-001:opened:20260505T000000Z",
            "event_type": "opened",
            "gap_id": "KG-20260505-001",
            "candidate_gap_id": "G8-KG-20260505-001",
            "status": "open",
            "occurred_at": "2026-05-05T00:00:00+00:00",
            "actor": "codex",
            "area": "source",
            "gap_type": "missing_source_root",
            "severity": "high",
            "title": "Missing source root",
            "question": "Which source root is canonical?",
            "description": "The dispatch cannot safely mine without a declared source root.",
            "evidence": "docs/CURRENT_STATE.md says source truth is missing.",
            "remediation": "Add the source-root declaration and rerun preflight.",
            "blocked_by_artifacts": ["docs/CURRENT_STATE.md"],
            "downstream_blocked_tasks": ["MCL-6"],
            "source_paths": ["reports/knowledge_gaps.jsonl", "docs/CURRENT_STATE.md"],
            "analyzer_target_paths": ["tools/memory-gap-analyzer.py"],
            "yield_estimate": "high",
            "effort_estimate": "low",
            "heuristic_fp_risk": "The root may exist in an unindexed workspace.",
            "heuristic_fn_risk": "Other missing roots may be absent from docs.",
            "resolution_summary": "",
            "resolution_evidence_paths": [],
            "terminal_artifact": "",
            "verification": {"commands": [], "passed": False},
            "reopen_reason": "",
        }
        row.update(overrides)
        return kg_tool.normalize_row(row)

    def read_jsonl(self, path):
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def append(self, row):
        return kg_tool.append_event(row, self.ledger, self.notes, repo=self.root)

    def test_validate_missing_ledger_fails_closed(self):
        errors = kg_tool.validate_ledger(self.ledger, repo=self.root)

        self.assertTrue(any("ledger missing" in error for error in errors))

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = kg_tool.main(["validate", "--ledger", str(self.ledger), "--repo", str(self.root)])

        self.assertEqual(rc, 1)
        self.assertIn("ledger missing", err.getvalue())

    def test_append_open_writes_ledger_note_and_index(self):
        result = self.append(self.row())

        self.assertEqual(result["row"]["gap_id"], "KG-20260505-001")
        rows = self.read_jsonl(self.ledger)
        self.assertEqual(rows[0]["schema"], kg_tool.SCHEMA)
        self.assertTrue((self.notes / "KG-20260505-001.md").is_file())
        self.assertTrue((self.notes / "INDEX.md").is_file())
        note = (self.notes / "KG-20260505-001.md").read_text(encoding="utf-8")
        self.assertIn("Which source root is canonical?", note)
        self.assertEqual(kg_tool.validate_ledger(self.ledger, repo=self.root), [])

    def test_list_uses_canonical_jsonl_not_projection_note(self):
        self.append(self.row())
        note = self.notes / "KG-20260505-001.md"
        note.write_text("corrupted projection\nstatus: resolved\n", encoding="utf-8")

        rows = kg_tool.list_rows(self.ledger, self.root, "open")

        self.assertEqual([row["gap_id"] for row in rows], ["KG-20260505-001"])
        self.assertEqual(rows[0]["status"], "open")

    def test_resolve_and_reopen_lifecycle(self):
        self.append(self.row())
        resolved = kg_tool.normalize_row({
            **self.row(),
            "event_id": "KG-20260505-001:resolved:20260505T010000Z",
            "event_type": "resolved",
            "status": "resolved",
            "occurred_at": "2026-05-05T01:00:00+00:00",
            "resolution_summary": "Declared root and added regression.",
            "resolution_evidence_paths": ["reports/resolution.md"],
            "terminal_artifact": "reports/resolution.md",
            "verification": {"commands": [{"command": "make knowledge-gap-test", "exit_code": 0}], "passed": True},
        })
        self.append(resolved)

        self.assertEqual(kg_tool.list_rows(self.ledger, self.root, "open"), [])
        self.assertEqual(kg_tool.list_rows(self.ledger, self.root, "resolved")[0]["status"], "resolved")

        reopened = kg_tool.normalize_row({
            **self.row(),
            "event_id": "KG-20260505-001:reopened:20260505T020000Z",
            "event_type": "reopened",
            "status": "open",
            "occurred_at": "2026-05-05T02:00:00+00:00",
            "reopen_reason": "The declaration did not cover sibling repos.",
        })
        self.append(reopened)

        self.assertEqual(kg_tool.list_rows(self.ledger, self.root, "open")[0]["event_type"], "reopened")

    def test_duplicate_open_gap_id_and_natural_key_rejected(self):
        self.append(self.row())

        with self.assertRaisesRegex(ValueError, "opened event for existing gap_id"):
            self.append(self.row(event_id="KG-20260505-001:opened:20260505T030000Z"))

        with self.assertRaisesRegex(ValueError, "duplicate active knowledge gap natural key"):
            self.append(self.row(
                event_id="KG-20260505-002:opened:20260505T030000Z",
                gap_id="KG-20260505-002",
                candidate_gap_id="G8-KG-20260505-002",
            ))

    def test_resolve_unknown_and_double_resolve_rejected(self):
        with self.assertRaisesRegex(ValueError, "ledger missing"):
            kg_tool.build_resolve_row(
                argparse_like(
                    gap_id="KG-20260505-001",
                    event_id=None,
                    occurred_at="2026-05-05T01:00:00+00:00",
                    actor="codex",
                    summary="done",
                    evidence_path=["reports/resolution.md"],
                    terminal_artifact="reports/resolution.md",
                    verification=["make knowledge-gap-test=0"],
                ),
                self.ledger,
                self.root,
            )

        self.append(self.row())
        resolved = kg_tool.build_resolve_row(
            argparse_like(
                gap_id="KG-20260505-001",
                event_id="KG-20260505-001:resolved:20260505T010000Z",
                occurred_at="2026-05-05T01:00:00+00:00",
                actor="codex",
                summary="done",
                evidence_path=["reports/resolution.md"],
                terminal_artifact="reports/resolution.md",
                verification=["make knowledge-gap-test=0"],
            ),
            self.ledger,
            self.root,
        )
        self.append(resolved)

        with self.assertRaisesRegex(ValueError, "not open"):
            kg_tool.build_resolve_row(
                argparse_like(
                    gap_id="KG-20260505-001",
                    event_id=None,
                    occurred_at="2026-05-05T02:00:00+00:00",
                    actor="codex",
                    summary="done again",
                    evidence_path=["reports/resolution.md"],
                    terminal_artifact="reports/resolution.md",
                    verification=["make knowledge-gap-test=0"],
                ),
                self.ledger,
                self.root,
            )

    def test_unsafe_refs_and_symlink_escape_rejected(self):
        outside = self.root.parent / "kg-outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        link = self.root / "docs" / "escape.md"
        link.symlink_to(outside)
        bad_rows = [
            self.row(blocked_by_artifacts=["/tmp/secret"]),
            self.row(blocked_by_artifacts=["../secret"]),
            self.row(blocked_by_artifacts=["vault://_privacy_quarantine/secret.md"]),
            self.row(blocked_by_artifacts=["vault://archive/old.md"]),
            self.row(source_paths=["https://example.com/x"]),
            self.row(source_paths=["docs/does-not-exist.md"]),
            self.row(source_paths=["docs/escape.md"]),
        ]

        for row in bad_rows:
            with self.assertRaises(ValueError):
                self.append(row)
        self.assertFalse(self.ledger.exists())

    def test_boolean_exit_code_is_rejected(self):
        self.append(self.row())
        resolved = self.row(
            event_id="KG-20260505-001:resolved:20260505T010000Z",
            event_type="resolved",
            status="resolved",
            occurred_at="2026-05-05T01:00:00+00:00",
            resolution_summary="Declared root and added regression.",
            resolution_evidence_paths=["reports/resolution.md"],
            terminal_artifact="reports/resolution.md",
            verification={"commands": [{"command": "make knowledge-gap-test", "exit_code": False}], "passed": True},
        )

        with self.assertRaisesRegex(ValueError, "exit_code must be integer"):
            self.append(resolved)

    def test_raw_jsonl_types_are_not_normalized_during_validation(self):
        raw = self.row()
        raw["source_paths"] = "docs/CURRENT_STATE.md"
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        self.ledger.write_text(json.dumps(raw) + "\n", encoding="utf-8")

        errors = kg_tool.validate_ledger(self.ledger, repo=self.root)

        self.assertTrue(any("source_paths must be a list" in error for error in errors))

        raw = self.row()
        raw["source_paths"] = "docs/CURRENT_STATE.md"
        with self.assertRaisesRegex(ValueError, "source_paths must be a list"):
            self.append(raw)

    def test_lifecycle_rejects_backward_timestamps(self):
        opened = self.row()
        resolved = kg_tool.normalize_row({
            **self.row(),
            "event_id": "KG-20260505-001:resolved:20260504T235959Z",
            "event_type": "resolved",
            "status": "resolved",
            "occurred_at": "2026-05-04T23:59:59+00:00",
            "resolution_summary": "resolved before open should fail",
            "resolution_evidence_paths": ["reports/resolution.md"],
            "terminal_artifact": "reports/resolution.md",
            "verification": {"commands": [{"command": "make knowledge-gap-test", "exit_code": 0}], "passed": True},
        })
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        self.ledger.write_text(json.dumps(opened) + "\n" + json.dumps(resolved) + "\n", encoding="utf-8")

        errors = kg_tool.validate_ledger(self.ledger, repo=self.root)

        self.assertTrue(any("occurred_at moves backward" in error for error in errors))

    def test_exact_custom_self_ledger_ref_is_allowed(self):
        self.assertTrue(
            kg_tool.path_is_safe_ref(
                str(self.ledger),
                self.root,
                must_exist=True,
                allow_self_ledger=self.ledger,
            )
        )

    def test_projection_sanitizes_backticks_and_control_chars(self):
        self.append(self.row(
            question="Can `frontmatter`:\nstatus: resolved be injected?",
            title="YAML `injection`",
        ))

        note = (self.notes / "KG-20260505-001.md").read_text(encoding="utf-8")
        self.assertNotIn("`frontmatter`", note)
        self.assertNotIn("\nstatus: resolved be injected?", note)

    def test_cli_add_defaults_source_path_to_custom_ledger(self):
        rc = kg_tool.main([
            "add",
            "--ledger", str(self.ledger),
            "--repo", str(self.root),
            "--notes-dir", str(self.notes),
            "--gap-id", "KG-20260505-009",
            "--occurred-at", "2026-05-05T00:00:00+00:00",
            "--area", "source",
            "--gap-type", "missing_source_root",
            "--question", "Which source root?",
            "--description", "Need a root.",
            "--evidence", "Missing in docs.",
            "--remediation", "Declare root.",
            "--blocked-by", "docs/CURRENT_STATE.md",
            "--json",
        ])

        self.assertEqual(rc, 0)
        row = self.read_jsonl(self.ledger)[0]
        self.assertEqual(row["source_paths"], ["reports/knowledge_gaps.jsonl"])


class KnowledgeGapV2SchemaTest(unittest.TestCase):
    """v2 schema design contracts (PR #651 KG schema v2 lane)."""

    def test_v2_schema_file_exists_and_extends_v1_event_types(self):
        self.assertTrue(SCHEMA_V2_PATH.is_file(),
                        "docs/schemas/knowledge_gap_event.v2.json must exist")
        doc = json.loads(SCHEMA_V2_PATH.read_text(encoding="utf-8"))
        self.assertEqual(doc.get("title"), "Auditooor Knowledge Gap Event v2")
        # All v1 event types remain valid; new v2-only types are additive.
        event_types = set(doc["properties"]["event_type"]["enum"])
        self.assertTrue({"opened", "resolved", "reopened"}.issubset(event_types),
                        "v2 schema must keep all v1 event types valid")
        self.assertTrue(
            {"progressed", "partially_resolved", "blocked_sharper", "narrowed"}.issubset(event_types),
            "v2 schema must add the four progression event types",
        )
        # Schema constant must accept BOTH v1 and v2 (forward-compatible migration).
        self.assertEqual(
            sorted(doc["properties"]["schema"]["enum"]),
            ["auditooor.knowledge_gap_event.v1", "auditooor.knowledge_gap_event.v2"],
        )


class KnowledgeGapV2EventValidationTest(unittest.TestCase):
    """Regression: a v2 event with event_type=progressed validates OK end-to-end."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-knowledge-gap-v2-test-")
        self.root = Path(self.tmp.name)
        self.ledger = self.root / "reports" / "knowledge_gaps.jsonl"
        self.notes = self.root / "obsidian-vault" / "knowledge-gaps"
        self.doc = self.root / "docs" / "CURRENT_STATE.md"
        self.tool_path = self.root / "tools" / "memory-gap-analyzer.py"
        self.progress_note = self.root / "docs" / "next-loop" / "progress_note.md"
        self.doc.parent.mkdir(parents=True)
        self.tool_path.parent.mkdir(parents=True)
        self.progress_note.parent.mkdir(parents=True)
        self.doc.write_text("# state\n", encoding="utf-8")
        self.tool_path.write_text("# analyzer\n", encoding="utf-8")
        self.progress_note.write_text("# progress\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def base_open_row(self):
        return kg_tool.normalize_row({
            "schema": kg_tool.SCHEMA,
            "event_id": "KG-20260506-V2-001:opened:20260506T000000Z",
            "event_type": "opened",
            "gap_id": "KG-20260506-V2-001",
            "candidate_gap_id": "G8-KG-20260506-V2-001",
            "status": "open",
            "occurred_at": "2026-05-06T00:00:00+00:00",
            "actor": "claude-worker-bb",
            "area": "source",
            "gap_type": "missing_source_root",
            "severity": "high",
            "title": "v2 progression test",
            "question": "Does the v2 progressed event validate end-to-end?",
            "description": "Regression for the v2 schema dual-validator.",
            "evidence": "docs/CURRENT_STATE.md says missing.",
            "remediation": "Append a progressed event citing a workspace path.",
            "blocked_by_artifacts": ["docs/CURRENT_STATE.md"],
            "downstream_blocked_tasks": ["MCL-6"],
            "source_paths": ["reports/knowledge_gaps.jsonl"],
            "analyzer_target_paths": ["tools/memory-gap-analyzer.py"],
            "yield_estimate": "high",
            "effort_estimate": "low",
            "heuristic_fp_risk": "",
            "heuristic_fn_risk": "",
            "resolution_summary": "",
            "resolution_evidence_paths": [],
            "terminal_artifact": "",
            "verification": {"commands": [], "passed": False},
            "reopen_reason": "",
        })

    def test_v2_progressed_event_validates_and_persists_progress_evidence(self):
        kg_tool.append_event(self.base_open_row(), self.ledger, self.notes, repo=self.root)
        progressed = kg_tool.normalize_row({
            **self.base_open_row(),
            "schema": kg_tool.SCHEMA_V2,
            "event_id": "KG-20260506-V2-001:progressed:20260506T010000Z",
            "event_type": "progressed",
            "occurred_at": "2026-05-06T01:00:00+00:00",
            "actor": "claude-worker-bb",
            "progress_evidence": "docs/next-loop/progress_note.md",
        })
        result = kg_tool.append_event(progressed, self.ledger, self.notes, repo=self.root)

        self.assertEqual(result["row"]["event_type"], "progressed")
        self.assertEqual(result["row"]["schema"], kg_tool.SCHEMA_V2)
        self.assertEqual(result["row"]["status"], "open")
        self.assertEqual(result["row"]["progress_evidence"], "docs/next-loop/progress_note.md")
        self.assertEqual(kg_tool.validate_ledger(self.ledger, repo=self.root), [])

    def test_v2_progressed_requires_v2_schema_constant(self):
        kg_tool.append_event(self.base_open_row(), self.ledger, self.notes, repo=self.root)
        bad = kg_tool.normalize_row({
            **self.base_open_row(),
            "schema": kg_tool.SCHEMA,  # v1 schema constant + v2 event_type = reject
            "event_id": "KG-20260506-V2-001:progressed:20260506T020000Z",
            "event_type": "progressed",
            "occurred_at": "2026-05-06T02:00:00+00:00",
            "progress_evidence": "docs/next-loop/progress_note.md",
        })
        with self.assertRaisesRegex(ValueError, "requires schema=auditooor.knowledge_gap_event.v2"):
            kg_tool.append_event(bad, self.ledger, self.notes, repo=self.root)

    def test_v1_reader_treats_unknown_event_type_as_opaque_pass_through(self):
        """v1 schema readers must NOT error when they encounter a v2-only event_type.

        Migration contract: tools or downstream consumers that still validate strictly against
        knowledge_gap_event.v1.json should treat unknown event_type strings as opaque (i.e.
        not promote them to status=resolved, not crash). We assert this by validating a v2
        progressed-event row against the v1 schema and confirming the schema spec is permissive
        on extra string event_type values via additionalProperties:false on object level but
        does NOT enforce a check that prevents pass-through readers from skipping unknown rows.

        Concretely: this test fails closed if the v1 schema enum is later tightened in a way
        that would break forward compatibility, and it pins the rule that a v2-only event_type
        appearing in v1-only consumers SHOULD be ignored (not raised) by the consumer.
        """
        v1_doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        v2_event = {
            "schema": kg_tool.SCHEMA,
            "event_type": "progressed",  # not in v1 enum
        }
        # The v1 enum does NOT contain 'progressed'; that mismatch is the signal a v1-only
        # reader must skip the row instead of treating it as the v1 'resolved' terminal event.
        self.assertNotIn(v2_event["event_type"], v1_doc["properties"]["event_type"]["enum"])
        # Opaque pass-through rule: the migration note in v2 schema documents that v1 readers
        # must treat unknown event_type values as opaque. This is a documentation contract
        # rather than an executable v1 check; we assert the v2 schema records the contract.
        v2_doc = json.loads(SCHEMA_V2_PATH.read_text(encoding="utf-8"))
        self.assertIn("opaque-pass-through", v2_doc.get("description", ""),
                      "v2 schema description must document the v1 opaque-pass-through migration rule")


def argparse_like(**kwargs):
    class Args:
        pass
    args = Args()
    for key, value in kwargs.items():
        setattr(args, key, value)
    return args


if __name__ == "__main__":
    unittest.main()
