import contextlib
import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path


FILE_LINE_RE = re.compile(r"\.sol:\d+|\.json")


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "harness-failure-memory.py"
SCHEMA_PATH = REPO_ROOT / "docs" / "schemas" / "harness_failure_root.v1.json"
EVENT_SCHEMA_PATH = REPO_ROOT / "docs" / "schemas" / "harness_failure_event.v1.json"
EVENT_SUMMARY_SCHEMA_PATH = REPO_ROOT / "docs" / "schemas" / "harness_failure_event_summary.v1.json"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


hfm = load_module("harness_failure_memory", MODULE_PATH)


class HarnessFailureMemoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-harness-memory-test-")
        self.root = Path(self.tmp.name)
        for rel, text in {
            "Makefile": "# make\n",
            "docs/evidence.md": "# evidence\n",
            "docs/archive/2026-04/RECON_CHIMERA_REAL_EXECUTION_RESULTS_2026-04-30.md": "# recon results\n",
            "docs/archive/2026-04/RECON_CHIMERA_INTEGRATION_PLAN_2026-04-29.md": "# recon plan\n",
            "tools/guard.py": "# guard\n",
            "tools/chimera-scaffold.py": "# chimera\n",
            "tools/harness-failure-memory.py": "# tool\n",
            "tools/tests/test_chimera_scaffold.py": "# test\n",
        }.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def row(self, **overrides):
        row = {
            "schema": hfm.SCHEMA,
            "root_cause_id": "forge-std-resolution",
            "title": "Forge std resolution failed",
            "status": "watch",
            "severity": "medium",
            "symptom": "Generated harness could not resolve forge-std.",
            "first_seen": "2026-05-04",
            "last_seen": "2026-05-05",
            "occurrence_count": 2,
            "tools_affected": ["tools/guard.py", "forge"],
            "known_fix": "Write deterministic remappings for forge-std.",
            "guard": "Run forge harness self-tests.",
            "counter_example_links": ["docs/evidence.md"],
            "source_paths": ["docs/evidence.md", "tools/guard.py"],
            "last_validated_at": "2026-05-05",
        }
        row.update(overrides)
        return row

    def event(self, **overrides):
        event = {
            "schema": hfm.EVENT_SCHEMA,
            "event_id": "hf-20260505-forge-std-001",
            "root_cause_id": "forge-std-resolution",
            "event_state": "pending",
            "occurred_at": "2026-05-05T12:34:56+00:00",
            "command": "forge test --match-test testHarnessCompiles",
            "exit_code": 1,
            "workspace": "audit/forge-std-workspace",
            "commit": "abcdef1",
            "raw_log_path": "reports/logs/forge-std-resolution.log",
            "harness_path": "test/Harness.t.sol",
            "classifier_confidence": 0.82,
            "knowledge_gap_refs": ["KLBQ-007", "KG-20260505-001"],
            "recurrence_window": {
                "first_seen": "2026-05-04",
                "last_seen": "2026-05-05",
                "event_count": 2,
            },
            "finalization_task_id": "",
            "finalization_status": "",
            "stale_reason": "",
            "next_action": {
                "kind": "record_finalization",
                "owner_lane": "memory recall / harness precision",
                "command": (
                    "python3 tools/task-finalization-ledger.py from-commit "
                    "--gap-id G10-forge-std-resolution --slot-id slot-1"
                ),
                "blocked_by": [],
            },
        }
        event.update(overrides)
        return event

    def test_schema_required_fields_match_tool_contract(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

        self.assertEqual(schema["title"], "Auditooor Harness Failure Root Cause")
        self.assertEqual(schema["properties"]["schema"]["const"], hfm.SCHEMA)
        self.assertEqual(tuple(schema["required"]), hfm.REQUIRED_ROW_FIELDS)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["occurrence_count"]["minimum"], 1)
        self.assertEqual(schema["properties"]["status"]["enum"], ["active", "mitigated", "watch"])
        self.assertEqual(schema["properties"]["severity"]["enum"], ["low", "medium", "high"])

    def test_event_schemas_required_fields_match_tool_contract(self):
        event_schema = json.loads(EVENT_SCHEMA_PATH.read_text(encoding="utf-8"))
        summary_schema = json.loads(EVENT_SUMMARY_SCHEMA_PATH.read_text(encoding="utf-8"))

        self.assertEqual(event_schema["title"], "Auditooor Harness Failure Event")
        self.assertEqual(event_schema["properties"]["schema"]["const"], hfm.EVENT_SCHEMA)
        self.assertEqual(tuple(event_schema["required"]), hfm.REQUIRED_EVENT_FIELDS)
        self.assertFalse(event_schema["additionalProperties"])
        self.assertEqual(event_schema["properties"]["exit_code"]["minimum"], 0)
        self.assertEqual(event_schema["properties"]["classifier_confidence"]["minimum"], 0)
        self.assertEqual(event_schema["properties"]["classifier_confidence"]["maximum"], 1)
        self.assertEqual(set(event_schema["properties"]["event_state"]["enum"]), hfm.EVENT_STATES)
        self.assertEqual(
            set(event_schema["properties"]["next_action"]["properties"]["kind"]["enum"]),
            hfm.NEXT_ACTION_KINDS,
        )
        recurrence = event_schema["properties"]["recurrence_window"]
        self.assertEqual(recurrence["required"], ["first_seen", "last_seen", "event_count"])
        self.assertFalse(recurrence["additionalProperties"])

        self.assertEqual(summary_schema["title"], "Auditooor Harness Failure Event Summary")
        self.assertEqual(summary_schema["properties"]["schema"]["const"], hfm.EVENT_SUMMARY_SCHEMA)
        self.assertFalse(summary_schema["additionalProperties"])
        root_props = summary_schema["properties"]["roots"]["items"]["properties"]
        self.assertEqual(root_props["event_count"]["minimum"], 1)
        self.assertEqual(root_props["max_classifier_confidence"]["minimum"], 0)
        self.assertEqual(root_props["max_classifier_confidence"]["maximum"], 1)

    def test_self_test_backfills_required_root_causes(self):
        rows = hfm.build_rows(REPO_ROOT)
        required = {
            "m14-prompt-shape-regression",
            "fixture-smoke-mode-flag-missing",
            "empty-setup-sol-harness",
            "forge-std-resolution",
            "wirer-diversity-collapse",
            "recon-log-tooling-failure-origin",
            "fork-replay-proof-boundary",
        }

        self.assertTrue(required.issubset({row["root_cause_id"] for row in rows}))
        for row in rows:
            self.assertEqual(hfm.validate_row(row, repo=REPO_ROOT), [])

    EXPECTED_SEMANTIC_MODES = (
        "unlimited-params",
        "self-bounded-handler",
        "silent-revert-actions",
        "harness-internal-accounting",
        "dead-cut-guard",
        "tautological-assert",
        "mock-callpath-vacuity",
        "compile-cascade",
        "prefix-runner-mismatch",
        "equivalent-mutant",
        "medusa-selfdestruct-vm-limit",
        "serving-join",
        "setup-crash-false-kill",
        "stale-sidecar",
        "sentinel-density-inversion",
        "smoke-then-orphan",
        "cluster-credit-masks-per-invariant",
        "auth-degrade-to-skeleton",
        "zero-byte-unit-spec",
        "wrong-cut-oos-target",
        "typed-skip-at-scale",
    )

    def test_seed_roots_carry_all_twenty_semantic_modes(self):
        seeds_by_id = {seed["root_cause_id"]: seed for seed in hfm.SEED_ROOTS}

        # All 20 modes (1-20) plus the 4b refinement = 21 named modes present.
        self.assertEqual(len(self.EXPECTED_SEMANTIC_MODES), 21)
        for mode in self.EXPECTED_SEMANTIC_MODES:
            self.assertIn(mode, seeds_by_id, f"semantic mode {mode} missing from SEED_ROOTS")
            seed = seeds_by_id[mode]
            self.assertTrue(seed["known_fix"].strip(), f"{mode}: known_fix (proven fix) must be non-empty")
            self.assertTrue(
                FILE_LINE_RE.search(seed["symptom"]),
                f"{mode}: symptom must carry a real_example file_line matching .sol:N or .json",
            )

    def test_semantic_mode_accessor_matches_name_set(self):
        accessor_names = tuple(seed["root_cause_id"] for seed in hfm.semantic_mode_seeds())

        self.assertEqual(accessor_names, hfm.SEMANTIC_MODE_NAMES)
        self.assertEqual(set(hfm.SEMANTIC_MODE_NAMES), set(self.EXPECTED_SEMANTIC_MODES))
        # The accessor returns copies, not the live seed dicts.
        copies = hfm.semantic_mode_seeds()
        copies[0]["known_fix"] = "MUTATED"
        self.assertNotEqual(hfm.semantic_mode_seeds()[0]["known_fix"], "MUTATED")

    def test_semantic_mode_seeds_validate_against_strict_schema(self):
        for seed in hfm.semantic_mode_seeds():
            row = hfm.normalize_row({**seed, "last_validated_at": hfm.today()})
            self.assertEqual(
                hfm.validate_row(row, repo=REPO_ROOT),
                [],
                f"semantic seed {seed['root_cause_id']} failed strict validate_row",
            )

    def test_validate_row_rejects_unsafe_refs_and_loose_types(self):
        bad = self.row(
            occurrence_count=True,
            counter_example_links="docs/evidence.md",
            source_paths=["/private/evidence.md", "docs/evidence.md"],
            invented_field="should fail",
        )

        errors = hfm.validate_row(bad, repo=self.root)

        self.assertIn("occurrence_count must be integer", errors)
        self.assertIn("counter_example_links must be list", errors)
        self.assertIn("unexpected fields: invented_field", errors)
        self.assertIn("unsafe or missing source ref: /private/evidence.md", errors)

    def test_event_schema_validates_per_occurrence_memory_and_summary(self):
        event = self.event()
        second = self.event(
            event_id="hf-20260505-forge-std-002",
            occurred_at="2026-05-05T12:45:00+00:00",
            command="make harness-failure-memory-test",
            exit_code=2,
            classifier_confidence=0.91,
            knowledge_gap_refs=["KLBQ-007"],
        )

        self.assertEqual(hfm.validate_event(event, repo=self.root), [])
        summary = hfm.summarize_events([event, second])

        self.assertEqual(summary["schema"], hfm.EVENT_SUMMARY_SCHEMA)
        self.assertEqual(summary["event_count"], 2)
        self.assertEqual(summary["event_state_counts"], {"finalized": 0, "pending": 2, "stale": 0})
        self.assertEqual(summary["root_cause_count"], 1)
        root = summary["roots"][0]
        self.assertEqual(root["root_cause_id"], "forge-std-resolution")
        self.assertEqual(root["event_count"], 2)
        self.assertEqual(root["event_state_counts"], {"finalized": 0, "pending": 2, "stale": 0})
        self.assertEqual(root["first_seen"], "2026-05-04")
        self.assertEqual(root["last_seen"], "2026-05-05")
        self.assertEqual(root["exit_codes"], [1, 2])
        self.assertEqual(root["knowledge_gap_refs"], ["KG-20260505-001", "KLBQ-007"])
        self.assertEqual(root["max_classifier_confidence"], 0.91)
        self.assertEqual(root["pending_event_ids"], ["hf-20260505-forge-std-001", "hf-20260505-forge-std-002"])
        self.assertEqual(root["next_action_kinds"], ["record_finalization"])

    def test_validate_event_rejects_unsafe_refs_and_loose_types(self):
        bad = self.event(
            exit_code=True,
            classifier_confidence=1.25,
            workspace="/private/worktree",
            raw_log_path="../logs/out.txt",
            harness_path="docs/.hidden/Harness.t.sol",
            knowledge_gap_refs=["not a kg"],
            recurrence_window={"first_seen": "2026-05-04", "event_count": 0},
            event_state="finalized",
            finalization_task_id="",
            finalization_status="maybe",
            next_action={"kind": "record_finalization", "owner_lane": "", "command": "TODO", "blocked_by": "x"},
            invented_field="should fail",
        )

        errors = hfm.validate_event(bad, repo=self.root)

        self.assertIn("exit_code must be integer", errors)
        self.assertIn("classifier_confidence must be between 0 and 1", errors)
        self.assertIn("unsafe workspace ref: /private/worktree", errors)
        self.assertIn("unsafe raw_log_path: ../logs/out.txt", errors)
        self.assertIn("unsafe harness_path: docs/.hidden/Harness.t.sol", errors)
        self.assertIn("invalid knowledge_gap_ref: not a kg", errors)
        self.assertIn("recurrence_window missing fields: last_seen", errors)
        self.assertIn("recurrence_window.event_count must be positive integer", errors)
        self.assertIn("finalized events require finalization_task_id", errors)
        self.assertIn("finalization_status must be one of ['blocked', 'deferred', 'failed', 'false_positive', 'landed']", errors)
        self.assertIn("finalized events require next_action.kind=none", errors)
        self.assertIn("next_action.command must be exact, not placeholder prose", errors)
        self.assertIn("next_action.blocked_by must be list of strings", errors)
        self.assertIn("unexpected fields: invented_field", errors)

    def test_event_state_semantics_prevent_ambiguous_completion(self):
        finalized = self.event(
            event_state="finalized",
            finalization_task_id="g10-forge-std-slot-1-landed",
            finalization_status="landed",
            next_action={
                "kind": "none",
                "owner_lane": "memory recall / harness precision",
                "command": "",
                "blocked_by": [],
            },
        )
        pending_with_completion = self.event(finalization_task_id="pretend-finalized")
        stale_without_reason = self.event(
            event_state="stale",
            next_action={
                "kind": "refresh_event_evidence",
                "owner_lane": "memory recall / harness precision",
                "command": "python3 tools/harness-failure-memory.py --validate-events",
                "blocked_by": ["event age exceeds active recurrence window"],
            },
        )

        self.assertEqual(hfm.validate_event(finalized, repo=self.root), [])
        self.assertIn(
            "pending events must not set finalization_task_id, finalization_status, or stale_reason",
            hfm.validate_event(pending_with_completion, repo=self.root),
        )
        self.assertIn("stale events require stale_reason", hfm.validate_event(stale_without_reason, repo=self.root))

    def test_validate_events_can_cross_check_task_finalization_ledger(self):
        events_report = self.root / "reports" / "harness_failure_events.jsonl"
        finalization_ledger = self.root / "reports" / "task_finalization.jsonl"
        events_report.parent.mkdir(parents=True)
        finalized = self.event(
            event_state="finalized",
            finalization_task_id="g10-forge-std-slot-1-landed",
            finalization_status="landed",
            next_action={
                "kind": "none",
                "owner_lane": "memory recall / harness precision",
                "command": "",
                "blocked_by": [],
            },
        )
        events_report.write_text(json.dumps(finalized) + "\n", encoding="utf-8")
        finalization_ledger.write_text(
            json.dumps({"task_id": "g10-forge-std-slot-1-landed", "status": "landed"}) + "\n",
            encoding="utf-8",
        )

        self.assertEqual(
            hfm.validate_event_report_with_finalization(
                events_report,
                repo=self.root,
                finalization_ledger=finalization_ledger,
            ),
            [],
        )

        finalization_ledger.write_text(
            json.dumps({"task_id": "g10-forge-std-slot-1-landed", "status": "failed"}) + "\n",
            encoding="utf-8",
        )

        errors = hfm.validate_event_report_with_finalization(
            events_report,
            repo=self.root,
            finalization_ledger=finalization_ledger,
        )
        self.assertTrue(any("does not match task-finalization ledger status failed" in error for error in errors))

    def test_from_events_ignores_stale_rows_and_requires_live_event(self):
        stale = self.event(
            event_state="stale",
            stale_reason="superseded by a newer finalization attempt",
            next_action={
                "kind": "refresh_event_evidence",
                "owner_lane": "memory recall / harness precision",
                "command": "python3 tools/harness-failure-memory.py --validate-events --events-report reports/harness_failure_events.jsonl",
                "blocked_by": ["superseded event"],
            },
        )

        rows, errors = hfm.materialize_rows_from_events([stale], repo=self.root)

        self.assertEqual(rows, [])
        self.assertEqual(errors, ["event-derived aggregate requires at least one non-stale event row"])

    def test_materialize_rows_from_events_honors_task_finalization_ledger(self):
        finalization_ledger = self.root / "reports" / "task_finalization.jsonl"
        finalization_ledger.parent.mkdir(parents=True)
        finalized = self.event(
            event_state="finalized",
            finalization_task_id="g10-forge-std-slot-1-landed",
            finalization_status="landed",
            next_action={
                "kind": "none",
                "owner_lane": "memory recall / harness precision",
                "command": "",
                "blocked_by": [],
            },
        )

        finalization_ledger.write_text(
            json.dumps({"task_id": "g10-forge-std-slot-1-landed", "status": "landed"}) + "\n",
            encoding="utf-8",
        )
        rows, errors = hfm.materialize_rows_from_events(
            [finalized],
            repo=self.root,
            finalization_ledger=finalization_ledger,
        )
        self.assertEqual(errors, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["root_cause_id"], "forge-std-resolution")

        finalization_ledger.write_text(
            json.dumps({"task_id": "g10-forge-std-slot-1-landed", "status": "failed"}) + "\n",
            encoding="utf-8",
        )
        rows, errors = hfm.materialize_rows_from_events(
            [finalized],
            repo=self.root,
            finalization_ledger=finalization_ledger,
        )
        self.assertEqual(rows, [])
        self.assertTrue(any("does not match task-finalization ledger status failed" in error for error in errors))

    def test_write_projection_outputs_notes_index_and_prunes_stale_generated_note(self):
        notes = self.root / "obsidian-vault" / "harness-failures"
        notes.mkdir(parents=True)
        stale = notes / "stale-root.md"
        stale.write_text(f"schema: {hfm.SCHEMA}\n", encoding="utf-8")
        manual = notes / "manual.md"
        manual.write_text("# manual note\n", encoding="utf-8")
        rows = [hfm.normalize_row(self.row())]

        written = hfm.write_projections(notes, rows)

        self.assertEqual(len(written), 2)
        self.assertFalse(stale.exists())
        self.assertTrue(manual.exists())
        note = notes / "forge-std-resolution.md"
        self.assertTrue(note.is_file())
        text = note.read_text(encoding="utf-8")
        self.assertIn("## Known Fix", text)
        self.assertIn("Write deterministic remappings", text)
        index = (notes / "INDEX.md").read_text(encoding="utf-8")
        self.assertIn("reports/harness_failures.jsonl", index)
        self.assertIn("forge-std-resolution.md", index)

    def test_cli_dry_run_json_writes_nothing(self):
        report = self.root / "reports" / "harness_failures.jsonl"
        vault = self.root / "obsidian-vault"
        out = io.StringIO()

        with contextlib.redirect_stdout(out):
            rc = hfm.main([
                "--repo",
                str(REPO_ROOT),
                "--report",
                str(report),
                "--vault-dir",
                str(vault),
                "--json",
            ])

        self.assertEqual(rc, 0)
        payload = json.loads(out.getvalue())
        self.assertTrue(payload["dry_run"])
        self.assertGreaterEqual(payload["root_cause_count"], 7)
        self.assertFalse(report.exists())
        self.assertFalse((vault / "harness-failures").exists())

    def test_validate_report_rejects_duplicate_root_cause(self):
        report = self.root / "reports" / "harness_failures.jsonl"
        report.parent.mkdir(parents=True)
        row = self.row()
        report.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n", encoding="utf-8")

        errors = hfm.validate_report(report, repo=self.root)

        self.assertTrue(any("duplicate root_cause_id forge-std-resolution" in error for error in errors))

    def test_cli_validate_events_writes_summary(self):
        events_report = self.root / "reports" / "harness_failure_events.jsonl"
        summary_report = self.root / "reports" / "harness_failure_event_summary.json"
        events_report.parent.mkdir(parents=True)
        events_report.write_text(json.dumps(self.event()) + "\n", encoding="utf-8")
        out = io.StringIO()

        with contextlib.redirect_stdout(out):
            rc = hfm.main([
                "--repo",
                str(self.root),
                "--validate-events",
                "--events-report",
                str(events_report),
                "--event-summary",
                str(summary_report),
                "--json",
            ])

        self.assertEqual(rc, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["schema"], hfm.EVENT_SUMMARY_SCHEMA)
        self.assertEqual(payload["event_count"], 1)
        self.assertTrue(summary_report.is_file())
        written = json.loads(summary_report.read_text(encoding="utf-8"))
        self.assertEqual(written["roots"][0]["root_cause_id"], "forge-std-resolution")

    def test_cli_from_events_materializes_aggregate_report_and_notes(self):
        events_report = self.root / "reports" / "harness_failure_events.jsonl"
        report = self.root / "reports" / "harness_failures.jsonl"
        vault = self.root / "obsidian-vault"
        events_report.parent.mkdir(parents=True)
        events_report.write_text(
            json.dumps(self.event()) + "\n"
            + json.dumps(self.event(
                event_id="hf-20260505-forge-std-002",
                occurred_at="2026-05-05T12:45:00+00:00",
                command="make harness-failure-memory-test",
                exit_code=2,
                recurrence_window={
                    "first_seen": "2026-05-03",
                    "last_seen": "2026-05-05",
                    "event_count": 2,
                },
            )) + "\n",
            encoding="utf-8",
        )
        out = io.StringIO()

        with contextlib.redirect_stdout(out):
            rc = hfm.main([
                "--repo",
                str(self.root),
                "--from-events",
                "--events-report",
                str(events_report),
                "--report",
                str(report),
                "--vault-dir",
                str(vault),
                "--write",
                "--json",
            ])

        self.assertEqual(rc, 0)
        payload = json.loads(out.getvalue())
        self.assertFalse(payload["dry_run"])
        self.assertEqual(payload["root_cause_count"], 1)
        self.assertEqual(hfm.validate_report(report, repo=self.root), [])
        rows = hfm.read_jsonl(report)
        self.assertEqual(rows[0]["root_cause_id"], "forge-std-resolution")
        self.assertEqual(rows[0]["occurrence_count"], 2)
        self.assertEqual(rows[0]["first_seen"], "2026-05-03")
        self.assertEqual(rows[0]["last_seen"], "2026-05-05")
        self.assertIn("reports/harness_failure_events.jsonl", rows[0]["source_paths"])
        self.assertTrue((vault / "harness-failures" / "forge-std-resolution.md").is_file())

    def test_cli_from_events_fails_closed_for_unknown_root_metadata(self):
        events_report = self.root / "reports" / "harness_failure_events.jsonl"
        report = self.root / "reports" / "harness_failures.jsonl"
        events_report.parent.mkdir(parents=True)
        events_report.write_text(
            json.dumps(self.event(root_cause_id="new-root-cause")) + "\n",
            encoding="utf-8",
        )
        err = io.StringIO()

        with contextlib.redirect_stderr(err):
            rc = hfm.main([
                "--repo",
                str(self.root),
                "--from-events",
                "--events-report",
                str(events_report),
                "--report",
                str(report),
                "--write",
            ])

        self.assertEqual(rc, 2)
        self.assertIn("unknown root_cause_id new-root-cause", err.getvalue())
        self.assertFalse(report.exists())

    def test_cli_from_events_fails_closed_for_empty_event_report(self):
        events_report = self.root / "reports" / "harness_failure_events.jsonl"
        report = self.root / "reports" / "harness_failures.jsonl"
        events_report.parent.mkdir(parents=True)
        events_report.write_text("", encoding="utf-8")
        err = io.StringIO()

        with contextlib.redirect_stderr(err):
            rc = hfm.main([
                "--repo",
                str(self.root),
                "--from-events",
                "--events-report",
                str(events_report),
                "--report",
                str(report),
                "--write",
            ])

        self.assertEqual(rc, 2)
        self.assertIn("requires at least one event row", err.getvalue())
        self.assertFalse(report.exists())

    def test_cli_from_events_fails_closed_for_finalization_ledger_mismatch(self):
        events_report = self.root / "reports" / "harness_failure_events.jsonl"
        finalization_ledger = self.root / "reports" / "task_finalization.jsonl"
        report = self.root / "reports" / "harness_failures.jsonl"
        events_report.parent.mkdir(parents=True)
        events_report.write_text(
            json.dumps(self.event(
                event_state="finalized",
                finalization_task_id="g10-forge-std-slot-1-landed",
                finalization_status="landed",
                next_action={
                    "kind": "none",
                    "owner_lane": "memory recall / harness precision",
                    "command": "",
                    "blocked_by": [],
                },
            )) + "\n",
            encoding="utf-8",
        )
        finalization_ledger.write_text(
            json.dumps({"task_id": "g10-forge-std-slot-1-landed", "status": "failed"}) + "\n",
            encoding="utf-8",
        )
        err = io.StringIO()

        with contextlib.redirect_stderr(err):
            rc = hfm.main([
                "--repo",
                str(self.root),
                "--from-events",
                "--events-report",
                str(events_report),
                "--task-finalization-ledger",
                str(finalization_ledger),
                "--report",
                str(report),
                "--write",
            ])

        self.assertEqual(rc, 2)
        self.assertIn("does not match task-finalization ledger status failed", err.getvalue())
        self.assertFalse(report.exists())

    def test_cli_from_events_fails_closed_for_missing_event_report(self):
        events_report = self.root / "reports" / "missing_events.jsonl"
        report = self.root / "reports" / "harness_failures.jsonl"
        err = io.StringIO()

        with contextlib.redirect_stderr(err):
            rc = hfm.main([
                "--repo",
                str(self.root),
                "--from-events",
                "--events-report",
                str(events_report),
                "--report",
                str(report),
                "--write",
            ])

        self.assertEqual(rc, 1)
        self.assertIn("event report missing", err.getvalue())
        self.assertFalse(report.exists())


if __name__ == "__main__":
    unittest.main()
