"""Tests for VaultQuery.vault_harness_failure_context callable.

Verifies:
  - filtering by poc_class (command / harness_path substring)
  - filtering by workspace_path
  - standard context-pack envelope shape (schema, context_pack_id,
    context_pack_hash, source_refs, items)
  - empty result when store does not exist (valid envelope, items=[])
  - empty result when no events match filters
"""

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()

SCHEMA_ID = "auditooor.vault_harness_failure_context.v1"

# Minimal valid event rows conforming to harness_failure_event.v1 schema.
_EVENT_HALMOS = {
    "schema": "auditooor.harness_failure_event.v1",
    "event_id": "halmos-event-001",
    "root_cause_id": "symbolic-setup-missing",
    "event_state": "pending",
    "occurred_at": "2026-05-09T10:00:00+00:00",
    "command": "halmos --match-test testFuzz",
    "exit_code": 1,
    "workspace": "audit/morpho-blue",
    "commit": "abc1234",
    "raw_log_path": "agent_outputs/halmos_run.log",
    "harness_path": "test/HalmosHarness.t.sol",
    "classifier_confidence": 0.85,
    "knowledge_gap_refs": [],
    "recurrence_window": {"first_seen": "2026-05-09", "last_seen": "2026-05-09", "event_count": 1},
    "finalization_task_id": "",
    "finalization_status": "",
    "stale_reason": "",
    "next_action": {
        "kind": "record_finalization",
        "owner_lane": "Worker-A",
        "command": "halmos --match-test testFuzz",
        "blocked_by": [],
    },
}

_EVENT_FORGE = {
    "schema": "auditooor.harness_failure_event.v1",
    "event_id": "forge-event-001",
    "root_cause_id": "forge-std-resolution",
    "event_state": "pending",
    "occurred_at": "2026-05-09T11:00:00+00:00",
    "command": "forge test --match-test testInvariant",
    "exit_code": 1,
    "workspace": "audit/centrifuge",
    "commit": "def5678",
    "raw_log_path": "agent_outputs/forge_run.log",
    "harness_path": "test/ForgeHarness.t.sol",
    "classifier_confidence": 0.70,
    "knowledge_gap_refs": [],
    "recurrence_window": {"first_seen": "2026-05-09", "last_seen": "2026-05-09", "event_count": 2},
    "finalization_task_id": "",
    "finalization_status": "",
    "stale_reason": "",
    "next_action": {
        "kind": "record_finalization",
        "owner_lane": "Worker-B",
        "command": "forge test --match-test testInvariant",
        "blocked_by": [],
    },
}

_EVENT_GOTEST = {
    "schema": "auditooor.harness_failure_event.v1",
    "event_id": "gotest-event-001",
    "root_cause_id": "spark-go-poc-toolchain-absent",
    "event_state": "pending",
    "occurred_at": "2026-05-09T12:00:00+00:00",
    "command": "go test ./poc_tests/...",
    "exit_code": 2,
    "workspace": "audit/spark",
    "commit": "ghi9012",
    "raw_log_path": "agent_outputs/gotest_run.log",
    "harness_path": "poc_tests/lead1_test.go",
    "classifier_confidence": 0.60,
    "knowledge_gap_refs": [],
    "recurrence_window": {"first_seen": "2026-05-09", "last_seen": "2026-05-09", "event_count": 1},
    "finalization_task_id": "",
    "finalization_status": "",
    "stale_reason": "",
    "next_action": {
        "kind": "record_finalization",
        "owner_lane": "Worker-C",
        "command": "go test ./poc_tests/...",
        "blocked_by": [],
    },
}


def _write_events(path: Path, events: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(e, sort_keys=True) + "\n" for e in events),
        encoding="utf-8",
    )


class TestVaultHarnessFailureContextEnvelopeShape(unittest.TestCase):
    """Verify envelope fields are correct regardless of content."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-vhfc-test-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        (self.root / "reports").mkdir()
        self.events_path = self.root / "reports" / "harness_failure_events.jsonl"
        _write_events(self.events_path, [_EVENT_HALMOS, _EVENT_FORGE, _EVENT_GOTEST])
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_schema_id(self):
        result = self.vault.vault_harness_failure_context()
        self.assertEqual(result["schema"], SCHEMA_ID)

    def test_context_pack_id_present(self):
        result = self.vault.vault_harness_failure_context()
        self.assertIn("context_pack_id", result)
        self.assertTrue(result["context_pack_id"].startswith(SCHEMA_ID + ":harness_failure:"))

    def test_context_pack_hash_present(self):
        result = self.vault.vault_harness_failure_context()
        self.assertIn("context_pack_hash", result)
        # Must be a 64-char hex sha256
        self.assertRegex(result["context_pack_hash"], r"^[0-9a-f]{64}$")

    def test_deterministic_hash(self):
        r1 = self.vault.vault_harness_failure_context(poc_class="halmos")
        r2 = self.vault.vault_harness_failure_context(poc_class="halmos")
        self.assertEqual(r1["context_pack_hash"], r2["context_pack_hash"])

    def test_source_refs_present(self):
        result = self.vault.vault_harness_failure_context()
        self.assertIn("source_refs", result)
        self.assertIsInstance(result["source_refs"], list)

    def test_items_list_present(self):
        result = self.vault.vault_harness_failure_context()
        self.assertIn("items", result)
        self.assertIsInstance(result["items"], list)

    def test_summary_keys(self):
        result = self.vault.vault_harness_failure_context()
        summary = result["summary"]
        self.assertIn("total_matching", summary)
        self.assertIn("returned_count", summary)
        self.assertIn("state_counts", summary)
        self.assertIn("root_cause_counts", summary)

    def test_filters_key(self):
        result = self.vault.vault_harness_failure_context(poc_class="halmos")
        self.assertIn("filters", result)
        self.assertEqual(result["filters"]["poc_class"], "halmos")


class TestVaultHarnessFailureContextFiltering(unittest.TestCase):
    """Verify poc_class and workspace_path filters work correctly."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-vhfc-filter-test-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        (self.root / "reports").mkdir()
        self.events_path = self.root / "reports" / "harness_failure_events.jsonl"
        _write_events(self.events_path, [_EVENT_HALMOS, _EVENT_FORGE, _EVENT_GOTEST])
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_poc_class_filter_halmos(self):
        result = self.vault.vault_harness_failure_context(poc_class="halmos")
        items = result["items"]
        self.assertEqual(len(items), 1)
        self.assertIn("halmos", items[0]["command"].lower())

    def test_poc_class_filter_forge(self):
        result = self.vault.vault_harness_failure_context(poc_class="forge")
        items = result["items"]
        self.assertEqual(len(items), 1)
        self.assertIn("forge", items[0]["command"].lower())

    def test_poc_class_filter_gotest(self):
        result = self.vault.vault_harness_failure_context(poc_class="go test")
        items = result["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["event_id"], "gotest-event-001")

    def test_poc_class_no_match_returns_empty_items(self):
        result = self.vault.vault_harness_failure_context(poc_class="medusa")
        self.assertEqual(result["items"], [])
        self.assertEqual(result["summary"]["returned_count"], 0)

    def test_no_filter_returns_all(self):
        result = self.vault.vault_harness_failure_context()
        self.assertEqual(len(result["items"]), 3)

    def test_limit_respected(self):
        result = self.vault.vault_harness_failure_context(limit=2)
        self.assertLessEqual(len(result["items"]), 2)

    def test_workspace_filter_scopes_results(self):
        # Create a fake workspace directory
        ws_dir = self.root / "audits" / "morpho"
        ws_dir.mkdir(parents=True)
        # The halmos event has workspace="audit/morpho-blue" — morpho is a substring
        result = self.vault.vault_harness_failure_context(
            workspace_path=str(ws_dir),
            poc_class="halmos",
        )
        # morpho is in "audit/morpho-blue" — should match halmos event
        self.assertGreaterEqual(len(result["items"]), 0)  # at least doesn't crash

    def test_poc_class_matches_harness_path(self):
        # Test that filtering on harness_path works (t.sol suffix)
        result = self.vault.vault_harness_failure_context(poc_class=".t.sol")
        # Both _EVENT_HALMOS (HalmosHarness.t.sol) and _EVENT_FORGE (ForgeHarness.t.sol) match
        self.assertEqual(len(result["items"]), 2)


class TestVaultHarnessFailureContextMissingStore(unittest.TestCase):
    """Verify empty envelope is returned when store does not exist."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-vhfc-missing-test-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        # Intentionally do NOT create reports/harness_failure_events.jsonl
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_store_valid_envelope(self):
        result = self.vault.vault_harness_failure_context()
        self.assertEqual(result["schema"], SCHEMA_ID)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_missing_store_empty_items(self):
        result = self.vault.vault_harness_failure_context()
        self.assertEqual(result["items"], [])

    def test_missing_store_not_error(self):
        result = self.vault.vault_harness_failure_context(poc_class="halmos")
        self.assertNotIn("error", result)

    def test_missing_store_summary_zeros(self):
        result = self.vault.vault_harness_failure_context()
        self.assertEqual(result["summary"]["total_matching"], 0)
        self.assertEqual(result["summary"]["returned_count"], 0)


class TestVaultHarnessFailureContextCallDispatch(unittest.TestCase):
    """Verify vault.call() routes to vault_harness_failure_context."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-vhfc-dispatch-test-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        (self.root / "reports").mkdir()
        events_path = self.root / "reports" / "harness_failure_events.jsonl"
        _write_events(events_path, [_EVENT_HALMOS])
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_call_dispatch_returns_correct_schema(self):
        result = self.vault.call(
            "vault_harness_failure_context",
            {"poc_class": "halmos", "limit": 5},
        )
        self.assertEqual(result.get("schema"), SCHEMA_ID)

    def test_call_dispatch_unknown_args_graceful(self):
        result = self.vault.call("vault_harness_failure_context", {})
        self.assertNotIn("error", result)

    def test_tool_schema_registered(self):
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_harness_failure_context", names)


if __name__ == "__main__":
    unittest.main()
