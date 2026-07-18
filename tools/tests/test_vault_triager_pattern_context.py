"""Unit tests for VaultQuery.vault_triager_pattern_context.

Mirrors the test structure of test_vault_harness_failure_context.py.
Stdlib-only; no external dependencies required.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

# ── locate repo root and load vault-mcp-server.py (hyphen filename) ──────────
_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT / "tools"))

_spec = importlib.util.spec_from_file_location(
    "vault_mcp_server",
    _REPO_ROOT / "tools" / "vault-mcp-server.py",
)
_vault_mcp = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules[_spec.name] = _vault_mcp  # required so dataclasses resolve __module__
_spec.loader.exec_module(_vault_mcp)  # type: ignore[union-attr]

TRIAGER_PATTERN_CONTEXT_SCHEMA: str = _vault_mcp.TRIAGER_PATTERN_CONTEXT_SCHEMA
TOOL_SCHEMAS: list = _vault_mcp.TOOL_SCHEMAS
VaultQuery = _vault_mcp.VaultQuery
handle_request = _vault_mcp.handle_request

# ── helpers ───────────────────────────────────────────────────────────────────

_SYNTHETIC_YAML = """\
- timestamp: '2026-01-01T00:00:00Z'
  base_rows: 100
  top_new_terms:
  - term: reentrancy
    weight: -0.9500
  - term: oracle
    weight: -0.8000
  - term: legitimate
    weight: 0.7000
- timestamp: '2026-01-02T00:00:00Z'
  base_rows: 110
  top_new_terms:
  - term: reentrancy
    weight: -0.9100
  - term: access control
    weight: -0.6500
- timestamp: '2026-01-03T00:00:00Z'
  base_rows: 120
  source: boost-classifier-from-solodit
  top_new_terms: []
"""

_SYNTHETIC_TRIAGER_PATTERNS = {
    "version": 1,
    "rejections": [
        {
            "id": "R12",
            "name": "Production-Profile PoC Mismatch",
            "severity": "warn",
            "description": "High or Critical storage proof uses MemDB, reflection, or synthetic state seeding.",
            "triager_language": ["real backend", "not memdb", "synthetic state seeding"],
            "triggers": ["MemDB", "reflection"],
            "pre_submit_guard": "Run production-profile preflight before filing.",
            "examples": ["dYdX cantina-202 v2 reflection rejection"],
        },
        {
            "id": "R13",
            "name": "Keeper-Direct Proof For Production-Path Claim",
            "severity": "warn",
            "description": "PoC calls keeper internals instead of FinalizeBlock or Commit.",
            "triager_language": ["FinalizeBlock/Commit", "real block execution path"],
            "triggers": ["keeper-direct"],
            "pre_submit_guard": "Use a protocol-level harness for High/Critical impact.",
            "examples": ["dYdX matching-engine keeper-direct proof risk"],
        },
    ],
    "acceptances": [],
    "in_review_risks": [],
}


def _make_vault(tmp_root: Path) -> "VaultQuery":
    """Create a VaultQuery whose repo_root is tmp_root."""
    vault_dir = tmp_root / "obsidian-vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    return VaultQuery(vault_dir=vault_dir, repo_root=tmp_root)


# ── test classes ──────────────────────────────────────────────────────────────


class TestTriagerPatternContextSchema(unittest.TestCase):
    """Schema constant sanity."""

    def test_schema_constant_value(self) -> None:
        self.assertEqual(
            TRIAGER_PATTERN_CONTEXT_SCHEMA,
            "auditooor.vault_triager_pattern_context.v1",
        )


class TestTriagerPatternContextAbsent(unittest.TestCase):
    """When source file is absent the result must be a valid empty envelope."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        self._vault = _make_vault(self._root)
        self._ws = self._root / "fake_workspace"
        self._ws.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_returns_dict(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        self.assertIsInstance(result, dict)

    def test_schema_field_present(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        self.assertEqual(result["schema"], TRIAGER_PATTERN_CONTEXT_SCHEMA)

    def test_empty_patterns_list(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        self.assertEqual(result["top_rejection_patterns"], [])

    def test_empty_source_files(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        self.assertEqual(result["source_files"], [])

    def test_source_exists_false(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        self.assertFalse(result["source_exists"])

    def test_context_pack_id_present(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        self.assertIn("context_pack_id", result)
        self.assertTrue(result["context_pack_id"].startswith(TRIAGER_PATTERN_CONTEXT_SCHEMA))

    def test_context_pack_hash_present(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        self.assertIn("context_pack_hash", result)
        self.assertIsInstance(result["context_pack_hash"], str)
        self.assertGreater(len(result["context_pack_hash"]), 0)


class TestTriagerPatternContextSynthetic(unittest.TestCase):
    """With a synthetic YAML the parser must aggregate correctly."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        ref_dir = self._root / "reference"
        ref_dir.mkdir(parents=True)
        (ref_dir / "rejection_classifier_history.yaml").write_text(
            _SYNTHETIC_YAML, encoding="utf-8"
        )
        self._vault = _make_vault(self._root)
        self._ws = self._root / "fake_ws"
        self._ws.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_source_exists_true(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        self.assertTrue(result["source_exists"])

    def test_source_files_nonempty(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        self.assertGreater(len(result["source_files"]), 0)

    def test_limit_respected(self) -> None:
        result = self._vault.vault_triager_pattern_context(
            workspace_path=str(self._ws), limit=2
        )
        self.assertLessEqual(len(result["top_rejection_patterns"]), 2)

    def test_limit_two_top_terms(self) -> None:
        """With limit=2 we should get the top-2 most frequent patterns."""
        result = self._vault.vault_triager_pattern_context(
            workspace_path=str(self._ws), limit=2
        )
        patterns = result["top_rejection_patterns"]
        self.assertEqual(len(patterns), 2)
        # 'reentrancy' appears in 2 records; others appear in 1 — must rank first
        self.assertEqual(patterns[0]["pattern"], "reentrancy")
        self.assertEqual(patterns[0]["count"], 2)

    def test_positive_weight_terms_excluded(self) -> None:
        """The positively-weighted term 'legitimate' must NOT appear."""
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        pattern_names = [p["pattern"] for p in result["top_rejection_patterns"]]
        self.assertNotIn("legitimate", pattern_names)

    def test_pattern_class_filter(self) -> None:
        result = self._vault.vault_triager_pattern_context(
            workspace_path=str(self._ws), pattern_class="oracle"
        )
        patterns = result["top_rejection_patterns"]
        self.assertGreater(len(patterns), 0)
        for p in patterns:
            self.assertIn("oracle", p["pattern"].lower())

    def test_pattern_fields_present(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        for p in result["top_rejection_patterns"]:
            self.assertIn("pattern", p)
            self.assertIn("count", p)
            self.assertIn("most_recent_iso", p)
            self.assertIn("representative_reason", p)

    def test_summary_training_records_parsed(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        summary = result["summary"]
        self.assertIn("training_records_parsed", summary)
        self.assertEqual(summary["training_records_parsed"], 3)

    def test_summary_counts_consistent(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        summary = result["summary"]
        self.assertIn("total_terms_aggregated", summary)
        self.assertIn("total_matching", summary)
        self.assertIn("returned_count", summary)
        self.assertLessEqual(summary["returned_count"], summary["total_matching"])


class TestTriagerPatternContextStructuredPatterns(unittest.TestCase):
    """Structured triager_patterns.json rows should be returned via MCP."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        ref_dir = self._root / "reference"
        ref_dir.mkdir(parents=True)
        (ref_dir / "triager_patterns.json").write_text(
            json.dumps(_SYNTHETIC_TRIAGER_PATTERNS),
            encoding="utf-8",
        )
        self._vault = _make_vault(self._root)
        self._ws = self._root / "fake_ws"
        self._ws.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_source_exists_with_structured_source_only(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        self.assertTrue(result["source_exists"])
        self.assertFalse(result["classifier_source_exists"])
        self.assertTrue(result["structured_source_exists"])
        self.assertIn("reference/triager_patterns.json", result["source_files"])

    def test_structured_patterns_returned(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        patterns = result["structured_rejection_patterns"]
        self.assertEqual(len(patterns), 2)
        self.assertEqual(patterns[0]["pattern_id"], "R12")
        self.assertEqual(patterns[0]["pattern_name"], "Production-Profile PoC Mismatch")
        self.assertIn("real backend", patterns[0]["triager_language"])
        self.assertIn("Run production-profile preflight", patterns[0]["pre_submit_guard"])

    def test_pattern_class_filter_matches_structured_language(self) -> None:
        result = self._vault.vault_triager_pattern_context(
            workspace_path=str(self._ws),
            pattern_class="FinalizeBlock",
        )
        patterns = result["structured_rejection_patterns"]
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0]["pattern_id"], "R13")

    def test_structured_summary_counts(self) -> None:
        result = self._vault.vault_triager_pattern_context(workspace_path=str(self._ws))
        summary = result["summary"]
        self.assertEqual(summary["structured_patterns_matching"], 2)
        self.assertEqual(summary["structured_returned_count"], 2)


class TestToolsCallDispatch(unittest.TestCase):
    """The MCP tools/call dispatch must route vault_triager_pattern_context."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        self._vault = _make_vault(self._root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_dispatch_returns_expected_schema(self) -> None:
        request = {
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "vault_triager_pattern_context",
                "arguments": {"workspace_path": str(self._root), "limit": 3},
            },
        }
        response = handle_request(self._vault, request)
        self.assertIn("result", response)
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["schema"], TRIAGER_PATTERN_CONTEXT_SCHEMA)

    def test_dispatch_does_not_return_unknown_tool_error(self) -> None:
        request = {
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "vault_triager_pattern_context",
                "arguments": {},
            },
        }
        response = handle_request(self._vault, request)
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertNotEqual(payload.get("error"), "unknown_tool")


class TestToolsList(unittest.TestCase):
    """The tools/list registration must include vault_triager_pattern_context."""

    def test_tool_registered(self) -> None:
        names = [t["name"] for t in TOOL_SCHEMAS]
        self.assertIn("vault_triager_pattern_context", names)

    def test_tool_has_description(self) -> None:
        entry = next(
            (t for t in TOOL_SCHEMAS if t["name"] == "vault_triager_pattern_context"), None
        )
        self.assertIsNotNone(entry)
        self.assertIn("description", entry)
        self.assertGreater(len(entry["description"]), 10)

    def test_tool_input_schema_has_workspace_path(self) -> None:
        entry = next(
            (t for t in TOOL_SCHEMAS if t["name"] == "vault_triager_pattern_context"), None
        )
        self.assertIsNotNone(entry)
        props = entry.get("inputSchema", {}).get("properties", {})
        self.assertIn("workspace_path", props)

    def test_tools_list_mcp_response(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        try:
            root = Path(tmp.name)
            vault = _make_vault(root)
            response = handle_request(vault, {"id": 1, "method": "tools/list", "params": {}})
            tools = response["result"]["tools"]
            names = [t["name"] for t in tools]
            self.assertIn("vault_triager_pattern_context", names)
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
