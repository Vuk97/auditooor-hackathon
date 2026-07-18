"""Unit tests for VaultQuery.vault_provider_capacity.

Mirrors the test structure of test_vault_triager_pattern_context.py.
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

PROVIDER_CAPACITY_SCHEMA: str = _vault_mcp.PROVIDER_CAPACITY_SCHEMA
TOOL_SCHEMAS: list = _vault_mcp.TOOL_SCHEMAS
VaultQuery = _vault_mcp.VaultQuery
handle_request = _vault_mcp.handle_request

# ── helpers ───────────────────────────────────────────────────────────────────

_BUDGET_LOG_ROWS = [
    {"provider": "kimi", "success": True, "cost_usd": 0.05, "ts": "2026-01-01T00:00:00Z"},
    {"provider": "kimi", "success": True, "cost_usd": 0.10, "ts": "2026-01-01T01:00:00Z"},
    {"provider": "minimax", "success": False, "cost_usd": 0.02, "ts": "2026-01-01T02:00:00Z"},
    {"provider": "minimax", "success": True, "cost_usd": 0.03, "ts": "2026-01-01T03:00:00Z"},
    {"provider": "minimax", "success": True, "cost_usd": 0.04, "ts": "2026-01-01T04:00:00Z"},
]

_BUDGET_CONFIG = {
    "providers": {
        "kimi": {"daily_budget_usd": 10.0, "max_calls": 100},
        "minimax": {"daily_budget_usd": 20.0, "max_calls": 200},
    }
}

_CALIB_LOG_ROWS = [
    {"provider": "kimi", "verdict": "TRUE", "task_type": "source-extraction"},
    {"provider": "kimi", "verdict": "TRUE", "task_type": "source-extraction"},
    {"provider": "kimi", "verdict": "FALSE", "task_type": "source-extraction"},
    {"provider": "minimax", "verdict": "TRUE", "task_type": "adversarial-kill"},
]


def _make_vault(tmp_root: Path) -> "VaultQuery":
    vault_dir = tmp_root / "obsidian-vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    return VaultQuery(vault_dir=vault_dir, repo_root=tmp_root)


def _write_calibration_dir(root: Path, *, budget_log: bool = True, budget_cfg: bool = False, calib_log: bool = False) -> None:
    calib_dir = root / "tools" / "calibration"
    calib_dir.mkdir(parents=True, exist_ok=True)
    if budget_log:
        log_path = calib_dir / "llm_budget_log.jsonl"
        log_path.write_text(
            "\n".join(json.dumps(r) for r in _BUDGET_LOG_ROWS) + "\n",
            encoding="utf-8",
        )
    if budget_cfg:
        cfg_path = calib_dir / "llm_budget.json"
        cfg_path.write_text(json.dumps(_BUDGET_CONFIG), encoding="utf-8")
    if calib_log:
        cal_path = calib_dir / "llm_calibration_log.jsonl"
        cal_path.write_text(
            "\n".join(json.dumps(r) for r in _CALIB_LOG_ROWS) + "\n",
            encoding="utf-8",
        )


# ── test classes ──────────────────────────────────────────────────────────────


class TestProviderCapacitySchemaConstant(unittest.TestCase):
    """Schema constant must match expected string."""

    def test_schema_constant_value(self) -> None:
        self.assertEqual(
            PROVIDER_CAPACITY_SCHEMA,
            "auditooor.vault_provider_capacity.v1",
        )


class TestProviderCapacityMissingLog(unittest.TestCase):
    """When budget log is absent the callable returns a graceful error envelope."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        self._vault = _make_vault(self._root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_returns_dict(self) -> None:
        result = self._vault.vault_provider_capacity()
        self.assertIsInstance(result, dict)

    def test_schema_field_present(self) -> None:
        result = self._vault.vault_provider_capacity()
        self.assertEqual(result.get("schema"), PROVIDER_CAPACITY_SCHEMA)

    def test_error_field_present(self) -> None:
        result = self._vault.vault_provider_capacity()
        self.assertIn("error", result)

    def test_error_is_no_budget_log(self) -> None:
        result = self._vault.vault_provider_capacity()
        self.assertEqual(result.get("error"), "no-budget-log")


class TestProviderCapacityAllProviders(unittest.TestCase):
    """Default (no provider filter) returns all providers from the log."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        _write_calibration_dir(self._root, budget_log=True)
        self._vault = _make_vault(self._root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_schema_field_present(self) -> None:
        result = self._vault.vault_provider_capacity()
        self.assertEqual(result.get("schema"), PROVIDER_CAPACITY_SCHEMA)

    def test_rows_list_present(self) -> None:
        result = self._vault.vault_provider_capacity()
        self.assertIn("rows", result)
        self.assertIsInstance(result["rows"], list)

    def test_both_providers_present(self) -> None:
        result = self._vault.vault_provider_capacity()
        providers = {r["provider"] for r in result["rows"]}
        self.assertIn("kimi", providers)
        self.assertIn("minimax", providers)

    def test_advisory_only_true(self) -> None:
        result = self._vault.vault_provider_capacity()
        self.assertTrue(result.get("advisory_only"))

    def test_context_pack_id_present(self) -> None:
        result = self._vault.vault_provider_capacity()
        self.assertIn("context_pack_id", result)
        self.assertTrue(result["context_pack_id"].startswith(PROVIDER_CAPACITY_SCHEMA))

    def test_context_pack_hash_present(self) -> None:
        result = self._vault.vault_provider_capacity()
        self.assertIn("context_pack_hash", result)
        self.assertIsInstance(result["context_pack_hash"], str)
        self.assertGreater(len(result["context_pack_hash"]), 0)


class TestProviderCapacityProviderFilter(unittest.TestCase):
    """Provider filter narrows result to a single provider."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        _write_calibration_dir(self._root, budget_log=True)
        self._vault = _make_vault(self._root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_filter_kimi_only(self) -> None:
        result = self._vault.vault_provider_capacity(provider="kimi")
        providers = {r["provider"] for r in result["rows"]}
        self.assertIn("kimi", providers)
        self.assertNotIn("minimax", providers)

    def test_filter_minimax_only(self) -> None:
        result = self._vault.vault_provider_capacity(provider="minimax")
        providers = {r["provider"] for r in result["rows"]}
        self.assertIn("minimax", providers)
        self.assertNotIn("kimi", providers)

    def test_provider_filter_field_reflects_arg(self) -> None:
        result = self._vault.vault_provider_capacity(provider="kimi")
        self.assertEqual(result.get("provider_filter"), "kimi")

    def test_no_filter_sets_all(self) -> None:
        result = self._vault.vault_provider_capacity()
        self.assertEqual(result.get("provider_filter"), "all")


class TestProviderCapacityRowSchema(unittest.TestCase):
    """Each row must contain required schema fields."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        _write_calibration_dir(self._root, budget_log=True, budget_cfg=True, calib_log=True)
        self._vault = _make_vault(self._root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_row_fields_present(self) -> None:
        result = self._vault.vault_provider_capacity()
        for row in result["rows"]:
            self.assertIn("provider", row)
            self.assertIn("active_model", row)
            self.assertIn("model_env_var", row)
            self.assertIn("daily_budget_usd", row)
            self.assertIn("recent_spend_est_usd", row)
            self.assertIn("headroom_pct", row)
            self.assertIn("recent_calibration_tp_rate", row)
            self.assertIn("recommended", row)

    def test_model_registry_present(self) -> None:
        result = self._vault.vault_provider_capacity()
        self.assertIn("model_registry", result)
        self.assertEqual(result["model_registry"]["kimi"]["default_model"], "kimi-for-coding")
        self.assertEqual(result["model_registry"]["minimax"]["default_model"], "MiniMax-M2.7")

    def test_kimi_headroom_computed(self) -> None:
        result = self._vault.vault_provider_capacity(provider="kimi")
        kimi = result["rows"][0]
        # kimi spend = 0.05 + 0.10 = 0.15; daily = 10.0; headroom = (10-0.15)/10*100
        self.assertIsNotNone(kimi["headroom_pct"])
        self.assertGreater(kimi["headroom_pct"], 0)

    def test_kimi_tp_rate_computed(self) -> None:
        result = self._vault.vault_provider_capacity(provider="kimi")
        kimi = result["rows"][0]
        # 2 TRUE / 3 decided = 0.667
        self.assertIsNotNone(kimi["recent_calibration_tp_rate"])
        self.assertAlmostEqual(kimi["recent_calibration_tp_rate"], 0.667, places=2)

    def test_recommended_bool(self) -> None:
        result = self._vault.vault_provider_capacity()
        for row in result["rows"]:
            self.assertIsInstance(row["recommended"], bool)


class TestProviderCapacityLimit(unittest.TestCase):
    """Limit parameter caps recent_rows per provider."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        _write_calibration_dir(self._root, budget_log=True)
        self._vault = _make_vault(self._root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_limit_one_caps_recent_rows(self) -> None:
        result = self._vault.vault_provider_capacity(limit=1)
        for row in result["rows"]:
            self.assertLessEqual(len(row["recent_rows"]), 1)

    def test_limit_two_caps_recent_rows(self) -> None:
        result = self._vault.vault_provider_capacity(limit=2)
        for row in result["rows"]:
            self.assertLessEqual(len(row["recent_rows"]), 2)


class TestProviderCapacityToolsListRegistration(unittest.TestCase):
    """The TOOL_SCHEMAS list must include vault_provider_capacity."""

    def test_tool_registered(self) -> None:
        names = [t["name"] for t in TOOL_SCHEMAS]
        self.assertIn("vault_provider_capacity", names)

    def test_tool_has_description(self) -> None:
        entry = next(
            (t for t in TOOL_SCHEMAS if t["name"] == "vault_provider_capacity"), None
        )
        self.assertIsNotNone(entry)
        self.assertIn("description", entry)
        self.assertGreater(len(entry["description"]), 10)

    def test_tool_input_schema_has_provider(self) -> None:
        entry = next(
            (t for t in TOOL_SCHEMAS if t["name"] == "vault_provider_capacity"), None
        )
        self.assertIsNotNone(entry)
        props = entry.get("inputSchema", {}).get("properties", {})
        self.assertIn("provider", props)

    def test_tool_input_schema_has_limit(self) -> None:
        entry = next(
            (t for t in TOOL_SCHEMAS if t["name"] == "vault_provider_capacity"), None
        )
        self.assertIsNotNone(entry)
        props = entry.get("inputSchema", {}).get("properties", {})
        self.assertIn("limit", props)


class TestProviderCapacityDispatch(unittest.TestCase):
    """The MCP tools/call dispatch must route vault_provider_capacity."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        _write_calibration_dir(self._root, budget_log=True)
        self._vault = _make_vault(self._root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_dispatch_returns_expected_schema(self) -> None:
        request = {
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "vault_provider_capacity",
                "arguments": {"limit": 3},
            },
        }
        response = handle_request(self._vault, request)
        self.assertIn("result", response)
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload.get("schema"), PROVIDER_CAPACITY_SCHEMA)

    def test_dispatch_does_not_return_unknown_tool_error(self) -> None:
        request = {
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "vault_provider_capacity",
                "arguments": {},
            },
        }
        response = handle_request(self._vault, request)
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertNotEqual(payload.get("error"), "unknown_tool")


if __name__ == "__main__":
    unittest.main()
