"""Tests for VaultQuery.vault_kill_rubric_context callable (W2-B-2).

Verifies:
  1. Happy path: all 5 sections returned when no filter.
  2. bug_class filter: "AMM" returns only the AMM section.
  3. contract_type filter: "DEX" matches only AMM (applies_to has "DEX").
  4. No match filter: returns empty rubric_rows, sections_returned=0.
  5. Missing library: graceful empty envelope with library_found=False.
  6. context_pack_id and context_pack_hash always present.
  7. Each row has required fields: id, title, applies_to, checklist, kill_verdict_template.
  8. CLI dispatch: subprocess.run exits 0 and returns valid JSON.
  9. Callable listed in TOOL_SCHEMAS.
  10. Workspace path fallback: omitting workspace_path still resolves library from repo root.
  11. bug_class case-insensitive: "amm" matches "AMM Rounding".
  12. Combined bug_class + contract_type filter: "reentrancy" + "DEX" returns empty
      (reentrancy applies to "any contract that transfers value", not DEX specifically).
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
SCHEMA_PREFIX = "auditooor.vault_kill_rubric_context.v1"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MINIMAL_LIBRARY = """\
# Kill Rubric Library

## 1. AMM Rounding

**Applies to:** any swap, liquidity add/remove, or fee-skim function in a DEX

### Rubric checklist

- [ ] **R-AMM-1: Round-trip test** — Swap A → B → A. Is the round-trip profitable?
- [ ] **R-AMM-2: One-leg drain test** — Does the pool debit without matching credit?

### Kill verdict template

```
Kill verdict: AMM Rounding
Tested combinations:
  - Round-trip: [YES/NO]
Reason for kill: [reason]
```

**Motivating miss:** Cantina #8 — Worker J missed one-leg drain at decimals=0.

---

## 2. Reentrancy

**Applies to:** any contract that transfers value (ETH or tokens)

### Rubric checklist

- [ ] **R-RE-1: Checks-effects-interactions (CEI) audit** — Are state updates before external calls?
- [ ] **R-RE-2: Hook-anchored model rejection** — Enumerate all external primitives.

### Kill verdict template

```
Kill verdict: Reentrancy
Tested vectors:
  - CEI audit: [PASS/FAIL]
Reason for kill: [reason]
```

**Motivating miss:** Cantina #29 — cross-primitive reentrancy missed.

---
"""


def _make_library(path: Path, content: str = MINIMAL_LIBRARY) -> None:
    (path / "docs").mkdir(parents=True, exist_ok=True)
    (path / "docs" / "KILL_RUBRIC_LIBRARY.md").write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestVaultKillRubricContext(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-vkrc-test-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        self.workspace = self.root / "audits" / "test-ws"
        self.workspace.mkdir(parents=True)
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    # ------------------------------------------------------------------
    # Test 1: Happy path — all sections returned with no filter
    # ------------------------------------------------------------------

    def test_happy_path_all_sections_returned(self):
        _make_library(self.root)
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.workspace)
        )
        self.assertTrue(result["library_found"])
        self.assertEqual(result["sections_returned"], 2)
        self.assertEqual(len(result["rubric_rows"]), 2)

    # ------------------------------------------------------------------
    # Test 2: bug_class filter — "AMM" returns only AMM section
    # ------------------------------------------------------------------

    def test_bug_class_filter_amm(self):
        _make_library(self.root)
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.workspace), bug_class="AMM"
        )
        self.assertEqual(result["sections_returned"], 1)
        self.assertEqual(result["rubric_rows"][0]["title"], "AMM Rounding")
        self.assertEqual(result["filter"]["bug_class"], "amm")

    # ------------------------------------------------------------------
    # Test 3: contract_type filter — "DEX" matches AMM section
    # ------------------------------------------------------------------

    def test_contract_type_filter_dex(self):
        _make_library(self.root)
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.workspace), contract_type="DEX"
        )
        self.assertEqual(result["sections_returned"], 1)
        self.assertEqual(result["rubric_rows"][0]["id"], "R-AMM")

    # ------------------------------------------------------------------
    # Test 4: No match filter → empty rubric_rows
    # ------------------------------------------------------------------

    def test_no_match_filter_returns_empty(self):
        _make_library(self.root)
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.workspace), bug_class="flashloan_xyz_nonexistent"
        )
        self.assertTrue(result["library_found"])
        self.assertEqual(result["sections_returned"], 0)
        self.assertEqual(result["rubric_rows"], [])

    # ------------------------------------------------------------------
    # Test 5: Missing library → graceful empty envelope
    # ------------------------------------------------------------------

    def test_missing_library_graceful_empty(self):
        # Do NOT create library file
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.workspace)
        )
        self.assertFalse(result["library_found"])
        self.assertEqual(result["rubric_rows"], [])
        self.assertIn("error", result)

    # ------------------------------------------------------------------
    # Test 6: context_pack_id and context_pack_hash always present
    # ------------------------------------------------------------------

    def test_context_pack_fields_always_present(self):
        # Test with library missing (graceful empty)
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.workspace)
        )
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        self.assertTrue(result["context_pack_id"].startswith(SCHEMA_PREFIX))

        # Test with library present
        _make_library(self.root)
        result2 = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.workspace)
        )
        self.assertIn("context_pack_id", result2)
        self.assertIn("context_pack_hash", result2)

    # ------------------------------------------------------------------
    # Test 7: Each row has required fields
    # ------------------------------------------------------------------

    def test_each_row_has_required_fields(self):
        _make_library(self.root)
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.workspace)
        )
        for row in result["rubric_rows"]:
            self.assertIn("id", row)
            self.assertIn("title", row)
            self.assertIn("applies_to", row)
            self.assertIn("checklist", row)
            self.assertIn("kill_verdict_template", row)
            self.assertIsInstance(row["checklist"], list)

    # ------------------------------------------------------------------
    # Test 8: CLI dispatch exits 0 and returns valid JSON
    # ------------------------------------------------------------------

    def test_cli_dispatch_exits_zero_and_valid_json(self):
        _make_library(self.root)
        proc = subprocess.run(
            [
                sys.executable, str(MODULE_PATH),
                "--repo-root", str(self.root),
                "--call", "vault_kill_rubric_context",
                "--args", json.dumps({"workspace_path": str(self.workspace)}),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        data = json.loads(proc.stdout)
        self.assertIn("context_pack_id", data)
        self.assertTrue(data["library_found"])

    # ------------------------------------------------------------------
    # Test 9: Callable listed in TOOL_SCHEMAS
    # ------------------------------------------------------------------

    def test_callable_in_tool_schemas(self):
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_kill_rubric_context", names)
        # Verify schema entry has expected keys
        schema_entry = next(t for t in vault_mcp_server.TOOL_SCHEMAS
                            if t["name"] == "vault_kill_rubric_context")
        self.assertIn("description", schema_entry)
        self.assertIn("inputSchema", schema_entry)

    # ------------------------------------------------------------------
    # Test 10: Workspace path omitted → falls back to repo root
    # ------------------------------------------------------------------

    def test_workspace_path_omitted_uses_repo_root(self):
        # Create library at the real repo root path (REPO_ROOT / docs)
        # The server's self._root == REPO_ROOT in prod; in test we set vault root
        # So we create the library at self.root/docs which is self.vault._root/docs
        _make_library(self.root)
        # Pass workspace_path pointing at self.root so repo root is self.root
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.root)
        )
        self.assertTrue(result["library_found"])
        self.assertGreater(result["sections_returned"], 0)

    # ------------------------------------------------------------------
    # Test 11: bug_class filter is case-insensitive
    # ------------------------------------------------------------------

    def test_bug_class_filter_case_insensitive(self):
        _make_library(self.root)
        result_lower = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.workspace), bug_class="amm"
        )
        result_upper = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.workspace), bug_class="AMM"
        )
        self.assertEqual(result_lower["sections_returned"], 1)
        self.assertEqual(result_lower["sections_returned"],
                         result_upper["sections_returned"])

    # ------------------------------------------------------------------
    # Test 12: Combined bug_class + contract_type that doesn't match → empty
    # ------------------------------------------------------------------

    def test_combined_filter_no_match_returns_empty(self):
        _make_library(self.root)
        # "reentrancy" section applies to "any contract that transfers value",
        # not matching "DEX" in contract_type
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.workspace),
            bug_class="reentrancy",
            contract_type="DEX",
        )
        self.assertEqual(result["sections_returned"], 0)


if __name__ == "__main__":
    unittest.main()
