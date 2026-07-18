"""Tests for VaultQuery.vault_remember callable (W2-B-4).

Verifies:
  1. Rejection: missing signed_token → accepted=False.
  2. Rejection: invalid/malformed token → accepted=False with token error.
  3. Rejection: valid token but wrong scope (no 'remember') → accepted=False.
  4. Rejection: invalid scope value (not in feedback|project|reference|user) → accepted=False.
  5. Rejection: content missing frontmatter → accepted=False.
  6. Rejection: frontmatter missing 'name' field → accepted=False.
  7. Rejection: frontmatter missing 'description' field → accepted=False.
  8. Happy path: valid token + valid content → accepted=True, memory_path written.
  9. Memory file content matches submitted content.
  10. MEMORY.md index updated with link entry.
  11. Second identical call is idempotent (index not duplicated).
  12. context_pack_id and context_pack_hash present in all responses.
  13. Callable listed in TOOL_SCHEMAS with required fields.
  14. Expired token → accepted=False.
"""

import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
TOKEN_PATH = REPO_ROOT / "tools" / "auditooor_mcp_token.py"
SCHEMA_PREFIX = "auditooor.vault_remember.v1"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module("vault_mcp_server", MODULE_PATH)
mcp_token = load_module("auditooor_mcp_token", TOKEN_PATH)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_CONTENT = """\
---
name: test-feedback-entry
description: Test feedback entry written by vault_remember
type: feedback
---

This is test feedback content written by the vault_remember callable.
"""

CONTENT_NO_FM = "No frontmatter here — just plain text."

CONTENT_MISSING_NAME = """\
---
description: Missing the name field
---
Body text.
"""

CONTENT_MISSING_DESC = """\
---
name: missing-desc-entry
---
Body text.
"""


def _issue_token_for_ws(workspace: Path, scope: list | None = None) -> str:
    """Issue a fresh remember-scoped token for workspace."""
    token, _ = mcp_token.issue_token(
        workspace_path=str(workspace),
        owner="claude",
        scope=scope if scope is not None else ["read", "write", "remember"],
        log=False,
    )
    return token


def _issue_token_no_remember(workspace: Path) -> str:
    """Issue a token with only 'read' scope (no remember)."""
    token, _ = mcp_token.issue_token(
        workspace_path=str(workspace),
        owner="claude",
        scope=["read"],
        log=False,
    )
    return token


def _issue_expired_token(workspace: Path) -> str:
    """Issue a token that is immediately expired (ttl_seconds=0)."""
    # Issue with 1s TTL, then sleep 2s to let it expire
    token, _ = mcp_token.issue_token(
        workspace_path=str(workspace),
        owner="claude",
        scope=["read", "write", "remember"],
        ttl_seconds=1,
        log=False,
    )
    time.sleep(2)
    return token


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestVaultRemember(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-vrem-test-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        self.workspace = self.root / "audits" / "test-ws"
        self.workspace.mkdir(parents=True)
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

        # Override home for memory writes during tests using AUDITOOOR_MCP_SECRET
        # so token validation works deterministically
        os.environ.setdefault("AUDITOOOR_MCP_SECRET", "test-secret-for-unit-tests")

    def tearDown(self):
        self.tmp.cleanup()

    def _memory_dir(self, workspace: Path) -> Path:
        """Compute expected memory directory for a given workspace path."""
        slug = str(workspace.resolve()).replace("/", "-").lstrip("-")
        return Path.home() / ".claude" / "projects" / slug / "memory"

    # ------------------------------------------------------------------
    # Test 1: Missing signed_token → rejected
    # ------------------------------------------------------------------

    def test_missing_token_rejected(self):
        result = self.vault.vault_remember(
            scope="feedback",
            content=VALID_CONTENT,
            signed_token="",
        )
        self.assertFalse(result["accepted"])
        self.assertIn("missing signed_token", result["error"])

    # ------------------------------------------------------------------
    # Test 2: Malformed token → rejected
    # ------------------------------------------------------------------

    def test_malformed_token_rejected(self):
        result = self.vault.vault_remember(
            scope="feedback",
            content=VALID_CONTENT,
            signed_token="notavalidtoken",
        )
        self.assertFalse(result["accepted"])
        self.assertIn("token invalid", result["error"])

    # ------------------------------------------------------------------
    # Test 3: Valid token but 'remember' scope missing → rejected
    # ------------------------------------------------------------------

    def test_token_without_remember_scope_rejected(self):
        token = _issue_token_no_remember(self.workspace)
        result = self.vault.vault_remember(
            scope="feedback",
            content=VALID_CONTENT,
            signed_token=token,
        )
        self.assertFalse(result["accepted"])
        self.assertIn("token invalid", result["error"])
        self.assertIn("remember", result["error"])

    # ------------------------------------------------------------------
    # Test 4: Invalid scope value → rejected
    # ------------------------------------------------------------------

    def test_invalid_scope_value_rejected(self):
        token = _issue_token_for_ws(self.workspace)
        result = self.vault.vault_remember(
            scope="not_a_real_scope",
            content=VALID_CONTENT,
            signed_token=token,
        )
        self.assertFalse(result["accepted"])
        self.assertIn("invalid scope", result["error"])

    # ------------------------------------------------------------------
    # Test 5: Content with no frontmatter → rejected
    # ------------------------------------------------------------------

    def test_content_without_frontmatter_rejected(self):
        token = _issue_token_for_ws(self.workspace)
        result = self.vault.vault_remember(
            scope="feedback",
            content=CONTENT_NO_FM,
            signed_token=token,
        )
        self.assertFalse(result["accepted"])
        self.assertIn("frontmatter", result["error"])

    # ------------------------------------------------------------------
    # Test 6: Frontmatter missing 'name' → rejected
    # ------------------------------------------------------------------

    def test_frontmatter_missing_name_rejected(self):
        token = _issue_token_for_ws(self.workspace)
        result = self.vault.vault_remember(
            scope="feedback",
            content=CONTENT_MISSING_NAME,
            signed_token=token,
        )
        self.assertFalse(result["accepted"])
        self.assertIn("name", result["error"])

    # ------------------------------------------------------------------
    # Test 7: Frontmatter missing 'description' → rejected
    # ------------------------------------------------------------------

    def test_frontmatter_missing_description_rejected(self):
        token = _issue_token_for_ws(self.workspace)
        result = self.vault.vault_remember(
            scope="feedback",
            content=CONTENT_MISSING_DESC,
            signed_token=token,
        )
        self.assertFalse(result["accepted"])
        self.assertIn("description", result["error"])

    # ------------------------------------------------------------------
    # Test 8: Happy path — accepted=True, file written
    # ------------------------------------------------------------------

    def test_happy_path_accepted_and_file_written(self):
        token = _issue_token_for_ws(self.workspace)
        result = self.vault.vault_remember(
            scope="feedback",
            content=VALID_CONTENT,
            signed_token=token,
        )
        self.assertTrue(result["accepted"], msg=result.get("error"))
        self.assertTrue(result["schema_validated"])
        self.assertIn("memory_path", result)
        # File must exist
        mem_path = Path(result["memory_path"])
        self.assertTrue(mem_path.exists(), f"memory file missing: {mem_path}")

    # ------------------------------------------------------------------
    # Test 9: Memory file content matches submitted content
    # ------------------------------------------------------------------

    def test_memory_file_content_matches_submitted(self):
        token = _issue_token_for_ws(self.workspace)
        result = self.vault.vault_remember(
            scope="feedback",
            content=VALID_CONTENT,
            signed_token=token,
        )
        self.assertTrue(result["accepted"])
        mem_path = Path(result["memory_path"])
        written = mem_path.read_text(encoding="utf-8")
        self.assertEqual(written, VALID_CONTENT)

    # ------------------------------------------------------------------
    # Test 10: MEMORY.md index updated with link entry
    # ------------------------------------------------------------------

    def test_memory_index_updated(self):
        token = _issue_token_for_ws(self.workspace)
        result = self.vault.vault_remember(
            scope="feedback",
            content=VALID_CONTENT,
            signed_token=token,
        )
        self.assertTrue(result["accepted"])
        # Check MEMORY.md exists and contains link to derived filename
        mem_dir = Path(result["memory_path"]).parent
        index = mem_dir / "MEMORY.md"
        self.assertTrue(index.exists(), "MEMORY.md not created")
        content = index.read_text(encoding="utf-8")
        self.assertIn(result["derived_filename"], content)

    # ------------------------------------------------------------------
    # Test 11: Idempotent — second identical call does not duplicate index entry
    # ------------------------------------------------------------------

    def test_idempotent_second_call_no_duplicate_index(self):
        token = _issue_token_for_ws(self.workspace)
        self.vault.vault_remember(
            scope="feedback",
            content=VALID_CONTENT,
            signed_token=token,
        )
        token2 = _issue_token_for_ws(self.workspace)
        result2 = self.vault.vault_remember(
            scope="feedback",
            content=VALID_CONTENT,
            signed_token=token2,
        )
        self.assertTrue(result2["accepted"])
        # The second call should NOT update index again (already indexed)
        self.assertFalse(result2["memory_index_updated"])
        # Index should only have one entry for this file
        mem_dir = Path(result2["memory_path"]).parent
        index_content = (mem_dir / "MEMORY.md").read_text(encoding="utf-8")
        filename = result2["derived_filename"]
        count = index_content.count(filename)
        self.assertEqual(count, 1, f"Expected 1 occurrence of {filename}, got {count}")

    # ------------------------------------------------------------------
    # Test 12: context_pack_id and context_pack_hash present in all responses
    # ------------------------------------------------------------------

    def test_context_pack_fields_always_present(self):
        # Rejection case
        result_reject = self.vault.vault_remember(
            scope="feedback",
            content=VALID_CONTENT,
            signed_token="INVALID",
        )
        self.assertIn("context_pack_id", result_reject)
        self.assertIn("context_pack_hash", result_reject)
        self.assertTrue(result_reject["context_pack_id"].startswith(SCHEMA_PREFIX))

        # Success case
        token = _issue_token_for_ws(self.workspace)
        result_ok = self.vault.vault_remember(
            scope="feedback",
            content=VALID_CONTENT,
            signed_token=token,
        )
        self.assertIn("context_pack_id", result_ok)
        self.assertIn("context_pack_hash", result_ok)

    # ------------------------------------------------------------------
    # Test 13: Callable listed in TOOL_SCHEMAS with required fields
    # ------------------------------------------------------------------

    def test_callable_in_tool_schemas(self):
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_remember", names)
        entry = next(t for t in vault_mcp_server.TOOL_SCHEMAS
                     if t["name"] == "vault_remember")
        self.assertIn("description", entry)
        self.assertIn("inputSchema", entry)
        required = entry["inputSchema"].get("required", [])
        for field in ("scope", "content", "signed_token"):
            self.assertIn(field, required)

    # ------------------------------------------------------------------
    # Test 14: Expired token → accepted=False
    # ------------------------------------------------------------------

    def test_expired_token_rejected(self):
        token = _issue_expired_token(self.workspace)
        result = self.vault.vault_remember(
            scope="feedback",
            content=VALID_CONTENT,
            signed_token=token,
        )
        self.assertFalse(result["accepted"])
        self.assertIn("token invalid", result["error"])
        self.assertIn("expired", result["error"])


if __name__ == "__main__":
    unittest.main()
