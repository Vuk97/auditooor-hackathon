"""Tests for MCP session-token TOOL_SCHEMAS and docs.

The token callables gate mutating MCP operations. Keep their tools/list schema
and operator-facing docs aligned so Codex/Claude/Kimi/Minimax wrappers know how
to request and verify scoped tokens.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
DOC_PATH = REPO_ROOT / "docs" / "VAULT_MCP_SERVER.md"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _tool_schema(name: str) -> dict:
    for entry in vault_mcp_server.TOOL_SCHEMAS:
        if entry.get("name") == name:
            return entry
    raise AssertionError(f"{name} not found in TOOL_SCHEMAS")


class TestVaultSessionTokenSchemaDoc(unittest.TestCase):
    def test_issue_session_token_schema_documents_inputs_and_ttl(self) -> None:
        entry = _tool_schema("vault_issue_session_token")
        desc = entry["description"].lower()
        for token in ("hmac-signed", "workspace", "ttl", "4h", "24h", "service-account"):
            self.assertIn(token, desc)

        props = entry["inputSchema"]["properties"]
        for name in ("workspace_path", "owner", "scope", "ttl_seconds"):
            self.assertIn(name, props)

        owner_enum = set(props["owner"]["enum"])
        for owner in (
            "claude",
            "codex",
            "kimi",
            "minimax",
            "anthropic-direct",
            "orchestrator",
            "operator",
            "service-account",
        ):
            self.assertIn(owner, owner_enum)

        self.assertEqual(props["scope"]["type"], "array")
        self.assertEqual(props["scope"]["items"]["type"], "string")

    def test_verify_session_token_schema_documents_inputs_and_return_shape(self) -> None:
        entry = _tool_schema("vault_verify_session_token")
        desc = entry["description"].lower()
        for token in ("valid", "error", "payload", "require_scope", "require_workspace"):
            self.assertIn(token, desc)

        props = entry["inputSchema"]["properties"]
        for name in ("token", "require_scope", "require_workspace"):
            self.assertIn(name, props)
        self.assertEqual(entry["inputSchema"]["required"], ["token"])

    def test_vault_mcp_docs_pin_session_token_rows(self) -> None:
        text = DOC_PATH.read_text(encoding="utf-8")
        for token in (
            "vault_issue_session_token",
            "workspace_path",
            "owner",
            "scope[]",
            "ttl_seconds",
            "HMAC-signed MCP session token",
            "Default TTL 4h",
            "24h",
            "vault_verify_session_token",
            "token",
            "require_scope",
            "require_workspace",
            "{valid, error, payload}",
        ):
            self.assertIn(token, text)


if __name__ == "__main__":
    unittest.main()
