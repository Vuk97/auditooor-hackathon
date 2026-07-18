#!/usr/bin/env python3
"""Regression coverage for Phase II.6.C semantic-gate MCP exposure."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_semantic_gate", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


class SemanticGateMcpWiringTests(unittest.TestCase):
    def test_vault_semantic_match_verify_is_exposed_as_an_mcp_callable(self) -> None:
        names = {tool["name"] for tool in vault_mcp_server.TOOL_SCHEMAS}
        self.assertIn("vault_semantic_match_verify", names)
        self.assertTrue(
            hasattr(vault_mcp_server.VaultQuery, "vault_semantic_match_verify"),
            "VaultQuery is missing the vault_semantic_match_verify callable",
        )


if __name__ == "__main__":
    unittest.main()
