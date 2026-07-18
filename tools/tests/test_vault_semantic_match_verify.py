#!/usr/bin/env python3
"""Regression coverage for vault_semantic_match_verify dispatch."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_semantic_gate_verify", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


class VaultSemanticMatchVerifyTests(unittest.TestCase):
    def test_call_dispatch_returns_degraded_envelope_for_missing_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing_workspace = Path(td) / "missing-workspace"
            query = vault_mcp_server.VaultQuery(Path(td))

            result = query.call(
                "vault_semantic_match_verify",
                {"workspace_path": str(missing_workspace)},
            )

        self.assertEqual(result["schema"], "auditooor.vault_semantic_match_verify.v1")
        self.assertTrue(result["degraded"])
        self.assertTrue(result["advisory_only"])
        self.assertEqual(result["kind"], "semantic_match_verify")
        self.assertEqual(result["reason"], "workspace_not_found")
        self.assertEqual(result["workspace_path"], str(missing_workspace.resolve()))

    def test_direct_callable_matches_the_same_degraded_shape(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing_workspace = Path(td) / "missing-workspace"
            query = vault_mcp_server.VaultQuery(Path(td))

            result = query.vault_semantic_match_verify(
                workspace_path=str(missing_workspace)
            )

        self.assertEqual(result["schema"], "auditooor.vault_semantic_match_verify.v1")
        self.assertTrue(result["degraded"])
        self.assertEqual(result["kind"], "semantic_match_verify")
        self.assertEqual(result["reason"], "workspace_not_found")


if __name__ == "__main__":
    unittest.main()
