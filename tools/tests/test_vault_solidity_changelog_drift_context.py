from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
FIXTURE = (
    REPO_ROOT
    / "tools"
    / "tests"
    / "fixtures"
    / "changelog_source_drift_miner"
    / "mezo_stale_tail"
)
EXPECTED_SCHEMA = "auditooor.vault_solidity_changelog_drift_context.v1"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_solidity_changelog_drift_context",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class VaultSolidityChangelogDriftContextTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-solidity-drift-")
        self.base = Path(self.tmp.name)
        self.vault_dir = self.base / "vault"
        self.repo = REPO_ROOT
        self.ws = self.base / "workspace"
        self.vault_dir.mkdir()
        shutil.copytree(FIXTURE, self.ws)
        self.vault_mcp = _load_vault_mcp()
        self.vault = self.vault_mcp.VaultQuery(self.vault_dir, repo_root=self.repo)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_returns_bounded_exposed_changelog_drift_context(self) -> None:
        result = self.vault.vault_solidity_changelog_drift_context(
            workspace_path=str(self.ws),
            limit=3,
        )

        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertEqual(result["kind"], "solidity_changelog_drift_context")
        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertTrue(result["advisory_only"])
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(result["promotion_allowed"])
        self.assertEqual(result["summary"]["exposed_call_site_count"], 1)
        self.assertEqual(result["ranked_exposed_call_sites"][0]["function"], "_requireNoUnderCollateralizedTroves")
        self.assertEqual(result["ranked_exposed_call_sites"][0]["verdict"], "consumer-NOT-updated-EXPOSED")
        self.assertTrue(result["context_pack_id"].startswith(EXPECTED_SCHEMA))
        self.assertTrue(result["privacy_guards"]["workspace_relative_refs_only"])
        self.assertTrue(result["privacy_guards"]["raw_source_bodies_not_returned"])

        payload = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(self.base), payload)
        self.assertNotIn("/Users/", payload)
        self.assertIn("StabilityPool.sol", payload)

    def test_missing_workspace_returns_valid_empty_envelope(self) -> None:
        result = self.vault.vault_solidity_changelog_drift_context(
            workspace_path=str(self.base / "missing"),
        )

        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertTrue(result["degraded"])
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(result["summary"]["exposed_call_site_count"], 0)

    def test_callable_is_registered_and_dispatches(self) -> None:
        names = {tool["name"] for tool in self.vault_mcp.TOOL_SCHEMAS}
        self.assertIn("vault_solidity_changelog_drift_context", names)

        result = self.vault.call(
            "vault_solidity_changelog_drift_context",
            {"workspace_path": str(self.ws), "limit": 2},
        )
        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertEqual(result["ranked_exposed_call_sites"][0]["function"], "_requireNoUnderCollateralizedTroves")


if __name__ == "__main__":
    unittest.main()
