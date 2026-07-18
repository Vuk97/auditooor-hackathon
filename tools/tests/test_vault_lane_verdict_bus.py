"""Tests for the ``vault_lane_verdict_bus`` MCP callable.

M1-2 wires the MCP callable against the expected M1-1 CLI contract:

  python3 tools/lane-verdict-bus.py consult --workspace <ws> --limit <n> --json

The CLI may land in a sibling lane, so these tests verify both the wrapper's
fail-soft degraded envelope when the CLI is absent and the command/JSON
contract when the CLI is available.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
SCHEMA = "auditooor.lane_verdict_bus.consult.v1"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_lvb", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


class TestVaultLaneVerdictBus(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="lane-verdict-bus-mcp-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        self.workspace = self.root / "audits" / "demo"
        self.workspace.mkdir(parents=True)
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, REPO_ROOT)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_degraded_when_m1_1_cli_missing(self):
        with mock.patch.object(Path, "is_file", return_value=False):
            result = self.vault.vault_lane_verdict_bus(
                workspace_path=str(self.workspace),
                limit=5,
            )

        self.assertEqual(result["schema"], SCHEMA)
        self.assertTrue(result["degraded"])
        self.assertEqual(result["degraded_reason"], "m1_1_cli_missing")
        self.assertEqual(result["verdicts"], [])
        self.assertEqual(result["verdicts_returned"], 0)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_empty_bus_contract_from_cli(self):
        cli_payload = {
            "schema": SCHEMA,
            "workspace_path": str(self.workspace),
            "verdicts": [],
        }
        completed = subprocess.CompletedProcess(
            args=["lane-verdict-bus"],
            returncode=0,
            stdout=json.dumps(cli_payload),
            stderr="",
        )

        with mock.patch.object(Path, "is_file", return_value=True), \
                mock.patch("subprocess.run", return_value=completed) as run:
            result = self.vault.vault_lane_verdict_bus(
                workspace_path=str(self.workspace),
                limit=3,
            )

        self.assertEqual(result["schema"], SCHEMA)
        self.assertFalse(result["degraded"])
        self.assertEqual(result["verdicts"], [])
        self.assertEqual(result["verdicts_returned"], 0)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        cmd = run.call_args.args[0]
        self.assertIn("consult", cmd)
        self.assertIn("--workspace", cmd)
        self.assertIn(str(self.workspace.resolve()), cmd)
        self.assertIn("--limit", cmd)
        self.assertIn("3", cmd)
        self.assertIn("--json", cmd)

    def test_filters_forward_to_cli(self):
        cli_payload = {
            "schema": SCHEMA,
            "workspace_path": str(self.workspace),
            "verdicts": [
                {"candidate_id": "C-1", "verdict": "DROPPED"},
            ],
        }
        completed = subprocess.CompletedProcess(
            args=["lane-verdict-bus"],
            returncode=0,
            stdout=json.dumps(cli_payload),
            stderr="",
        )

        with mock.patch.object(Path, "is_file", return_value=True), \
                mock.patch("subprocess.run", return_value=completed) as run:
            result = self.vault.vault_lane_verdict_bus(
                workspace_path=str(self.workspace),
                limit=10,
                candidate_id="C-1",
                attack_class="precision-loss",
                filter={"verdict": "DROPPED"},
            )

        self.assertEqual(result["verdicts_returned"], 1)
        self.assertEqual(result["filters_applied"], ["verdict=DROPPED"])
        cmd = run.call_args.args[0]
        self.assertIn("--candidate-id", cmd)
        self.assertIn("C-1", cmd)
        self.assertIn("--attack-class", cmd)
        self.assertIn("precision-loss", cmd)
        self.assertIn("--filter", cmd)
        self.assertIn("verdict=DROPPED", cmd)

    def test_nonzero_cli_degrades_with_empty_verdicts(self):
        completed = subprocess.CompletedProcess(
            args=["lane-verdict-bus"],
            returncode=2,
            stdout="",
            stderr="bad args",
        )

        with mock.patch.object(Path, "is_file", return_value=True), \
                mock.patch("subprocess.run", return_value=completed):
            result = self.vault.vault_lane_verdict_bus(
                workspace_path=str(self.workspace),
            )

        self.assertTrue(result["degraded"])
        self.assertEqual(result["degraded_reason"], "m1_1_cli_nonzero")
        self.assertEqual(result["verdicts"], [])

    def test_dispatch_and_schema_registration(self):
        names = [tool["name"] for tool in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_lane_verdict_bus", names)

        result = self.vault._dispatch(
            "vault_lane_verdict_bus",
            {"workspace_path": str(self.workspace)},
        )
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(result["verdicts"], [])

    def test_cli_dispatch_exits_zero_on_empty_bus(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--repo-root",
                str(REPO_ROOT),
                "--vault-dir",
                str(self.vault_dir),
                "--call",
                "vault_lane_verdict_bus",
                "--args",
                json.dumps({"workspace_path": str(self.workspace), "limit": 2}),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["schema"], SCHEMA)
        self.assertEqual(parsed["verdicts"], [])
        self.assertFalse(parsed["degraded"])

    def test_live_cli_records_are_mirrored_into_verdicts(self):
        append_proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "lane-verdict-bus.py"),
                "append",
                "--workspace",
                str(self.workspace),
                "--lane-id",
                "M1-1",
                "--candidate-id",
                "cand-1",
                "--attack-class",
                "rounding",
                "--verdict",
                "DROPPED",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(append_proc.returncode, 0, append_proc.stderr[:300])

        result = self.vault.vault_lane_verdict_bus(
            workspace_path=str(self.workspace),
            limit=5,
        )

        self.assertFalse(result["degraded"])
        self.assertEqual(result["verdicts_returned"], 1)
        self.assertEqual(len(result["verdicts"]), 1)
        self.assertEqual(result["verdicts"][0]["candidate_id"], "cand-1")
        self.assertEqual(result["verdicts"][0]["verdict"], "DROPPED")
        self.assertEqual(result["records"][0]["candidate_id"], "cand-1")


if __name__ == "__main__":
    unittest.main()
