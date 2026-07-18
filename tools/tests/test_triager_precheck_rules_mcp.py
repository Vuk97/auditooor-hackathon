from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

_spec = importlib.util.spec_from_file_location(
    "vault_mcp_server",
    REPO_ROOT / "tools" / "vault-mcp-server.py",
)
_mcp = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
assert _spec.loader is not None
sys.modules[_spec.name] = _mcp
_spec.loader.exec_module(_mcp)


class TriagerPrecheckRulesMcpTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        (self.vault_dir / "INDEX.md").write_text("# Index\n", encoding="utf-8")
        (self.vault_dir / "INDEX_active.md").write_text("# Active\n", encoding="utf-8")
        (self.vault_dir / "NEXT_LOOP.md").write_text("# Next\n", encoding="utf-8")
        self.ws = self.root / "workspace"
        self.ws.mkdir()
        self.draft = self.ws / "draft.md"
        self.draft.write_text(
            "# Event-only accounting finding\n\n"
            "Severity: High\n\n"
            "The issue only affects event emission and has no functional impact.\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_callable_returns_rules_mvp_envelope_without_provider_prediction(self) -> None:
        vault = _mcp.VaultQuery(self.vault_dir, REPO_ROOT)
        packet = vault.call(
            "vault_triager_precheck_rules",
            {"draft_path": str(self.draft), "workspace_path": str(self.ws), "severity": "High"},
        )

        self.assertEqual(packet["schema"], "auditooor.triager_precheck_rules.v1")
        self.assertEqual(packet["mode"], "rules_mvp")
        self.assertIsInstance(packet["provider_status"]["provider"], str)
        self.assertIn(packet["provider_status"]["state"], {"not_configured", "configured", "blocked"})
        self.assertIsNone(packet.get("predicted_verdict"))
        self.assertIn("R1", {row["id"] for row in packet["matched_patterns"]})
        silent = {row["class_key"]: row for row in packet["silent_kill_predictions"]}
        self.assertTrue(silent["event_only"]["matched"])
        self.assertTrue(silent["no_fund_impact"]["matched"])
        self.assertFalse(silent["event_only"]["provider_backed"])
        self.assertEqual(packet["claimed_severity"], "High")
        self.assertIn("reference/triager_patterns.json", packet["source_refs"])

    def test_registered_as_rules_precheck_and_local_simulator(self) -> None:
        names = {tool["name"] for tool in _mcp.TOOL_SCHEMAS}
        self.assertIn("vault_triager_precheck_rules", names)
        self.assertIn("vault_triager_simulate", names)
        schema = next(tool for tool in _mcp.TOOL_SCHEMAS if tool["name"] == "vault_triager_simulate")
        self.assertNotIn("dispatcher", schema["inputSchema"]["properties"])

    def test_simulate_docs_describe_provider_backed_boundary(self) -> None:
        docs = (REPO_ROOT / "docs" / "MCP_LANE_SPECIFIC_CALLABLES.md").read_text(encoding="utf-8")
        section = docs.split("### `vault_triager_simulate`", 1)[1].split("\n### ", 1)[0]

        self.assertIn("provider_backed=true", section)
        self.assertIn("advisory", section)
        self.assertIn("consent/auth", section)
        self.assertIn("provider_status.provider_backed=false", section)

    def test_simulate_wraps_precheck_without_provider_prediction(self) -> None:
        vault = _mcp.VaultQuery(self.vault_dir, REPO_ROOT)
        packet = vault.call(
            "vault_triager_simulate",
            {"draft_path": str(self.draft), "workspace_path": str(self.ws), "severity": "High"},
        )

        self.assertEqual(packet["schema"], "auditooor.vault_triager_simulate.v1")
        self.assertEqual(packet["mode"], "local_rules_simulation")
        self.assertIsInstance(packet["provider_status"]["provider"], str)
        self.assertIn(packet["provider_status"]["state"], {"not_configured", "configured", "blocked"})
        self.assertFalse(packet["provider_status"]["provider_backed"])
        self.assertNotIn("predicted_verdict", packet)
        self.assertEqual(packet["local_posture"], "needs_hardening_before_filing")
        self.assertIn("F_no_fund_impact_or_actor_model", packet["blocking_classes"])
        self.assertIn("R1", {row["id"] for row in packet["matched_patterns"]})
        self.assertIn("tools/triager-pre-filing-simulator.py", packet["source_refs"])

    def test_simulate_can_opt_into_provider_backed_mode_with_mock_dispatcher(self) -> None:
        dispatcher = self.root / "mock_dispatcher.py"
        dispatcher.write_text(
            "import json\n"
            "print(json.dumps({\n"
            "  'predicted_verdict': 'needs_more_proof',\n"
            "  'confidence': 0.61,\n"
            "  'killer_phrase': 'event-only',\n"
            "  'suggested_strengthening': 'show funds impact',\n"
            "  'rationale': 'provider advisory mock'\n"
            "}))\n",
            encoding="utf-8",
        )
        old = os.environ.get("AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER")
        os.environ["AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER"] = "1"
        try:
            vault = _mcp.VaultQuery(self.vault_dir, REPO_ROOT)
            packet = vault.call(
                "vault_triager_simulate",
                {
                    "draft_path": str(self.draft),
                    "workspace_path": str(self.ws),
                    "severity": "High",
                    "provider_backed": True,
                    "dispatcher": str(dispatcher),
                },
            )
        finally:
            if old is None:
                os.environ.pop("AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER", None)
            else:
                os.environ["AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER"] = old

        self.assertEqual(packet["schema"], "auditooor.vault_triager_simulate.v1")
        self.assertEqual(packet["mode"], "provider_backed_simulation")
        self.assertTrue(packet["provider_status"]["provider_backed"])
        self.assertTrue(packet["provider_status"]["provider_call_made"])
        self.assertEqual(packet["predicted_verdict"]["predicted_verdict"], "needs_more_proof")
        self.assertTrue(packet["provider_advisory_only"])
        self.assertTrue(packet["capability_boundary"]["provider_backed_simulation"])

    def test_simulate_provider_backed_blocked_mcp_omits_prediction(self) -> None:
        dispatcher = self.root / "mock_dispatcher_fail.py"
        dispatcher.write_text(
            "import json\n"
            "print(json.dumps({'predicted_verdict': 'likely_accept', 'confidence': 1}))\n"
            "raise SystemExit(2)\n",
            encoding="utf-8",
        )
        old = os.environ.get("AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER")
        os.environ["AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER"] = "1"
        try:
            vault = _mcp.VaultQuery(self.vault_dir, REPO_ROOT)
            packet = vault.call(
                "vault_triager_simulate",
                {
                    "draft_path": str(self.draft),
                    "workspace_path": str(self.ws),
                    "provider_backed": True,
                    "dispatcher": str(dispatcher),
                },
            )
        finally:
            if old is None:
                os.environ.pop("AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER", None)
            else:
                os.environ["AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER"] = old

        self.assertEqual(packet["schema"], "auditooor.vault_triager_simulate.v1")
        self.assertEqual(packet["mode"], "provider_backed_simulation_blocked")
        self.assertFalse(packet["provider_status"]["predicted_verdict_supported"])
        self.assertFalse(packet["capability_boundary"]["provider_backed_simulation"])
        self.assertNotIn("predicted_verdict", packet)

    def test_cli_call_dispatches_precheck(self) -> None:
        env = os.environ.copy()
        env["AUDITOOOR_MCP_TELEMETRY_DISABLE"] = "1"
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "vault-mcp-server.py"),
                "--vault-dir",
                str(self.vault_dir),
                "--call",
                "vault_triager_precheck_rules",
                "--args",
                json.dumps({"draft_path": str(self.draft), "workspace_path": str(self.ws)}),
            ],
            check=True,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        packet = json.loads(proc.stdout)
        self.assertEqual(packet["schema"], "auditooor.triager_precheck_rules.v1")
        self.assertEqual(packet["mode"], "rules_mvp")
        self.assertTrue(packet["provider_status"]["reason"])


if __name__ == "__main__":
    unittest.main()
