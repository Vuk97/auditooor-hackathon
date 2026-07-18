from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "p4-provider-readiness-probe.py"


def load_module() -> Any:
    spec = importlib.util.spec_from_file_location("p4_provider_readiness_probe", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, payload: Any) -> None:
    write(path, json.dumps(payload, indent=2))


class P4ProviderReadinessProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="p4_provider_probe_")
        self.root = Path(self.tmp.name)
        self.preflight = self.root / "reports" / "p4" / "raw" / "llm_preflight_fixture.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def seed_provider_ready_code(self) -> None:
        write(
            self.root / "tools" / "triager-pre-filing-simulator.py",
            "\n".join(
                [
                    "PROVIDER_CAPABILITY_BOUNDARY = {}",
                    "def build_provider_simulation():",
                    "    return 'tools/llm-dispatch.py'",
                    "parser.add_argument('--provider-backed')",
                ]
            ),
        )
        write(
            self.root / "tools" / "vault-mcp-server.py",
            "\n".join(
                [
                    "def vault_triager_simulate():",
                    "    provider_backed = True",
                    "    build_provider_simulation()",
                    "    return 'AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER'",
                ]
            ),
        )
        write(self.root / "tools" / "llm-dispatch.py", "# dispatcher\n")
        write(self.root / "tools" / "lib" / "triager_precheck_schema.py", "# schema\n")
        write(self.root / "reference" / "triager_patterns.json", "[]\n")

    def seed_preflight(self, *, kimi_usable: bool = True) -> None:
        write_json(
            self.preflight,
            {
                "records": [
                    {
                        "provider": "kimi",
                        "usable": kimi_usable,
                        "dry_run": True,
                        "resolution_path": "kimi-oauth-file" if kimi_usable else "none",
                        "error_class": None if kimi_usable else "no-key",
                    },
                    {
                        "provider": "minimax",
                        "usable": False,
                        "dry_run": True,
                        "resolution_path": "none",
                        "error_class": "no-key",
                    },
                    {
                        "provider": "anthropic",
                        "usable": False,
                        "dry_run": True,
                        "resolution_path": "none",
                        "error_class": "no-key",
                    },
                ]
            },
        )

    def test_separates_ready_local_code_from_missing_live_consent(self) -> None:
        mod = load_module()
        self.seed_provider_ready_code()
        self.seed_preflight()

        report = mod.build_report(
            self.root,
            preflight_paths=[self.preflight],
            env={},
            generated_at_utc="2026-05-24T00:00:00Z",
        )

        self.assertEqual(report["verdict"], "local_code_ready_blocked_by_live_consent")
        self.assertTrue(report["local_code_readiness"]["ready"])
        self.assertEqual(report["blocking_categories"]["local_code"], [])
        self.assertTrue(report["provider_auth_readiness"]["minimum_one_provider_dry_run_usable"])
        self.assertEqual(report["blocking_categories"]["provider_auth"], [])
        self.assertIn(
            "minimax_auth_unusable_dry_run:no-key",
            report["blocking_categories"]["provider_auth_nonblocking_provider_gaps"],
        )
        self.assertIn("live_network_consent_missing", report["blocking_categories"]["live_consent"])
        self.assertFalse(report["live_provider_calls_run"])

    def test_missing_provider_simulation_builder_is_local_code_blocker(self) -> None:
        mod = load_module()
        write(self.root / "tools" / "triager-pre-filing-simulator.py", "# local rules only\n")
        write(
            self.root / "tools" / "vault-mcp-server.py",
            "def vault_triager_simulate(): provider_backed = True; build_provider_simulation()\n"
            "AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER = '1'\n",
        )
        write(self.root / "tools" / "llm-dispatch.py", "# dispatcher\n")
        write(self.root / "tools" / "lib" / "triager_precheck_schema.py", "# schema\n")
        write(self.root / "reference" / "triager_patterns.json", "[]\n")
        self.seed_preflight()

        report = mod.build_report(
            self.root,
            preflight_paths=[self.preflight],
            env={"AUDITOOOR_LLM_NETWORK_CONSENT": "1"},
            generated_at_utc="2026-05-24T00:00:00Z",
        )

        self.assertEqual(report["verdict"], "blocked_by_local_code")
        blockers = report["blocking_categories"]["local_code"]
        self.assertTrue(any(row["blocker"] == "provider_simulation_builder_missing_or_incomplete" for row in blockers))
        self.assertEqual(report["blocking_categories"]["live_consent"], [])

    def test_no_preflight_artifact_is_provider_auth_blocker(self) -> None:
        mod = load_module()
        self.seed_provider_ready_code()

        report = mod.build_report(
            self.root,
            preflight_paths=[],
            env={"ADVERSARIAL_LIVE_CONSENT": "1"},
            generated_at_utc="2026-05-24T00:00:00Z",
        )

        self.assertEqual(report["verdict"], "local_code_ready_blocked_by_provider_auth")
        self.assertEqual(report["blocking_categories"]["local_code"], [])
        self.assertEqual(report["blocking_categories"]["live_consent"], [])
        self.assertIn("kimi_auth_not_checked_offline", report["blocking_categories"]["provider_auth"])

    def test_default_discovery_uses_p4_offline_preflight_only(self) -> None:
        mod = load_module()
        p4_offline = (
            self.root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_P4_CURRENT_LOCAL_RECHECK"
            / "raw"
            / "llm_preflight_20260524T102126Z.json"
        )
        p4_live = (
            self.root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_P4_CURRENT_LOCAL_RECHECK"
            / "raw_live"
            / "llm_preflight_20260524T102127Z.json"
        )
        unrelated = (
            self.root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_P1_LLM_SWEEP_MVP"
            / "raw_auth"
            / "llm_preflight_20260524T135431Z.json"
        )
        write_json(
            p4_offline,
            {
                "records": [
                    {"provider": "kimi", "usable": True, "dry_run": True, "resolution_path": "kimi-oauth-file"},
                    {"provider": "minimax", "usable": False, "dry_run": True, "error_class": "no-key"},
                    {"provider": "anthropic", "usable": False, "dry_run": True, "error_class": "no-key"},
                ]
            },
        )
        write_json(
            p4_live,
            {"records": [{"provider": "anthropic", "usable": True, "dry_run": False, "resolution_path": "live"}]},
        )
        write_json(
            unrelated,
            {"records": [{"provider": "anthropic", "usable": True, "dry_run": True, "resolution_path": "env"}]},
        )
        os.utime(p4_offline, (1, 1))
        os.utime(p4_live, (2, 2))
        os.utime(unrelated, (3, 3))

        auth = mod.provider_auth_readiness(self.root)

        self.assertEqual(
            auth["evidence_source"],
            "reports/v3_iter_2026-05-24/lane_P4_CURRENT_LOCAL_RECHECK/raw/llm_preflight_20260524T102126Z.json",
        )
        self.assertTrue(auth["minimum_one_provider_dry_run_usable"])
        self.assertEqual(auth["provider_status"][0]["provider"], "kimi")
        self.assertTrue(auth["provider_status"][0]["usable_dry_run"])

    def test_explicit_non_dry_run_preflight_is_not_offline_auth_evidence(self) -> None:
        mod = load_module()
        live_preflight = self.root / "reports" / "p4" / "raw_live" / "llm_preflight_live.json"
        write_json(
            live_preflight,
            {"records": [{"provider": "kimi", "usable": True, "dry_run": False, "resolution_path": "live"}]},
        )

        auth = mod.provider_auth_readiness(self.root, preflight_paths=[live_preflight])

        self.assertEqual(auth["evidence_source"], "not_found")
        self.assertFalse(auth["minimum_one_provider_dry_run_usable"])
        self.assertIn("kimi_auth_not_checked_offline", auth["provider_auth_blockers"])

    def test_markdown_summarizes_categories_without_secrets(self) -> None:
        mod = load_module()
        self.seed_provider_ready_code()
        self.seed_preflight()
        report = mod.build_report(
            self.root,
            preflight_paths=[self.preflight],
            env={},
            generated_at_utc="2026-05-24T00:00:00Z",
        )

        markdown = mod.render_markdown(report)

        self.assertIn("Verdict: `local_code_ready_blocked_by_live_consent`", markdown)
        self.assertIn("`live_consent`: `1`", markdown)
        self.assertIn("kimi-oauth-file", markdown)
        self.assertNotIn("access_token", markdown)


if __name__ == "__main__":
    unittest.main()
