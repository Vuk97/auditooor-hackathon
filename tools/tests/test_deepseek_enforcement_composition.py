#!/usr/bin/env python3
"""test_deepseek_enforcement_composition.py - 5-layer DeepSeek enforcement.

DEEPSEEK-INTEGRATION-CORE (2026-05-26). R36 pathspec via
tools/agent-pathspec-register.py (lane-DEEPSEEK-INTEGRATION-CORE entry in
agent_pathspec.json).

Verifies the five enforcement layers compose correctly when a DeepSeek
dispatch happens:

  Layer 1 - llm-dispatch routing: --provider deepseek-flash routes to
            the DeepSeek Anthropic-compat endpoint; auto-mode does NOT
            include DeepSeek.
  Layer 2 - budget cap: the per-call cost_estimate is stamped into the
            audit record; provider-capacity-report aggregates it
            against the $100/mo cap and $80 alert.
  Layer 3 - R37 verification_tier: every DeepSeek dispatch audit
            record carries verification_tier=tier-3-synthetic by
            default, with --verified-by upgrading the attestation.
  Layer 4 - L34 v2 path-guard: writes to drafts (per-finding folders)
            still require operator authorization; tracker / ledger /
            lesson-anchor / out-of-scope buckets remain auto-executable.
            The DeepSeek provider does NOT relax L34 v2.
  Layer 5 - Universal rule-enforce hook: the R36 pathspec entry for
            lane-DEEPSEEK-INTEGRATION-CORE is present in
            .auditooor/agent_pathspec.json so universal-rule-enforce
            allows writes to tools/llm-dispatch.py etc.

Five tests, one per layer.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock


ROOT = pathlib.Path(__file__).resolve().parents[2]
LLM_TOOL = ROOT / "tools" / "llm-dispatch.py"
PROVIDER_CAPACITY = ROOT / "tools" / "provider-capacity-report.py"
L34_CLASSIFIER = ROOT / "tools" / "l34-path-classifier.py"
PATHSPEC_FILE = ROOT / ".auditooor" / "agent_pathspec.json"


def _load_llm_dispatch():
    spec = importlib.util.spec_from_file_location("llm_dispatch_ds_5l", LLM_TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_provider_capacity():
    spec = importlib.util.spec_from_file_location("provider_capacity_ds_5l", PROVIDER_CAPACITY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _clean_env(extra: dict | None = None) -> dict:
    drop = {
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL", "KIMI_API_KEY", "KIMI_ANTHROPIC_BASE_URL",
        "KIMI_MODEL", "MINIMAX_API_KEY", "MINIMAX_ANTHROPIC_BASE_URL",
        "MINIMAX_MODEL", "AUDITOOOR_LLM_PROVIDER",
        "AUDITOOOR_LLM_AUTH_HEADER", "AUDITOOOR_LLM_NETWORK_CONSENT",
        "ADVERSARIAL_LIVE_CONSENT", "AUDITOOOR_KIMI_OAUTH_FILE",
        "AUDITOOOR_LLM_BUDGET_GUARD", "DEEPSEEK_API_KEY",
        "DEEPSEEK_BASE_URL", "DEEPSEEK_FLASH_MODEL", "DEEPSEEK_PRO_MODEL",
        "AUDITOOOR_DEEPSEEK_MOCK", "AUDITOOOR_DEEPSEEK_ALIASES_FILE",
    }
    base = {k: v for k, v in os.environ.items() if k not in drop}
    base["AUDITOOOR_LLM_BUDGET_GUARD"] = "0"
    base.setdefault(
        "AUDITOOOR_KIMI_OAUTH_FILE",
        "/dev/null/no-such-kimi-credentials.json",
    )
    if extra:
        base.update(extra)
    return base


class FiveLayerCompositionTest(unittest.TestCase):

    def test_layer1_llm_dispatch_routing_to_deepseek_endpoint(self) -> None:
        """Layer 1: --provider deepseek-flash builds the DeepSeek URL."""
        llm = _load_llm_dispatch()
        with patch.dict(
            os.environ,
            _clean_env({"DEEPSEEK_API_KEY": "sk-test"}),
            clear=True,
        ):
            cfg = llm._resolve_provider_config("deepseek-flash")
            self.assertEqual(
                cfg["api_url"],
                "https://api.deepseek.com/anthropic/v1/messages",
            )
            self.assertEqual(cfg["name"], "deepseek-flash")
            # Auto-mode does NOT include DeepSeek (separate cost envelope).
            chain, _ = llm._resolve_provider_chain("auto", None)
            chain_names = [c["name"] for c in chain]
            self.assertNotIn("deepseek-flash", chain_names)
            self.assertNotIn("deepseek-pro", chain_names)

    def test_layer2_budget_cap_aggregation(self) -> None:
        """Layer 2: provider-capacity-report aggregates DeepSeek costs."""
        provider_cap = _load_provider_capacity()
        # Build an isolated audit dir with two synthetic DeepSeek records.
        with tempfile.TemporaryDirectory() as tmp:
            audit_dir = pathlib.Path(tmp) / "agent_outputs"
            audit_dir.mkdir(parents=True)
            # Synthetic record 1: live flash call, $50 cost
            (audit_dir / "llm_dispatch_synthetic_1.json").write_text(json.dumps({
                "timestamp": "2030-01-15T12:00:00+00:00",
                "provider": "deepseek-flash",
                "model": "deepseek-v4-flash",
                "task_type": "source-extract",
                "mock_mode": False,
                "cost_estimate": {"cost_total_usd": 50.0, "applicable": True},
                "outcome": "ok",
            }), encoding="utf-8")
            # Synthetic record 2: live flash call, $35 cost -> total $85
            # exceeds $80 alert but NOT $100 cap.
            (audit_dir / "llm_dispatch_synthetic_2.json").write_text(json.dumps({
                "timestamp": "2030-01-16T12:00:00+00:00",
                "provider": "deepseek-flash",
                "model": "deepseek-v4-flash",
                "task_type": "source-extract",
                "mock_mode": False,
                "cost_estimate": {"cost_total_usd": 35.0, "applicable": True},
                "outcome": "ok",
            }), encoding="utf-8")
            with patch.object(
                provider_cap,
                "DISPATCH_AUDIT_ROOTS",
                (audit_dir,),
            ):
                summary = provider_cap._deepseek_cost_summary(month_iso="2030-01")
            flash = summary["per_provider"]["deepseek-flash"]
            self.assertEqual(flash["calls"], 2)
            self.assertEqual(flash["live_calls"], 2)
            self.assertAlmostEqual(flash["cost_usd_total"], 85.0, places=2)
            self.assertTrue(flash["alert_fired"], "alert at $80 should fire at $85")
            self.assertFalse(flash["cap_fired"], "cap at $100 should NOT fire at $85")
            self.assertEqual(flash["cost_usd_alert"], 80.0)
            self.assertEqual(flash["cost_usd_cap"], 100.0)
            # By-task-type breakdown should match.
            self.assertIn("source-extract", flash["by_task_type"])
            self.assertAlmostEqual(
                flash["by_task_type"]["source-extract"]["cost_usd"],
                85.0,
                places=2,
            )

    def test_layer3_r37_verification_tier_stamp(self) -> None:
        """Layer 3: every DeepSeek dispatch carries tier-3 by default."""
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            prompt = tmp_path / "p.txt"
            prompt.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env({
                "DEEPSEEK_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err = io.StringIO()
            urlopen_mock = MagicMock()
            with patch.object(llm.urllib.request, "urlopen", urlopen_mock), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err):
                rc = llm.main([
                    "--prompt-file", str(prompt),
                    "--provider", "deepseek-pro",
                    "--mock",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"stderr={err.getvalue()!r}")
            records = list(audit_dir.glob("llm_dispatch_*.json"))
            self.assertEqual(len(records), 1)
            audit = json.loads(records[0].read_text())
            # Default tier
            self.assertEqual(
                audit["verification_tier"],
                "tier-3-synthetic-taxonomy-anchored",
            )
            self.assertTrue(audit["mock_mode"])

    def test_layer4_l34_path_guard_unchanged(self) -> None:
        """Layer 4: L34 v2 path-guard is NOT relaxed by DeepSeek dispatch.

        Tools-tier writes (this lane) are out-of-scope under L34. Draft
        files inside per-finding folders remain draft-file bucket and
        still require per-draft operator authorization. We verify by
        classifying both this lane's writes and a synthetic draft path.
        """
        # Tool path is out-of-scope.
        proc1 = subprocess.run(
            [
                "python3", str(L34_CLASSIFIER),
                str(LLM_TOOL),
                "--json",
            ],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc1.returncode, 0, f"stderr={proc1.stderr!r}")
        data1 = json.loads(proc1.stdout)
        self.assertEqual(data1["results"][0]["bucket"], "out-of-scope")
        self.assertFalse(data1["results"][0]["requires_per_draft_op_auth"])
        # Draft file remains draft-file (requires per-draft auth).
        synthetic_draft = "submissions/paste_ready/foo-bar-HIGH/foo-bar-HIGH.md"
        proc2 = subprocess.run(
            [
                "python3", str(L34_CLASSIFIER),
                synthetic_draft,
                "--json",
            ],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc2.returncode, 0, f"stderr={proc2.stderr!r}")
        data2 = json.loads(proc2.stdout)
        self.assertEqual(data2["results"][0]["bucket"], "draft-file")
        self.assertTrue(data2["results"][0]["requires_per_draft_op_auth"])

    def test_layer5_r36_pathspec_present(self) -> None:
        """Layer 5: lane-DEEPSEEK-INTEGRATION-CORE entry in pathspec file."""
        self.assertTrue(PATHSPEC_FILE.is_file(), f"missing {PATHSPEC_FILE}")
        data = json.loads(PATHSPEC_FILE.read_text())
        agents = data.get("agents", [])
        lane_ids = [a.get("agent_id") for a in agents]
        self.assertIn("lane-DEEPSEEK-INTEGRATION-CORE", lane_ids)
        # Sanity: the entry covers tools/llm-dispatch.py at minimum.
        entry = next(a for a in agents if a.get("agent_id") == "lane-DEEPSEEK-INTEGRATION-CORE")
        files = entry.get("files", [])
        self.assertIn("tools/llm-dispatch.py", files)
        self.assertIn("tools/provider-capacity-report.py", files)
        self.assertIn("tools/deepseek-model-probe.py", files)


if __name__ == "__main__":
    unittest.main()
