#!/usr/bin/env python3
"""test_deepseek_dispatch.py - DeepSeek Flash + Pro provider integration tests.

DEEPSEEK-INTEGRATION-CORE (2026-05-26). R36 pathspec via
tools/agent-pathspec-register.py (lane-DEEPSEEK-INTEGRATION-CORE entry in
agent_pathspec.json).

12+ hermetic tests covering:

 1. Mock-mode short-circuit: --mock emits ok-mocked outcome + skips network
 2. Mock-mode env-var equivalence: AUDITOOOR_DEEPSEEK_MOCK=1 == --mock
 3. Mock-mode tier stamp: verification_tier defaults to tier-3
 4. --verified-by attestation stamp
 5. _DEFAULT_BASE_URLS contains deepseek-flash + deepseek-pro
 6. _DEFAULT_MODELS contains operator-cited names
 7. _DEEPSEEK_PRICING_USD_PER_M_TOKENS schema invariants
 8. _resolve_api_key resolves DEEPSEEK_API_KEY for both variants
 9. _resolve_provider_config builds correct api_url + model
10. _resolve_provider_chain explicit deepseek-flash with no key -> exit 2
11. _resolve_deepseek_model_alias reads reference file
12. _deepseek_cost_estimate computes per-call USD
13. Audit record includes provider-name and cost_estimate (mock-mode)
14. L33 env-export discipline (DEEPSEEK_API_KEY in ~/.zshrc)
15. Concurrency budget reference (>=50 in-flight semaphore advisory)

All network is mocked via unittest.mock.patch on urllib.request.urlopen.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch, MagicMock


ROOT = pathlib.Path(__file__).resolve().parents[2]
LLM_TOOL = ROOT / "tools" / "llm-dispatch.py"


def _load_llm_dispatch():
    spec = importlib.util.spec_from_file_location("llm_dispatch_ds", LLM_TOOL)
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


class DefaultsAndPricingTest(unittest.TestCase):
    """Tests 5-7: module-level constants are correctly defined."""

    def test_default_base_urls_includes_deepseek(self) -> None:
        llm = _load_llm_dispatch()
        self.assertIn("deepseek-flash", llm._DEFAULT_BASE_URLS)
        self.assertIn("deepseek-pro", llm._DEFAULT_BASE_URLS)
        self.assertEqual(
            llm._DEFAULT_BASE_URLS["deepseek-flash"],
            "https://api.deepseek.com/anthropic",
        )
        self.assertEqual(
            llm._DEFAULT_BASE_URLS["deepseek-pro"],
            "https://api.deepseek.com/anthropic",
        )

    def test_default_models_includes_deepseek(self) -> None:
        llm = _load_llm_dispatch()
        self.assertIn("deepseek-flash", llm._DEFAULT_MODELS)
        self.assertIn("deepseek-pro", llm._DEFAULT_MODELS)
        # Per live probe 2026-05-26 the canonical API model_ids are these.
        self.assertEqual(llm._DEFAULT_MODELS["deepseek-flash"], "deepseek-v4-flash")
        self.assertEqual(llm._DEFAULT_MODELS["deepseek-pro"], "deepseek-v4-pro")

    def test_pricing_table_schema(self) -> None:
        llm = _load_llm_dispatch()
        for variant in ("deepseek-flash", "deepseek-pro"):
            row = llm._DEEPSEEK_PRICING_USD_PER_M_TOKENS[variant]
            for key in (
                "input_cache_miss",
                "input_cache_hit",
                "output",
                "context_window",
                "max_output_tokens",
                "concurrency_limit",
            ):
                self.assertIn(key, row, f"{variant} missing {key}")
            self.assertGreater(row["input_cache_miss"], row["input_cache_hit"])
            self.assertGreater(row["output"], row["input_cache_miss"])
        # Per operator table: Flash concurrency=2500, Pro concurrency=500.
        self.assertEqual(
            llm._DEEPSEEK_PRICING_USD_PER_M_TOKENS["deepseek-flash"]["concurrency_limit"],
            2500,
        )
        self.assertEqual(
            llm._DEEPSEEK_PRICING_USD_PER_M_TOKENS["deepseek-pro"]["concurrency_limit"],
            500,
        )
        self.assertGreaterEqual(
            llm._DEEPSEEK_PRICING_USD_PER_M_TOKENS["deepseek-pro"]["concurrency_limit"],
            50,  # concurrency budget advisory
        )


class ResolveApiKeyTest(unittest.TestCase):
    """Test 8: DEEPSEEK_API_KEY resolves for both Flash and Pro."""

    def test_resolve_api_key_flash_uses_deepseek_env(self) -> None:
        llm = _load_llm_dispatch()
        with patch.dict(os.environ, _clean_env({"DEEPSEEK_API_KEY": "sk-test-1"}), clear=True):
            self.assertEqual(llm._resolve_api_key("deepseek-flash"), "sk-test-1")

    def test_resolve_api_key_pro_uses_deepseek_env(self) -> None:
        llm = _load_llm_dispatch()
        with patch.dict(os.environ, _clean_env({"DEEPSEEK_API_KEY": "sk-test-2"}), clear=True):
            self.assertEqual(llm._resolve_api_key("deepseek-pro"), "sk-test-2")

    def test_resolve_api_key_no_env_returns_none(self) -> None:
        llm = _load_llm_dispatch()
        with patch.dict(os.environ, _clean_env(), clear=True):
            self.assertIsNone(llm._resolve_api_key("deepseek-flash"))
            self.assertIsNone(llm._resolve_api_key("deepseek-pro"))


class ResolveProviderConfigTest(unittest.TestCase):
    """Test 9: provider config builds correct api_url + model."""

    def test_flash_config_has_correct_api_url(self) -> None:
        llm = _load_llm_dispatch()
        with patch.dict(os.environ, _clean_env({"DEEPSEEK_API_KEY": "sk-test"}), clear=True):
            cfg = llm._resolve_provider_config("deepseek-flash")
            self.assertIsNotNone(cfg)
            self.assertEqual(cfg["name"], "deepseek-flash")
            self.assertEqual(
                cfg["api_url"],
                "https://api.deepseek.com/anthropic/v1/messages",
            )
            self.assertEqual(cfg["model"], "deepseek-v4-flash")

    def test_pro_config_has_correct_api_url(self) -> None:
        llm = _load_llm_dispatch()
        with patch.dict(os.environ, _clean_env({"DEEPSEEK_API_KEY": "sk-test"}), clear=True):
            cfg = llm._resolve_provider_config("deepseek-pro")
            self.assertIsNotNone(cfg)
            self.assertEqual(cfg["name"], "deepseek-pro")
            self.assertEqual(cfg["model"], "deepseek-v4-pro")

    def test_no_key_returns_none(self) -> None:
        llm = _load_llm_dispatch()
        with patch.dict(os.environ, _clean_env(), clear=True):
            self.assertIsNone(llm._resolve_provider_config("deepseek-flash"))


class ResolveProviderChainTest(unittest.TestCase):
    """Test 10: explicit --provider deepseek-flash with no key -> exit 2."""

    def test_explicit_no_key_exits_2(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            prompt = tmp_path / "p.txt"
            prompt.write_text("x", encoding="utf-8")
            env = _clean_env({"AUDITOOOR_LLM_NETWORK_CONSENT": "1"})
            err = io.StringIO()
            urlopen_mock = MagicMock()
            with patch.object(llm.urllib.request, "urlopen", urlopen_mock), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stderr", err):
                rc = llm.main([
                    "--prompt-file", str(prompt),
                    "--provider", "deepseek-flash",
                    "--audit-dir", str(tmp_path / "audit"),
                ])
            self.assertEqual(rc, 2)
            self.assertIn("no-api-key", err.getvalue())
            urlopen_mock.assert_not_called()

    def test_auto_mode_does_not_include_deepseek(self) -> None:
        """DeepSeek must NOT participate in auto-mode fallback chain."""
        llm = _load_llm_dispatch()
        with patch.dict(os.environ, _clean_env({"DEEPSEEK_API_KEY": "sk-ds"}), clear=True):
            chain, _ = llm._resolve_provider_chain("auto", None)
            chain_names = [c["name"] for c in chain]
            self.assertNotIn("deepseek-flash", chain_names)
            self.assertNotIn("deepseek-pro", chain_names)


class ModelAliasResolverTest(unittest.TestCase):
    """Test 11: _resolve_deepseek_model_alias reads the reference file."""

    def test_alias_resolves_from_file(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            alias_file = pathlib.Path(tmp) / "aliases.json"
            alias_file.write_text(json.dumps({
                "aliases": {
                    "deepseek-flash": {"api_model_id": "deepseek-v4-flash"},
                    "deepseek-pro": {"api_model_id": "deepseek-v4-pro"},
                }
            }), encoding="utf-8")
            with patch.dict(
                os.environ,
                _clean_env({"AUDITOOOR_DEEPSEEK_ALIASES_FILE": str(alias_file)}),
                clear=True,
            ):
                self.assertEqual(
                    llm._resolve_deepseek_model_alias("deepseek-flash"),
                    "deepseek-v4-flash",
                )

    def test_alias_missing_file_returns_none(self) -> None:
        llm = _load_llm_dispatch()
        with patch.dict(
            os.environ,
            _clean_env({"AUDITOOOR_DEEPSEEK_ALIASES_FILE": "/no/such/file"}),
            clear=True,
        ):
            self.assertIsNone(llm._resolve_deepseek_model_alias("deepseek-flash"))


class CostEstimateTest(unittest.TestCase):
    """Test 12: _deepseek_cost_estimate computes per-call USD."""

    def test_flash_cost_no_cache_hit(self) -> None:
        llm = _load_llm_dispatch()
        est = llm._deepseek_cost_estimate(
            provider="deepseek-flash",
            input_tokens=1_000_000,
            output_tokens=1_000_000,
        )
        self.assertTrue(est["applicable"])
        # Flash: input cache-miss=$0.14/M, output=$0.28/M -> $0.42 total.
        self.assertAlmostEqual(est["cost_total_usd"], 0.42, places=2)
        self.assertEqual(est["input_cache_hit_tokens"], 0)
        self.assertEqual(est["input_cache_miss_tokens"], 1_000_000)

    def test_pro_cost_with_cache_hit(self) -> None:
        llm = _load_llm_dispatch()
        est = llm._deepseek_cost_estimate(
            provider="deepseek-pro",
            input_tokens=1_000_000,
            output_tokens=0,
            cache_hit_input_tokens=500_000,
        )
        # Pro: cache-miss=$0.435/M, cache-hit=$0.003625/M.
        # 500K miss * $0.435 / 1M + 500K hit * $0.003625 / 1M.
        expected = 500_000 * 0.435 / 1_000_000 + 500_000 * 0.003625 / 1_000_000
        self.assertAlmostEqual(est["cost_total_usd"], round(expected, 6), places=6)

    def test_non_deepseek_provider_not_applicable(self) -> None:
        llm = _load_llm_dispatch()
        est = llm._deepseek_cost_estimate(
            provider="kimi", input_tokens=1000, output_tokens=1000,
        )
        self.assertFalse(est["applicable"])


class MockModeTest(unittest.TestCase):
    """Tests 1-4, 13: --mock + --verified-by + verification_tier stamps."""

    def _run_mock(
        self, *, env_extra: dict, args_extra: list[str]
    ) -> tuple[int, str, pathlib.Path]:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            prompt = tmp_path / "p.txt"
            prompt.write_text("hello deepseek", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env(env_extra)
            buf = io.StringIO()
            err = io.StringIO()
            urlopen_mock = MagicMock()
            with patch.object(llm.urllib.request, "urlopen", urlopen_mock), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err):
                rc = llm.main([
                    "--prompt-file", str(prompt),
                    "--audit-dir", str(audit_dir),
                ] + args_extra)
            # Capture audit records BEFORE returning (TemporaryDirectory cleanup).
            audit_records = sorted(audit_dir.glob("llm_dispatch_*.json"))
            if not audit_records:
                self.fail(f"no audit records emitted; stderr={err.getvalue()!r}")
            audit = json.loads(audit_records[0].read_text())
            # Stash the parsed audit on the instance so callers can read it.
            self._last_audit = audit
            self._last_urlopen_called = urlopen_mock.called
            self._last_stdout = buf.getvalue()
            self._last_stderr = err.getvalue()
            return rc, buf.getvalue(), audit_records[0]

    def test_mock_flag_skips_network_emits_ok_mocked(self) -> None:
        rc, stdout, _ = self._run_mock(
            env_extra={
                "DEEPSEEK_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            },
            args_extra=[
                "--provider", "deepseek-flash",
                "--mock",
            ],
        )
        self.assertEqual(rc, 0, f"stderr={self._last_stderr!r}")
        self.assertIn("mock-mode", stdout)
        self.assertFalse(self._last_urlopen_called)
        self.assertEqual(self._last_audit["outcome"], "ok-mocked")
        self.assertTrue(self._last_audit["mock_mode"])

    def test_mock_env_var_equivalent_to_flag(self) -> None:
        rc, stdout, _ = self._run_mock(
            env_extra={
                "DEEPSEEK_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_DEEPSEEK_MOCK": "1",
            },
            args_extra=[
                "--provider", "deepseek-pro",
            ],
        )
        self.assertEqual(rc, 0, f"stderr={self._last_stderr!r}")
        self.assertEqual(self._last_audit["outcome"], "ok-mocked")
        self.assertTrue(self._last_audit["mock_mode"])
        self.assertFalse(self._last_urlopen_called)

    def test_mock_stamps_verification_tier_tier_3(self) -> None:
        self._run_mock(
            env_extra={
                "DEEPSEEK_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            },
            args_extra=[
                "--provider", "deepseek-flash",
                "--mock",
            ],
        )
        self.assertEqual(
            self._last_audit["verification_tier"],
            "tier-3-synthetic-taxonomy-anchored",
        )

    def test_verified_by_attestation_stamps(self) -> None:
        self._run_mock(
            env_extra={
                "DEEPSEEK_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            },
            args_extra=[
                "--provider", "deepseek-flash",
                "--mock",
                "--verified-by", "claude-second-pass",
            ],
        )
        self.assertEqual(self._last_audit.get("verified_by"), "claude-second-pass")

    def test_mock_audit_includes_cost_estimate(self) -> None:
        self._run_mock(
            env_extra={
                "DEEPSEEK_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            },
            args_extra=[
                "--provider", "deepseek-flash",
                "--mock",
            ],
        )
        cost = self._last_audit.get("cost_estimate")
        self.assertIsNotNone(cost)
        self.assertEqual(cost["provider"], "deepseek-flash")
        self.assertTrue(cost["applicable"])
        self.assertIn("cost_total_usd", cost)
        # Even a tiny prompt should yield a non-negative cost.
        self.assertGreaterEqual(cost["cost_total_usd"], 0.0)


class L33EnvShellExportTest(unittest.TestCase):
    """Test 14: L33 discipline - DEEPSEEK_API_KEY must be in zshrc."""

    def test_deepseek_api_key_in_zshrc(self) -> None:
        # L33: MCP-scoped env is siloed inside Claude sessions; shell
        # tools and cron jobs read ~/.zshrc directly.
        zshrc = pathlib.Path.home() / ".zshrc"
        if not zshrc.is_file():
            self.skipTest("no ~/.zshrc on this host")
        contents = zshrc.read_text(encoding="utf-8", errors="replace")
        # We only require a reference to DEEPSEEK_API_KEY; the value
        # itself is operator-managed.
        self.assertIn(
            "DEEPSEEK_API_KEY",
            contents,
            "DEEPSEEK_API_KEY must appear in ~/.zshrc per L33 discipline; "
            "MCP-scoped env (~/.claude.json) is siloed from shell/cron.",
        )


class BudgetConfigTest(unittest.TestCase):
    """Test 15: budget config exposes DeepSeek cost cap + alert."""

    def test_budget_config_has_deepseek_entries(self) -> None:
        budget_path = ROOT / "tools" / "calibration" / "llm_budget.json"
        data = json.loads(budget_path.read_text(encoding="utf-8"))
        providers = data["providers"]
        for variant in ("deepseek-flash", "deepseek-pro"):
            self.assertIn(variant, providers)
            row = providers[variant]
            self.assertEqual(row["cost_usd_per_month_cap"], 100.0)
            self.assertEqual(row["cost_usd_per_month_alert"], 80.0)
            self.assertIn("concurrency_limit", row)


if __name__ == "__main__":
    unittest.main()
