#!/usr/bin/env python3
"""Guard tests for the local-cli provider in llm-dispatch.py.

The local-cli provider rides the operator's local coding-agent CLI (codex or
claude) subscription - NO API key - so every llm-dispatch consumer works under
whichever agent is driving. These tests pin the pure helpers (prompt extraction,
codex JSONL parse) + config resolution + the no-CLI fallback, and run a live
codex round-trip when codex is installed (skipped otherwise)."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("llm_dispatch", ROOT / "tools" / "llm-dispatch.py")
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


class TestPromptExtraction(unittest.TestCase):
    def test_system_plus_messages_joined(self):
        body = json.dumps({
            "system": "SYS-GUARDRAILS",
            "messages": [{"role": "user", "content": "USER-TASK"}],
        }).encode()
        out = mod._local_cli_extract_prompt(body)
        self.assertIn("SYS-GUARDRAILS", out)
        self.assertIn("USER-TASK", out)

    def test_content_block_list(self):
        body = json.dumps({
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "BLOCK-A"},
                {"type": "image", "source": {}},
                {"type": "text", "text": "BLOCK-B"},
            ]}],
        }).encode()
        out = mod._local_cli_extract_prompt(body)
        self.assertIn("BLOCK-A", out)
        self.assertIn("BLOCK-B", out)

    def test_non_json_body_passthrough(self):
        self.assertEqual(mod._local_cli_extract_prompt(b"raw prompt"), "raw prompt")


class TestCodexStdoutParse(unittest.TestCase):
    def test_extracts_last_agent_message(self):
        jsonl = "\n".join([
            '{"type":"thread.started","thread_id":"x"}',
            '{"type":"item.completed","item":{"id":"i0","type":"agent_message","text":"FIRST"}}',
            '{"type":"item.completed","item":{"id":"i1","type":"agent_message","text":"FINAL"}}',
            '{"type":"turn.completed","usage":{"output_tokens":6}}',
        ])
        self.assertEqual(mod._parse_codex_stdout(jsonl), "FINAL")

    def test_ignores_non_json_and_non_message(self):
        self.assertEqual(mod._parse_codex_stdout("noise\n{\"type\":\"turn.started\"}\n"), "")


class TestConfigResolution(unittest.TestCase):
    def setUp(self):
        # snapshot + clear the selector envs
        self._saved = {k: os.environ.get(k) for k in (mod._LOCAL_CLI_AGENT_ENV, mod._LOCAL_CLI_MODEL_ENV)}
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_none_when_no_cli(self):
        orig_codex, orig_which = mod._find_codex_bin, shutil.which
        mod._find_codex_bin = lambda: None
        shutil.which = lambda name: None
        try:
            self.assertIsNone(mod._resolve_local_cli_config())
        finally:
            mod._find_codex_bin, shutil.which = orig_codex, orig_which

    def test_auto_keeps_local_cli_disabled_when_claude_is_present(self):
        # REFINED POLICY (dispatch-architecture audit): in AUTO mode the local-cli
        # Claude remains explicit-only because its headless auth is unreliable.
        orig_codex, orig_which = mod._find_codex_bin, shutil.which
        mod._find_codex_bin = lambda: "/fake/codex"
        shutil.which = lambda name: "/fake/claude" if name == "claude" else None
        try:
            self.assertIsNone(mod._resolve_local_cli_config())
        finally:
            mod._find_codex_bin, shutil.which = orig_codex, orig_which

    def test_auto_falls_back_to_codex_when_claude_is_absent(self):
        # Codex is the agentic fallback when Claude is unavailable.
        orig_codex, orig_which = mod._find_codex_bin, shutil.which
        mod._find_codex_bin = lambda: "/fake/codex"
        shutil.which = lambda name: None
        try:
            cfg = mod._resolve_local_cli_config()
            self.assertIsNotNone(cfg)
            self.assertEqual(cfg["backend"], "codex")
        finally:
            mod._find_codex_bin, shutil.which = orig_codex, orig_which

    def test_force_codex_still_works(self):
        # codex remains available when EXPLICITLY forced.
        orig_codex, orig_which = mod._find_codex_bin, shutil.which
        mod._find_codex_bin = lambda: "/fake/codex"
        shutil.which = lambda name: None
        os.environ[mod._LOCAL_CLI_AGENT_ENV] = "codex"
        try:
            cfg = mod._resolve_local_cli_config()
            self.assertEqual(cfg["backend"], "codex")
        finally:
            mod._find_codex_bin, shutil.which = orig_codex, orig_which

    def test_force_claude(self):
        orig_codex, orig_which = mod._find_codex_bin, shutil.which
        mod._find_codex_bin = lambda: "/fake/codex"
        shutil.which = lambda name: "/fake/claude" if name == "claude" else None
        os.environ[mod._LOCAL_CLI_AGENT_ENV] = "claude"
        try:
            cfg = mod._resolve_local_cli_config()
            self.assertEqual(cfg["backend"], "claude")
            self.assertEqual(cfg["model"], "sonnet")  # claude default model
        finally:
            mod._find_codex_bin, shutil.which = orig_codex, orig_which

    def test_force_claude_missing_fails_closed(self):
        orig_codex, orig_which = mod._find_codex_bin, shutil.which
        mod._find_codex_bin = lambda: "/fake/codex"
        shutil.which = lambda name: None
        os.environ[mod._LOCAL_CLI_AGENT_ENV] = "claude"
        try:
            self.assertIsNone(mod._resolve_local_cli_config())
        finally:
            mod._find_codex_bin, shutil.which = orig_codex, orig_which


class TestAutoChainLocalCliFallback(unittest.TestCase):
    def test_local_cli_codex_fallback_is_first_when_claude_is_absent(self):
        orig_codex, orig_which = mod._find_codex_bin, shutil.which
        mod._find_codex_bin = lambda: "/fake/codex"
        shutil.which = lambda name: None
        try:
            chain, explicit = mod._resolve_provider_chain("auto", None)
            names = [p["name"] for p in chain]
            self.assertEqual(names[0], "local-cli")
            self.assertEqual(chain[0]["backend"], "codex")
        finally:
            mod._find_codex_bin, shutil.which = orig_codex, orig_which

    def test_force_local_cli_claude_present_in_chain(self):
        # When forced to claude, local-cli IS the chain head.
        orig_codex, orig_which = mod._find_codex_bin, shutil.which
        mod._find_codex_bin = lambda: None
        shutil.which = lambda name: "/fake/claude" if name == "claude" else None
        os.environ[mod._LOCAL_CLI_AGENT_ENV] = "claude"
        try:
            chain, explicit = mod._resolve_provider_chain("auto", None)
            self.assertTrue(chain)
            self.assertEqual(chain[0]["name"], "local-cli")
        finally:
            mod._find_codex_bin, shutil.which = orig_codex, orig_which
            os.environ.pop(mod._LOCAL_CLI_AGENT_ENV, None)


class TestLiveCodexRoundTrip(unittest.TestCase):
    def test_live_codex_dispatch(self):
        codex = mod._find_codex_bin()
        if not codex:
            self.skipTest("codex CLI not installed")
        cfg = {"name": "local-cli", "backend": "codex", "bin": codex, "model": "",
               "all_candidates": [("codex", codex)]}
        body = json.dumps({"messages": [{"role": "user",
                          "content": "Reply with exactly the two characters: OK"}]}).encode()
        try:
            text, status, retries, tokens = mod._local_cli_once(cfg, body, timeout=120.0)
        except mod.ProviderFallback as e:
            self.skipTest(f"codex not authenticated in this env: {e}")
        self.assertEqual(status, 200)
        self.assertIn("OK", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
