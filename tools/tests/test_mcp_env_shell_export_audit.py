"""
Tests for tools/mcp-env-shell-export-audit.py (L33 rule).
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import importlib.util, types

def _load_module():
    spec = importlib.util.spec_from_file_location(
        "mcp_env_shell_export_audit",
        Path(__file__).parent.parent / "mcp-env-shell-export-audit.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_mod = _load_module()
enumerate_mcp_env_keys = _mod.enumerate_mcp_env_keys
grep_rc_for_export = _mod.grep_rc_for_export
audit = _mod.audit


class TestEnumerateMcpEnvKeys(unittest.TestCase):

    def test_empty_config(self):
        self.assertEqual(enumerate_mcp_env_keys({}), [])

    def test_no_env_block(self):
        cfg = {"mcpServers": {"solodit": {"command": "npx"}}}
        self.assertEqual(enumerate_mcp_env_keys(cfg), [])

    def test_single_key(self):
        cfg = {
            "mcpServers": {
                "solodit": {
                    "command": "npx",
                    "env": {"SOLODIT_API_KEY": "abc123"},
                }
            }
        }
        result = enumerate_mcp_env_keys(cfg)
        self.assertEqual(result, [("solodit", "SOLODIT_API_KEY")])

    def test_multiple_servers_multiple_keys(self):
        cfg = {
            "mcpServers": {
                "solodit": {"env": {"SOLODIT_API_KEY": "x"}},
                "kimi": {"env": {"KIMI_API_KEY": "y", "KIMI_MODEL": "moonshot"}},
            }
        }
        result = enumerate_mcp_env_keys(cfg)
        self.assertIn(("solodit", "SOLODIT_API_KEY"), result)
        self.assertIn(("kimi", "KIMI_API_KEY"), result)
        self.assertIn(("kimi", "KIMI_MODEL"), result)
        self.assertEqual(len(result), 3)


class TestGrepRcForExport(unittest.TestCase):

    def _write_rc(self, content: str) -> Path:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".rc", delete=False
        )
        tmp.write(content)
        tmp.flush()
        return Path(tmp.name)

    def test_key_present(self):
        rc = self._write_rc('export SOLODIT_API_KEY="abc"\n')
        result = grep_rc_for_export("SOLODIT_API_KEY", [rc])
        self.assertTrue(result[str(rc)])

    def test_key_absent(self):
        rc = self._write_rc('export OTHER_VAR="x"\n')
        result = grep_rc_for_export("SOLODIT_API_KEY", [rc])
        self.assertFalse(result[str(rc)])

    def test_key_commented_out(self):
        rc = self._write_rc('# export SOLODIT_API_KEY="abc"\n')
        result = grep_rc_for_export("SOLODIT_API_KEY", [rc])
        # Commented lines: pattern requires no leading # - should be absent
        self.assertFalse(result[str(rc)])

    def test_nonexistent_rc_file(self):
        fake = Path("/tmp/does_not_exist_l33_test.rc")
        result = grep_rc_for_export("SOLODIT_API_KEY", [fake])
        self.assertFalse(result[str(fake)])

    def test_key_in_second_rc(self):
        rc1 = self._write_rc('export OTHER="x"\n')
        rc2 = self._write_rc('export SOLODIT_API_KEY="abc"\n')
        result = grep_rc_for_export("SOLODIT_API_KEY", [rc1, rc2])
        self.assertFalse(result[str(rc1)])
        self.assertTrue(result[str(rc2)])


class TestAudit(unittest.TestCase):

    def _make_claude_json(self, content: dict) -> Path:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        json.dump(content, tmp)
        tmp.flush()
        return Path(tmp.name)

    def _write_rc(self, content: str) -> Path:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".rc", delete=False
        )
        tmp.write(content)
        tmp.flush()
        return Path(tmp.name)

    def test_pass_all_exported(self):
        rc = self._write_rc('export SOLODIT_API_KEY="x"\n')
        cfg = {
            "mcpServers": {
                "solodit": {"env": {"SOLODIT_API_KEY": "x"}}
            }
        }
        claude_path = self._make_claude_json(cfg)
        with patch.object(_mod, "CLAUDE_JSON_PATH", claude_path):
            result = audit(rc_files=[rc])
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(len(result["missing_from_shell_rc"]), 0)

    def test_fail_missing_export(self):
        rc = self._write_rc('export UNRELATED_KEY="y"\n')
        cfg = {
            "mcpServers": {
                "solodit": {"env": {"SOLODIT_API_KEY": "secret"}}
            }
        }
        claude_path = self._make_claude_json(cfg)
        with patch.object(_mod, "CLAUDE_JSON_PATH", claude_path):
            result = audit(rc_files=[rc])
        self.assertEqual(result["verdict"], "fail-missing-shell-rc-exports")
        self.assertEqual(len(result["missing_from_shell_rc"]), 1)
        self.assertEqual(result["missing_from_shell_rc"][0]["env_key"], "SOLODIT_API_KEY")

    def test_empty_mcp_servers(self):
        rc = self._write_rc('')
        claude_path = self._make_claude_json({})
        with patch.object(_mod, "CLAUDE_JSON_PATH", claude_path):
            result = audit(rc_files=[rc])
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["total_mcp_env_keys"], 0)

    def test_missing_claude_json(self):
        fake_path = Path("/tmp/does_not_exist_l33_claude.json")
        rc = self._write_rc('')
        with patch.object(_mod, "CLAUDE_JSON_PATH", fake_path):
            result = audit(rc_files=[rc])
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["total_mcp_env_keys"], 0)


if __name__ == "__main__":
    unittest.main()
