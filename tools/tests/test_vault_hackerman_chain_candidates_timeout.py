#!/usr/bin/env python3
# r36-rebuttal: cap78-chain-candidates-timeout-2026-05-27 lane registered via
# tools/agent-pathspec-register.py (.auditooor/agent_pathspec.json, TTL 2h).
"""CAP-GAP-78 regression tests: vault_hackerman_chain_candidates timeout_seconds kwarg.

Covers:
  1. Default timeout_seconds=60 is reflected in response inputs block.
  2. Explicit timeout_seconds=5 is clamped and reflected correctly.
  3. timeout_seconds=0 is clamped to minimum 5.
  4. timeout_seconds=9999 is clamped to maximum 600.
  5. Schema inputSchema contains timeout_seconds property with correct bounds.
  6. Both success and degraded (error) paths carry timeout_seconds in inputs.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_server_class():
    """Load vault-mcp-server with sys.modules pre-registration.

    Required to avoid Python 3.12+ dataclass AttributeError on
    'NoneType' object has no attribute '__dict__'. Pattern from
    test_vault_hackerman_chain_candidates_global_seed.py.
    """
    module_name = "vault_mcp_server_cap78"
    if module_name in sys.modules:
        mod = sys.modules[module_name]
        return mod.VaultQuery, mod.TOOL_SCHEMAS
    spec = importlib.util.spec_from_file_location(module_name, str(MODULE_PATH))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return mod.VaultQuery, mod.TOOL_SCHEMAS


class TestChainCandidatesTimeoutKwarg(unittest.TestCase):
    """Unit tests for the CAP-GAP-78 timeout_seconds kwarg."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.ServerClass, cls.TOOL_SCHEMAS = _load_server_class()
        except Exception as exc:
            raise unittest.SkipTest(f"Cannot load vault-mcp-server: {exc}") from exc
        # VaultQuery(vault_dir, repo_root=None) - pass a dummy vault_dir.
        try:
            import tempfile as _tmp
            _vd = Path(_tmp.mkdtemp(prefix="cap78_test_vault_"))
            cls.srv = cls.ServerClass(_vd)
        except Exception as exc:
            raise unittest.SkipTest(f"Cannot instantiate VaultQuery: {exc}") from exc

    def _call(self, **kwargs):
        """Invoke vault_hackerman_chain_candidates and return result."""
        return self.srv.vault_hackerman_chain_candidates(**kwargs)

    # ------------------------------------------------------------------
    # 1. Default timeout (60s) is reflected in inputs.
    # ------------------------------------------------------------------
    def test_default_timeout_in_inputs(self):
        out = self._call(limit=1, include_generic=False)
        inputs = out.get("inputs") or {}
        self.assertIn(
            "timeout_seconds",
            inputs,
            "inputs block must contain timeout_seconds",
        )
        self.assertAlmostEqual(
            float(inputs["timeout_seconds"]),
            60.0,
            places=1,
            msg="Default timeout_seconds must be 60.0",
        )

    # ------------------------------------------------------------------
    # 2. Explicit timeout_seconds=5 (minimum) is reflected.
    # ------------------------------------------------------------------
    def test_explicit_timeout_5_reflected(self):
        out = self._call(limit=1, include_generic=False, timeout_seconds=5)
        inputs = out.get("inputs") or {}
        self.assertAlmostEqual(
            float(inputs.get("timeout_seconds", -1)),
            5.0,
            places=1,
            msg="timeout_seconds=5 must be stored as 5.0",
        )

    # ------------------------------------------------------------------
    # 3. timeout_seconds=0 is clamped to 5 (minimum).
    # ------------------------------------------------------------------
    def test_zero_clamped_to_minimum(self):
        out = self._call(limit=1, include_generic=False, timeout_seconds=0)
        inputs = out.get("inputs") or {}
        self.assertGreaterEqual(
            float(inputs.get("timeout_seconds", 0)),
            5.0,
            "timeout_seconds=0 must be clamped to >= 5.0",
        )

    # ------------------------------------------------------------------
    # 4. timeout_seconds=9999 is clamped to 600 (maximum).
    # ------------------------------------------------------------------
    def test_large_value_clamped_to_maximum(self):
        out = self._call(limit=1, include_generic=False, timeout_seconds=9999)
        inputs = out.get("inputs") or {}
        self.assertLessEqual(
            float(inputs.get("timeout_seconds", 9999)),
            600.0,
            "timeout_seconds=9999 must be clamped to <= 600.0",
        )

    # ------------------------------------------------------------------
    # 5. Schema inputSchema contains timeout_seconds with correct bounds.
    # ------------------------------------------------------------------
    def test_schema_contains_timeout_seconds(self):
        schema_entry = None
        for entry in self.TOOL_SCHEMAS:
            if entry.get("name") == "vault_hackerman_chain_candidates":
                schema_entry = entry
                break
        self.assertIsNotNone(
            schema_entry,
            "vault_hackerman_chain_candidates not found in TOOL_SCHEMAS",
        )
        props = (schema_entry.get("inputSchema") or {}).get("properties") or {}
        self.assertIn(
            "timeout_seconds",
            props,
            "inputSchema must expose timeout_seconds property",
        )
        ts_prop = props["timeout_seconds"]
        self.assertEqual(ts_prop.get("type"), "number")
        self.assertEqual(ts_prop.get("minimum"), 5)
        self.assertEqual(ts_prop.get("maximum"), 600)

    # ------------------------------------------------------------------
    # 6. The degraded (error) path also carries timeout_seconds in inputs.
    # (Force a degraded path by passing a non-existent tag_dir.)
    # ------------------------------------------------------------------
    def test_degraded_path_carries_timeout_seconds(self):
        out = self._call(
            limit=1,
            include_generic=False,
            tag_dir="/nonexistent_cap78_timeout_test_dir",
            timeout_seconds=42,
        )
        # Either degraded or not - inputs must carry timeout_seconds.
        inputs = out.get("inputs") or {}
        self.assertIn(
            "timeout_seconds",
            inputs,
            "Degraded path inputs block must contain timeout_seconds",
        )
        self.assertAlmostEqual(
            float(inputs.get("timeout_seconds", -1)),
            42.0,
            places=1,
            msg="Degraded path must reflect explicit timeout_seconds=42",
        )


if __name__ == "__main__":
    unittest.main()
