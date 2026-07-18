#!/usr/bin/env python3
"""Regression: inscope-hunt-batch-builder._is_in_scope must be DENYLIST-ONLY.

The manifest (inscope_units.jsonl) is already the authoritative scope-filtered
set, so a unit is in-scope unless it hits the OOS denylist. Before 2026-06-27
_is_in_scope ALSO required a positive match against a hardcoded Optimism-only
allowlist (packages/contracts-bedrock/src/, /op-node/...), so on EVERY non-OP
workspace it dropped all units -> 0 hunt tasks (Morpho exposed it: 655 in-scope
units -> 0 tasks). A positive allowlist must never drop a manifest unit."""
import importlib.util
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "inscope-hunt-batch-builder.py"
_s = importlib.util.spec_from_file_location("ihbb_scope", _T)
ihbb = importlib.util.module_from_spec(_s)
_s.loader.exec_module(ihbb)


class ScopeGenericTest(unittest.TestCase):
    def test_non_optimism_inscope_paths_not_dropped(self):
        # Morpho (and any non-OP) in-scope paths must be in-scope.
        for rel in (
            "src/vault-v2/src/VaultV2.sol",
            "src/morpho-blue/src/Morpho.sol",
            "src/bundler3/src/adapters/CoreAdapter.sol",
            "src/metamorpho-v1-1/src/MetaMorphoV1_1.sol",
            "contracts/Foo.sol",                 # generic layout
            "programs/x/src/lib.rs",             # generic non-OP
        ):
            self.assertTrue(ihbb._is_in_scope(rel), f"wrongly dropped in-scope: {rel}")

    def test_oos_denylist_still_drops(self):
        for rel in (
            "src/vault-v2/test/VaultV2.t.sol",   # .t.sol
            "src/morpho-blue/test/Foo.sol",      # /test/
            "src/x/mocks/MockOracle.sol",        # /mocks/
            "src/y/foo_test.go",                 # _test.go
            "docs/guide.md",                     # /docs/
        ):
            self.assertFalse(ihbb._is_in_scope(rel), f"OOS not dropped: {rel}")

    def test_optimism_hint_paths_still_in_scope(self):
        # The former allowlist entries remain in-scope (now via denylist-pass).
        self.assertTrue(ihbb._is_in_scope("packages/contracts-bedrock/src/L1/Foo.sol"))
        self.assertTrue(ihbb._is_in_scope("op-node/rollup/derive/x.go"))


if __name__ == "__main__":
    unittest.main()
