#!/usr/bin/env python3
"""Tests for tools/scope-md-parser.py (Wave O-A).

11 unit tests covering:
  1. Real base-azul SCOPE.md: base-succinct-client-utils → IN_SCOPE via modification rule
  2. Real base-azul SCOPE.md: hypothetical op-succinct-utils → OOS
  3. Real base-azul SCOPE.md: path under op-node → OOS
  4. Real base-azul SCOPE.md: path under crates/execution/ → IN_SCOPE
  5. ModRule.matches_crate_name: positive case (base-succinct-client-utils)
  6. ModRule.matches_crate_name: negative case (op-succinct-utils — no fork_prefix)
  7. parse_scope_md: extracts modification_rules from well-formed SCOPE.md
  8. parse_scope_md: extracts in_scope_paths from ## In scope section
  9. parse_scope_md: extracts oos_paths from ## Out of scope section
 10. is_path_in_scope: default advisory for unknown path with no Cargo.toml
 11. is_path_in_scope: modification_rule trumps OOS token match
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "scope-md-parser.py"

# Real SCOPE.md location (base-azul audit workspace)
REAL_SCOPE_MD = Path("/Users/wolf/audits/base-azul/SCOPE.md")


def _load_module():
    spec = importlib.util.spec_from_file_location("scope_md_parser", TOOL)
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["scope_md_parser"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_module()

_SYNTHETIC_SCOPE_MD = """\
# Scope

## In scope

### Blockchain / DLT
- `github.com/base/base/tree/v0.8.0-rc.28`
  - `crates/execution/*`
  - `crates/consensus/*`
  - `crates/proof/*`

### Dependencies & modifications
- Base modifications to **Op-Succinct** are in-scope (core Op-Succinct is OOS).

## Out of scope (explicitly carved out)

- OP Stack code: `op-node`, `op-geth`, `op-batcher`, `op-reth`.
- ZK prover internals + circuits (SP1 guest programs, Succinct Prover Network).
- **Op-Succinct core** (only Base's changes to it are in-scope).
"""


class TestModRuleMatchesCrateName(unittest.TestCase):
    """Tests for ModRule.matches_crate_name."""

    def test_positive_base_succinct_client_utils(self):
        """base-succinct-client-utils matches fork_prefix=base-, upstream=op-succinct."""
        rule = _MOD.ModRule(upstream_crate="op-succinct", fork_prefix="base-")
        self.assertTrue(rule.matches_crate_name("base-succinct-client-utils"))

    def test_negative_no_fork_prefix(self):
        """op-succinct-utils does not have the base- prefix → no match."""
        rule = _MOD.ModRule(upstream_crate="op-succinct", fork_prefix="base-")
        self.assertFalse(rule.matches_crate_name("op-succinct-utils"))

    def test_negative_unrelated_crate(self):
        """totally-unrelated-crate does not match."""
        rule = _MOD.ModRule(upstream_crate="op-succinct", fork_prefix="base-")
        self.assertFalse(rule.matches_crate_name("totally-unrelated-crate"))


class TestParseScopeMd(unittest.TestCase):
    """Tests for parse_scope_md() against synthetic SCOPE.md fixture."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        scope_path = Path(self._tmp.name) / "SCOPE.md"
        scope_path.write_text(_SYNTHETIC_SCOPE_MD, encoding="utf-8")
        self.scope_path = scope_path
        self.manifest = _MOD.parse_scope_md(scope_path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_modification_rules_extracted(self):
        """parse_scope_md extracts 'Base modifications to Op-Succinct are in-scope' rule."""
        rules = self.manifest.modification_rules
        self.assertTrue(len(rules) >= 1, f"Expected >=1 mod rule, got {rules}")
        upstreams = [r.upstream_crate for r in rules]
        self.assertTrue(
            any("succinct" in u for u in upstreams),
            f"Expected 'succinct' in upstream crates, got {upstreams}",
        )

    def test_in_scope_paths_extracted(self):
        """parse_scope_md extracts in-scope path tokens from ## In scope section."""
        paths = self.manifest.in_scope_paths
        # Should contain tokens referencing crates/execution etc.
        combined = " ".join(paths)
        self.assertIn("crates/execution", combined, f"in_scope_paths: {paths[:10]}")

    def test_oos_paths_extracted(self):
        """parse_scope_md extracts OOS path tokens from ## Out of scope section."""
        paths = self.manifest.oos_paths
        combined = " ".join(paths)
        self.assertIn("op-node", combined, f"oos_paths: {paths[:10]}")


class TestIsPathInScope(unittest.TestCase):
    """Tests for is_path_in_scope() using synthetic fixture."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        scope_path = Path(self._tmp.name) / "SCOPE.md"
        scope_path.write_text(_SYNTHETIC_SCOPE_MD, encoding="utf-8")
        self.manifest = _MOD.parse_scope_md(scope_path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_unknown_path_default_in_scope(self):
        """Path with no matching token → in_scope_default (advisory)."""
        in_scope, reason = _MOD.is_path_in_scope(
            "some/totally/random/path.rs", self.manifest, crate_name=None
        )
        self.assertTrue(in_scope)
        self.assertIn("default", reason.lower())

    def test_modification_rule_trumps_oos_token(self):
        """If crate_name matches modification_rule, result is IN_SCOPE even if path has OOS substring.

        This is the core Gap #1 fix: crates/succinct/utils/client/ contains
        tokens that might match OOS patterns, but the crate name base-succinct-client-utils
        identifies it as a Base modification → IN_SCOPE wins.
        """
        in_scope, reason = _MOD.is_path_in_scope(
            "external/base-rc28-clean/crates/succinct/utils/client/src/precompiles/mod.rs",
            self.manifest,
            crate_name="base-succinct-client-utils",
        )
        self.assertTrue(in_scope, f"Expected IN_SCOPE via modification rule, got: {reason}")
        self.assertIn("modification_rule", reason)

    def test_op_node_path_is_oos(self):
        """Path containing op-node is OOS."""
        in_scope, reason = _MOD.is_path_in_scope(
            "external/base/op-node/crates/foo/bar.rs",
            self.manifest,
            crate_name=None,
        )
        self.assertFalse(in_scope, f"Expected OOS for op-node path, got: {reason}")
        self.assertIn("oos", reason.lower())

    def test_crates_execution_is_in_scope(self):
        """Path under crates/execution/ is IN_SCOPE via in-scope token match."""
        in_scope, reason = _MOD.is_path_in_scope(
            "external/base/crates/execution/engine-tree/src/cached_execution.rs",
            self.manifest,
            crate_name=None,
        )
        self.assertTrue(in_scope, f"Expected IN_SCOPE for crates/execution path, got: {reason}")


@unittest.skipUnless(REAL_SCOPE_MD.exists(), "real SCOPE.md not found at /Users/wolf/audits/base-azul/SCOPE.md")
class TestRealScopeMd(unittest.TestCase):
    """Tests against the actual base-azul SCOPE.md (skipped if file absent)."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = _MOD.parse_scope_md(REAL_SCOPE_MD)

    def test_base_succinct_client_utils_in_scope(self):
        """base-succinct-client-utils + crates/succinct/utils/client path → IN_SCOPE (Gap #1 fix)."""
        in_scope, reason = _MOD.is_path_in_scope(
            "external/base-rc28-clean/crates/succinct/utils/client/src/precompiles/mod.rs",
            self.manifest,
            crate_name="base-succinct-client-utils",
        )
        self.assertTrue(
            in_scope,
            f"SCOPE.md:34 declares Base modifications to Op-Succinct in-scope. "
            f"Crate 'base-succinct-client-utils' should pass. Got reason: {reason}",
        )
        self.assertIn("modification_rule", reason)

    def test_hypothetical_op_succinct_crate_is_oos(self):
        """Hypothetical upstream crate op-succinct-utils → OOS (no base- prefix)."""
        in_scope, reason = _MOD.is_path_in_scope(
            "external/op-succinct/crates/utils/client/src/foo.rs",
            self.manifest,
            crate_name="op-succinct-utils",
        )
        self.assertFalse(
            in_scope,
            f"Upstream op-succinct crate should be OOS. Got reason: {reason}",
        )

    def test_op_node_is_oos(self):
        """Path under op-node → OOS per SCOPE.md:39."""
        in_scope, reason = _MOD.is_path_in_scope(
            "external/base/op-node/crates/sync/src/lib.rs",
            self.manifest,
            crate_name=None,
        )
        self.assertFalse(in_scope, f"op-node path should be OOS. Got: {reason}")

    def test_crates_execution_in_scope(self):
        """Path under crates/execution/ → IN_SCOPE per SCOPE.md:12."""
        in_scope, reason = _MOD.is_path_in_scope(
            "external/base/crates/execution/evm/src/handler.rs",
            self.manifest,
            crate_name=None,
        )
        self.assertTrue(in_scope, f"crates/execution path should be IN_SCOPE. Got: {reason}")


if __name__ == "__main__":
    unittest.main()
