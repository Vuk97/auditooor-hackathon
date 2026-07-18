#!/usr/bin/env python3
"""test_hunt_completeness_non_code_cluster.py

Generic false-red fix (2026-07-03, surfaced on NUVA): the cluster-coverage signal
(L35 hunt-completeness) treated non-CODE SCOPE.md bullets as in-scope clusters that
need a hunt sidecar, so a smart-contract audit whose SCOPE.md carries a `Scope mode:`
directive line and Web/App domain assets (`app.nuva.finance`, `nuva.finance`)
FALSE-RED'd `fail-missing-cluster-coverage` forever - those "clusters" can never have
a hunt sidecar. `_is_non_code_cluster` now strips scope-directive prose + bare web
domains; real code clusters (`owner/repo`, contract-address labels) are kept.

This can only turn a false-fail into a pass; it never reds a passing audit.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "hunt-completeness-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("hunt_completeness_check", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["hunt_completeness_check"] = m
    spec.loader.exec_module(m)
    return m


class TestNonCodeClusterFilter(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_scope_directive_is_non_code(self):
        self.assertTrue(self.m._is_non_code_cluster("scope mode: primacy of impact for smart contract"))
        self.assertTrue(self.m._is_non_code_cluster("Primacy model: Primacy of Impact"))

    def test_pin_declaration_is_non_code(self):
        # SCOPE.md pin bullet (surfaced on SSV: `pin = 9bb7b21`) is metadata, not a code cluster
        self.assertTrue(self.m._is_non_code_cluster("pin = 9bb7b21"))
        self.assertTrue(self.m._is_non_code_cluster("PIN: bbb26a2"))

    def test_ssv_real_module_clusters_kept(self):
        for c in ("ssvnetwork", "ssvoperators", "operatorlib", "clusterlib",
                  "corelib", "protocollib", "validatorlib", "types"):
            self.assertFalse(self.m._is_non_code_cluster(c), c)

    def test_web_domains_are_non_code(self):
        # cluster names are CLEANED (the parenthetical URL is stripped), so they
        # arrive as bare hostnames like these:
        self.assertTrue(self.m._is_non_code_cluster("app.nuva.finance"))
        self.assertTrue(self.m._is_non_code_cluster("nuva.finance"))
        self.assertTrue(self.m._is_non_code_cluster("app.example.io"))

    def test_real_code_clusters_are_kept(self):
        for c in ("provlabs/vault", "provlabs/nuva-evm-contracts",
                  "ethereum eth_nvprime_vault_router", "src/vault/keeper"):
            self.assertFalse(self.m._is_non_code_cluster(c), c)

    def test_owner_repo_with_dot_is_kept(self):
        # a repo path with a '/' is a code cluster even if the owner has a dot
        self.assertFalse(self.m._is_non_code_cluster("my.org/contracts"))

    def test_empty_is_non_code(self):
        self.assertTrue(self.m._is_non_code_cluster("  "))


if __name__ == "__main__":
    unittest.main()
