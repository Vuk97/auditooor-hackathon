#!/usr/bin/env python3
"""Guard test: per-function-hacker-questions.py rubric-row SURFACE-APPLICABILITY gate.

Pinned waste (NUVA 2026-06-30): 120/434 = 28% of the ranked per-fn questions were the
Critical "governance-voting-manipulation" rubric row attached to EVM contracts with ZERO
governance state - every one auto-NEGATIVE, burning 28% of hunt budget. The gate drops a
structurally-vacuous impact class PER REPO-TREE (a sibling tree that DOES have the surface,
e.g. a cosmos gov vault, still gets the questions) and is FAIL-OPEN (never drops on a scan
error or a relative/unknown path).
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "per-function-hacker-questions.py"


def _load():
    sys.argv = ["per-function-hacker-questions.py"]
    spec = importlib.util.spec_from_file_location("per_function_hacker_questions", _TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = _load()
GOV = "Manipulation of governance voting result deviating from voted outcome"
THEFT = "Direct theft of any user funds, whether at-rest or in-motion"


class SurfaceGateTest(unittest.TestCase):
    def setUp(self):
        # fresh per-test cache so trees don't leak between cases
        M._SURFACE_CACHE.clear()
        self.root = Path(tempfile.mkdtemp(prefix="surface_gate_"))

    def _mk(self, rel, body):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
        return p

    # governance row dropped on a tree with NO governance surface
    def test_governance_dropped_when_absent(self):
        f = self._mk("src/evm/contracts/Vault.sol",
                     "contract Vault { function deposit() external {} }")
        self.assertFalse(M._rubric_row_applicable(GOV, str(f)))

    # governance row KEPT on a tree that HAS governance symbols
    def test_governance_kept_when_present(self):
        f = self._mk("src/gov/keeper/msg_server.go",
                     "package keeper\nfunc (k Keeper) Vote() {} // governance proposal tally")
        self.assertTrue(M._rubric_row_applicable(GOV, str(f)))

    # non-surface-gated class (theft) is never dropped
    def test_theft_never_gated(self):
        f = self._mk("src/evm/contracts/Vault.sol", "contract Vault {}")
        self.assertTrue(M._rubric_row_applicable(THEFT, str(f)))

    # PER-TREE isolation: sibling EVM tree (no gov) drops, cosmos tree (gov) keeps
    def test_per_tree_isolation(self):
        evm = self._mk("src/nuva-evm-contracts/contracts/RemoteVault.sol",
                       "contract RemoteVault { function withdraw() external {} }")
        cosmos = self._mk("src/vault/x/vault/keeper/msg_server.go",
                          "package keeper\n// governance voting quorum proposal")
        self.assertFalse(M._rubric_row_applicable(GOV, str(evm)))
        self.assertTrue(M._rubric_row_applicable(GOV, str(cosmos)))

    # vendored governance symbols (node_modules) must NOT keep the row alive
    def test_vendored_surface_excluded(self):
        f = self._mk("src/evm/contracts/Vault.sol", "contract Vault {}")
        self._mk("src/evm/node_modules/dep/Gov.sol",
                 "contract Gov { function vote() external {} // governance quorum proposal }")
        self.assertFalse(M._rubric_row_applicable(GOV, str(f)),
                         "vendored node_modules governance must not keep the row applicable")

    # test files must NOT count as surface
    def test_test_files_excluded(self):
        f = self._mk("src/evm/contracts/Vault.sol", "contract Vault {}")
        self._mk("src/evm/test/Gov.t.sol", "contract GovTest { // governance voting proposal }")
        self.assertFalse(M._rubric_row_applicable(GOV, str(f)))

    # fail-open: relative / non-existent path -> never drop
    def test_fail_open_relative_path(self):
        self.assertTrue(M._rubric_row_applicable(GOV, "contracts/Vault.sol"))

    # repo-tree resolution picks the dir under a 'src' segment
    def test_repo_tree_under_src(self):
        f = self._mk("src/nuva-evm-contracts/contracts/X.sol", "contract X {}")
        root = M._repo_tree_for(str(f))
        self.assertEqual(Path(root).name, "nuva-evm-contracts")


if __name__ == "__main__":
    unittest.main()
