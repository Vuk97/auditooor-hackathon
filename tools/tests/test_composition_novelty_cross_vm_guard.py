"""Regression: composition-novelty cross-VM pairing guard (root-caused NUVA 2026-07-14).

The composition-novelty engine paired a Cosmos-Go keeper method (SwapIn @ vault.go)
with EVM Solidity methods (_doDeposit/triggerRedeem) under a shared 'totalshares'
node - a lowercased-symbol match across the language boundary (Cosmos
vault.TotalShares vs an EVM totalSupply). Two ops on different chains/VMs can never
form a real op_a;op_b synchronous sequence, so those 16 rows were false-red
composition obligations. The guard skips a pair when both op languages are known
and differ; same-language and unknown-language pairs are kept (conservative).
"""
import importlib.util
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "composition-novelty-search.py"


def _load():
    spec = importlib.util.spec_from_file_location("cns_guard_test", _TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class _FakeOp:
    def __init__(self, file):
        self.file = file


class TestCompositionNoveltyCrossVMGuard(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_op_lang_mapping(self):
        self.assertEqual(self.m._op_lang(_FakeOp("src/vault/keeper/vault.go")), "go")
        self.assertEqual(self.m._op_lang(_FakeOp("contracts/CrossChainManager.sol")), "evm")
        self.assertEqual(self.m._op_lang(_FakeOp("prime/RedemptionProxy.sol")), "evm")
        self.assertEqual(self.m._op_lang(_FakeOp("src/lib.rs")), "rust")
        self.assertEqual(self.m._op_lang(_FakeOp("")), "")
        self.assertEqual(self.m._op_lang(_FakeOp("Makefile")), "")

    def test_cross_vm_pair_is_skipped(self):
        go = self.m._op_lang(_FakeOp("src/vault/keeper/vault.go"))       # SwapIn
        evm = self.m._op_lang(_FakeOp("contracts/CrossChainManager.sol"))  # _doDeposit
        # the exact guard condition used in analyse(): la and lb and la != lb
        self.assertTrue(go and evm and go != evm,
                        "a Go keeper method and an EVM contract method must be a "
                        "cross-VM pair -> skipped (never a real composition sequence)")

    def test_same_vm_pair_is_kept(self):
        a = self.m._op_lang(_FakeOp("contracts/prime/DedicatedVaultRouter.sol"))
        b = self.m._op_lang(_FakeOp("contracts/prime/RedemptionProxy.sol"))
        self.assertFalse(a and b and a != b,
                         "two EVM Solidity methods are same-VM -> the pair is KEPT")

    def test_unknown_language_pair_is_kept_conservative(self):
        a = self.m._op_lang(_FakeOp("src/vault/keeper/vault.go"))
        b = self.m._op_lang(_FakeOp(""))  # unclassified
        self.assertFalse(a and b and a != b,
                         "an unknown-language op must NOT trigger the skip "
                         "(conservative: never suppress an unclassified pair)")


if __name__ == "__main__":
    unittest.main()
