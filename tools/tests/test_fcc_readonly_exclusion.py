"""Read-only (view/getter/pure) exclusion from the per-function attack-coverage
denominator (operator-requested methodology 2026-06-22). A function that cannot mutate
state or move funds has no per-function attack surface, so demanding a mutation-verified
harness for it is wrong and inflates the denominator.

SAFETY (the #1 sin is dropping a real mutator): value-movers MUST stay KEPT. Solidity
view/pure is compiler-guaranteed; Go getters are excluded ONLY when the body has zero
state-write/fund-move tokens (any write token -> KEEP).
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("fcc_ro", str(_TOOLS / "function-coverage-completeness.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fcc_ro"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestReadOnlyExclusion(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_value_movers_kept(self):
        cases = [
            ("MintCoins", "func (k BaseKeeper) MintCoins(ctx, m, amt) error {", "go", "k.setSupply(ctx, s.Add(amt))"),
            ("BurnCoins", "func (k BaseKeeper) BurnCoins(ctx, m, amt) error {", "go", "k.subUnlockedCoins(addr, amt)"),
            ("SendCoins", "func (k BaseSendKeeper) SendCoins(ctx,f,t,a) error {", "go", "k.addCoins(t, a)"),
            ("unmigrate", "function unmigrate(uint256 amount) external {", "solidity", "matic.safeTransfer(msg.sender, amount);"),
            ("bridgeAsset", "function bridgeAsset(...) public payable {", "solidity", "token.safeTransferFrom(...);"),
        ]
        for name, sig, lang, body in cases:
            self.assertFalse(self.m._is_nonattack_boilerplate(name, sig, lang, body),
                             f"value-mover {name} must be KEPT (not excluded)")

    def test_readonly_excluded(self):
        # Solidity view/pure: compiler-guaranteed read-only
        self.assertTrue(self.m._is_nonattack_boilerplate(
            "balanceOf", "function balanceOf(address a) external view returns (uint256) {", "solidity", "return _b[a];"))
        self.assertTrue(self.m._is_nonattack_boilerplate(
            "exp2", "function exp2(uint256 x) internal pure returns (uint256) {", "solidity", "return r;"))
        # Go getter with zero state-write tokens
        self.assertTrue(self.m._is_nonattack_boilerplate(
            "GetBalance", "func (k Keeper) GetBalance(ctx, a, d) sdk.Coin {", "go", "return k.getBalance(ctx,a,d)"))

    def test_go_getter_with_write_token_kept(self):
        # a Get* that ALSO writes state must be KEPT (conservative: any write token wins)
        self.assertFalse(self.m._is_nonattack_boilerplate(
            "GetOrCreateAccount", "func (k Keeper) GetOrCreateAccount(ctx, a) Account {", "go",
            "acc := New(); k.SetAccount(ctx, acc); return acc"))

    def test_non_getter_go_not_excluded(self):
        # a non-getter-named go fn is never read-only-excluded (no compiler guarantee)
        self.assertFalse(self.m._is_nonattack_boilerplate(
            "processWithdrawal", "func (k Keeper) processWithdrawal(ctx, a) error {", "go", "return nil"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
