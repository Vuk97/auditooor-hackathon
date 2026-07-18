"""Loop-fix 2026-06-22: guard-negative-space-analyzer._is_vendored used scope_exclusion.is_oos,
which treats cosmos-sdk/cometbft/wasmd as vendored NAME markers and dropped the in-scope FORK
repos that ARE the audit target -> cosmos-sdk (435) + cometbft (72) guards = 0. Switching to
is_oos_DIR (directory-shape only) keeps the fork production source while still dropping
test/generated/vendored-DIR pollution. bor/Solidity unaffected (not name-markers).
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("gns_fs", str(_TOOLS / "guard-negative-space-analyzer.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gns_fs"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestForkScopeInScope(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_inscope_fork_source_kept(self):
        # the audit target forks must NOT be dropped as vendored-name
        for rel in ("src/cosmos-sdk/x/bank/keeper/keeper.go",
                    "src/cosmos-sdk/x/staking/keeper/delegation.go",
                    "src/cometbft/consensus/state.go",
                    "src/bor/consensus/bor/bor.go",
                    "src/pos-contracts/contracts/staking/stakeManager/StakeManager.sol"):
            self.assertFalse(self.m._is_vendored(rel), f"in-scope fork source dropped: {rel}")

    def test_fork_test_and_generated_still_dropped(self):
        # test/generated/vendored-DIR pollution inside the fork is still OOS
        for rel in ("src/cosmos-sdk/x/bank/keeper/keeper_test.go",
                    "src/cosmos-sdk/x/bank/types/bank.pb.go",
                    "src/cometbft/types/block_test.go",
                    "src/bor/accounts/abi/bind/backends/simulated.go",
                    "src/cosmos-sdk/vendor/github.com/foo/bar.go"):
            self.assertTrue(self.m._is_vendored(rel), f"OOS pollution NOT dropped: {rel}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
