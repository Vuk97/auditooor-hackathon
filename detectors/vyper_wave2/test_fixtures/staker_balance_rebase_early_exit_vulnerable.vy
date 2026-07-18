# fixture: positive — staker_balance_rebase_early_exit (VULNERABLE)
# Bug: unstake reads balance directly without calling _calculate_values first.

# @version ^0.3.10

balances: HashMap[address, uint256]
pending_rebase: uint256

@internal
def _calculate_values():
    # lazy rebase application — updates balances based on pending_rebase
    pass

@external
def unstake(amount: uint256):
    # Bug: reads self.balances without calling _calculate_values first.
    # A staker can exit before a positive rebase updates their balance.
    assert self.balances[msg.sender] >= amount, "insufficient balance"
    self.balances[msg.sender] -= amount

@external
def trigger_rebase(delta: uint256):
    self.pending_rebase += delta
