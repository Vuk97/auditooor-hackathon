# fixture: negative — staker_balance_rebase_early_exit (CLEAN)
# Fix: unstake calls _calculate_values before reading balance.

# @version ^0.3.10

balances: HashMap[address, uint256]
pending_rebase: uint256

@internal
def _calculate_values():
    # lazy rebase application — updates balances based on pending_rebase
    pass

@external
def unstake(amount: uint256):
    # Fix: apply lazy rebase before reading balance
    self._calculate_values()
    assert self.balances[msg.sender] >= amount, "insufficient balance"
    self.balances[msg.sender] -= amount

@external
def trigger_rebase(delta: uint256):
    self.pending_rebase += delta
