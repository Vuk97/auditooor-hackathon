# fixture: positive — shares_accounting_liquidation_mismatch (VULNERABLE)
# Bug: liquidate references both total_shares and claimable_yield
# from different checkpoints — causes liquidation to fail.

# @version ^0.3.10

total_shares: uint256
vault_shares: HashMap[address, uint256]
claimable_yield: HashMap[address, uint256]
yield_snapshot: uint256  # snapshotted at different time than total_shares

@external
def liquidate(user: address):
    # Bug: total_shares snapshotted at one time, claimable_yield at another
    shares: uint256 = self.total_shares
    yield_amount: uint256 = self.claimable_yield[user]
    # These two values are from inconsistent checkpoints — liquidation fails
    # when yield_amount exceeds what shares would indicate
    assert yield_amount <= shares, "inconsistent state"
    self.vault_shares[user] = 0

@external
def checkpoint_yield(user: address, amount: uint256):
    self.claimable_yield[user] = amount
