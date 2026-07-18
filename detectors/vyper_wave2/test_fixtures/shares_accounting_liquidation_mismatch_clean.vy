# fixture: negative — shares_accounting_liquidation_mismatch (CLEAN)
# Fix: liquidation only uses one share-accounting source (no cross-checkpoint split).

# @version ^0.3.10

vault_shares: HashMap[address, uint256]
debt: HashMap[address, uint256]

@external
def liquidate(user: address):
    # Clean: only uses one class of share accounting
    user_shares: uint256 = self.vault_shares[user]
    user_debt: uint256 = self.debt[user]
    assert user_debt > 0, "no debt"
    self.vault_shares[user] = 0
    self.debt[user] = 0

@external
def borrow(user: address, amount: uint256):
    self.debt[user] += amount
