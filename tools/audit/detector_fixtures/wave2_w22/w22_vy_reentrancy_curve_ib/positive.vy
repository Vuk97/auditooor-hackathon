# Fixture: Curve-IB-style Vyper pool with the @nonreentrant decorator
# REMOVED on a withdraw path that performs an external raw_call before
# state mutation. Mirrors the audit-pin shape in the re-entrancy preview
# JSONL (Curve IB / Curve stablecoin Vyper variants).
#
# Detector w22_vy_reentrancy_curve_ib should fire on this file.
# @version 0.3.10

balances: public(HashMap[address, uint256])
total_deposits: public(uint256)

@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value
    self.total_deposits += msg.value

# Positive: NO @nonreentrant decorator AND raw_call before state mutation.
@external
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount, "insufficient"
    # EXTERNAL CALL FIRST -- read-only and balance-drain re-entrancy paths.
    raw_call(msg.sender, b"", value=amount)
    # State updated AFTER external call.
    self.balances[msg.sender] -= amount
    self.total_deposits -= amount

@view
@external
def get_virtual_price() -> uint256:
    if self.total_deposits == 0:
        return 0
    return self.balance * 10**18 / self.total_deposits
