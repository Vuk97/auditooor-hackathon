# Fixture: Curve-IB-style Vyper pool WITH the @nonreentrant("lock")
# decorator AND checks-effects-interactions ordering on the withdraw path.
# Structurally similar to positive.vy but should NOT fire the
# w22_vy_reentrancy_curve_ib detector.
# @version 0.3.10

balances: public(HashMap[address, uint256])
total_deposits: public(uint256)

@external
@payable
@nonreentrant("lock")
def deposit():
    self.balances[msg.sender] += msg.value
    self.total_deposits += msg.value

# Negative: @nonreentrant guard AND state mutated BEFORE external call.
@external
@nonreentrant("lock")
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount, "insufficient"
    # Effects first.
    self.balances[msg.sender] -= amount
    self.total_deposits -= amount
    # Interactions last.
    raw_call(msg.sender, b"", value=amount)

@view
@external
def get_virtual_price() -> uint256:
    if self.total_deposits == 0:
        return 0
    return self.balance * 10**18 / self.total_deposits
