# fixture: positive — amount_claimable_per_share_accounting (VULNERABLE)
# Bug: deposit does not initialize the per-position amount_claimed baseline
# while amount_claimable_per_share is in use.

# @version ^0.3.10

amount_claimable_per_share: uint256
positions: HashMap[address, uint256]  # amount deposited
amount_claimed: HashMap[address, uint256]

@external
def deposit(amount: uint256):
    # Bug: amount_claimable_per_share may be non-zero at this point,
    # but amount_claimed[msg.sender] is never set here.
    # New depositor starts at amount_claimed=0, stealing accumulated yield.
    self.positions[msg.sender] += amount

@external
def distribute_yield(total: uint256, total_supply: uint256):
    self.amount_claimable_per_share += total * 10**18 / total_supply

@external
def claim() -> uint256:
    claimable: uint256 = (self.amount_claimable_per_share * self.positions[msg.sender] / 10**18) - self.amount_claimed[msg.sender]
    self.amount_claimed[msg.sender] = self.amount_claimable_per_share * self.positions[msg.sender] / 10**18
    return claimable
