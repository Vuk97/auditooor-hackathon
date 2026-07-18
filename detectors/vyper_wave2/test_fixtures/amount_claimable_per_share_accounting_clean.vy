# fixture: negative — amount_claimable_per_share_accounting (CLEAN)
# Fix: deposit initializes amount_claimed baseline to avoid stale-accumulator bug.

# @version ^0.3.10

amount_claimable_per_share: uint256
positions: HashMap[address, uint256]
amount_claimed: HashMap[address, uint256]

@external
def deposit(amount: uint256):
    # Fix: snapshot the current accumulator so new depositor starts from now
    self.amount_claimed[msg.sender] = self.amount_claimable_per_share * (self.positions[msg.sender] + amount) / 10**18
    self.positions[msg.sender] += amount

@external
def distribute_yield(total: uint256, total_supply: uint256):
    self.amount_claimable_per_share += total * 10**18 / total_supply

@external
def claim() -> uint256:
    claimable: uint256 = (self.amount_claimable_per_share * self.positions[msg.sender] / 10**18) - self.amount_claimed[msg.sender]
    self.amount_claimed[msg.sender] = self.amount_claimable_per_share * self.positions[msg.sender] / 10**18
    return claimable
