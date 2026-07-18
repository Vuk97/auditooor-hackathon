# @version ^0.3.0

treasury: public(address)

@external
def sweep(amount: uint256):
    send(self.treasury, amount)   # <-- vyper transfer-stipend
