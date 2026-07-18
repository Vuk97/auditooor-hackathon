# fixture: positive — flashloan_missing_repay_check (VULNERABLE)
# Bug: flash_loan invokes callback but does not assert repayment.

# @version ^0.3.10

token: address

@external
def flash_loan(receiver: address, amount: uint256):
    balance_before: uint256 = ERC20(self.token).balanceOf(self)
    ERC20(self.token).transfer(receiver, amount)
    # Invoke callback — attacker controls receiver
    IFlashLoanReceiver(receiver).execute(amount)
    # Bug: no assertion that loan + fee was repaid
    # An attacker can simply not repay and drain the pool

@external
def get_balance() -> uint256:
    return ERC20(self.token).balanceOf(self)
