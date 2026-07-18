# fixture: negative — flashloan_missing_repay_check (CLEAN)
# Fix: flash_loan asserts balance_after >= balance_before + fee.

# @version ^0.3.10

token: address
FEE_BPS: constant(uint256) = 30  # 0.3%

@external
def flash_loan(receiver: address, amount: uint256):
    balance_before: uint256 = ERC20(self.token).balanceOf(self)
    fee: uint256 = amount * FEE_BPS / 10000
    ERC20(self.token).transfer(receiver, amount)
    IFlashLoanReceiver(receiver).execute(amount)
    # Fix: assert repayment including fee
    assert ERC20(self.token).balanceOf(self) >= balance_before + fee, "flash loan not repaid"

@external
def get_balance() -> uint256:
    return ERC20(self.token).balanceOf(self)
