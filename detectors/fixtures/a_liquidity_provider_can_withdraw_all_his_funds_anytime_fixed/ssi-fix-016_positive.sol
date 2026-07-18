pragma solidity ^0.8.20;

contract LiquidityProviderWithdrawAnytimePositive {
    uint256 internal providerBalance;
    uint256 internal lastRequestedAmount;

    function seedBalance(uint256 amount) external {
        providerBalance = amount;
    }

    function requestWithdrawal() internal returns (bool) {
        lastRequestedAmount = providerBalance;
        return providerBalance > 0;
    }
}
