pragma solidity ^0.8.20;

contract LiquidityProviderWithdrawAnytimeClean {
    uint256 internal providerBalance;
    uint256 internal lockedBalance;

    function seedBalance(uint256 amount) external {
        providerBalance = amount;
    }

    function _updateWithdrawalLock() internal {
        lockedBalance = providerBalance;
    }

    function requestWithdrawal() internal returns (bool) {
        _updateWithdrawalLock();
        return lockedBalance > 0;
    }
}
