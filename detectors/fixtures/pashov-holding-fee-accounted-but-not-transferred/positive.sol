pragma solidity ^0.8.20;

contract FeeVault {
    uint256 public received;

    function sendToVault(uint256 amount) external {
        received += amount;
    }
}

contract PositiveHoldingFeeAccountedButNotTransferred {
    FeeVault internal immutable vault;
    uint256 public realizedTradingFeesCollateral;

    constructor(FeeVault feeVault) {
        vault = feeVault;
    }

    function realizeHoldingFeesOnOpenTrade(
        uint256 holdingFeesCollateral,
        uint256 availableCollateralInDiamond
    ) external {
        uint256 amountSentToVault;
        if (holdingFeesCollateral > availableCollateralInDiamond) {
            amountSentToVault = availableCollateralInDiamond;
        } else {
            amountSentToVault = holdingFeesCollateral;
        }

        vault.sendToVault(amountSentToVault);
        realizedTradingFeesCollateral += holdingFeesCollateral;
    }
}
