pragma solidity ^0.8.20;

library Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract MarginLiquidationRewardPositive {
    IERC20 public collateralToken;
    IERC20 public debtToken;
    uint256 internal constant PERCENT = 1e18;
    uint256 public liquidatorRewardPercent = 5e16;

    struct Loan {
        uint256 assignedCollateral;
        uint256 debtInCollateralToken;
        uint256 debtFutureValue;
    }

    function executeLiquidate(Loan memory loan, address liquidator) public returns (uint256 liquidatorReward) {
        uint256 collateralSurplus = loan.assignedCollateral - loan.debtInCollateralToken;
        uint256 debtFutureValue = loan.debtFutureValue;
        liquidatorReward = Math.min(collateralSurplus, debtFutureValue * liquidatorRewardPercent / PERCENT);
        collateralToken.transfer(liquidator, liquidatorReward);
    }
}
