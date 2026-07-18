pragma solidity ^0.8.20;

library Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract MarginLiquidationRewardClean {
    IERC20 public collateralToken;
    IERC20 public debtToken;
    uint256 internal constant PERCENT = 1e18;
    uint256 public liquidatorRewardPercent = 5e16;
    uint256 public oraclePrice = 2_000e18;

    struct Loan {
        uint256 assignedCollateral;
        uint256 debtInCollateralToken;
        uint256 debtFutureValue;
    }

    function executeLiquidate(Loan memory loan, address liquidator) public returns (uint256 liquidatorReward) {
        uint256 collateralSurplus = loan.assignedCollateral - loan.debtInCollateralToken;
        uint256 debtFutureValue = loan.debtFutureValue;
        uint256 debtRewardInCollateral = convertToCollateral(debtFutureValue * liquidatorRewardPercent / PERCENT);
        liquidatorReward = Math.min(collateralSurplus, debtRewardInCollateral);
        collateralToken.transfer(liquidator, liquidatorReward);
    }

    function convertToCollateral(uint256 debtAmount) internal view returns (uint256) {
        return debtAmount * 1e18 / oraclePrice;
    }
}
