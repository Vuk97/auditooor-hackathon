pragma solidity ^0.8.20;

library Math {
    function mulDivDown(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256) {
        return (x * y) / denominator;
    }
}

contract MarginLiquidationCapPositive {
    uint256 internal constant PERCENT = 1e18;

    struct RiskConfig {
        uint256 crLiquidation;
    }

    struct State {
        RiskConfig riskConfig;
    }

    State internal state;

    constructor() {
        state.riskConfig.crLiquidation = 13e17;
    }

    function executeLiquidate(uint256 debtInCollateralToken) public view returns (uint256 collateralRemainderCap) {
        collateralRemainderCap = Math.mulDivDown(
            debtInCollateralToken,
            state.riskConfig.crLiquidation,
            PERCENT
        );
    }
}
