// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

enum InterestRateMode {
    NONE,
    STABLE,
    VARIABLE
}

library WadRayMathLike {
    function percentMul(uint256 value, uint256 percentage) internal pure returns (uint256) {
        return value * percentage / 10_000;
    }
}

contract AaveFlashloanPremiumOnDebtBearingLegPositive {
    using WadRayMathLike for uint256;

    uint256 public flashloanPremiumTotal = 9;
    uint256[] public reportedPremiums;
    uint256 public lastDebtOpened;

    function flashLoan(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata interestRateModes
    ) external {
        executeFlashLoan(assets, amounts, interestRateModes);
    }

    function executeFlashLoan(
        address[] memory,
        uint256[] memory amounts,
        uint256[] memory interestRateModes
    ) internal {
        uint256[] memory totalPremiums = new uint256[](amounts.length);

        for (uint256 i = 0; i < amounts.length; ++i) {
            uint256 amount = amounts[i];
            uint256 interestRateMode = interestRateModes[i];

            totalPremiums[i] = amount.percentMul(flashloanPremiumTotal);

            if (interestRateMode == uint256(InterestRateMode.NONE)) {
                reportedPremiums.push(totalPremiums[i]);
            } else {
                lastDebtOpened += amount;
            }
        }
    }
}
