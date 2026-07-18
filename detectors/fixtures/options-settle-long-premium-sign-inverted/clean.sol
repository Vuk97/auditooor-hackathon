// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ICollateralTracker {
    function exercise(
        address account,
        int256 token0Delta,
        int256 token1Delta,
        int256 feeDelta,
        int256 collateralDelta
    ) external;
}

contract OptionPremiumSettlementEngine {
    ICollateralTracker public immutable s_collateralToken0;
    mapping(bytes32 => int256) public premiumOwed;

    constructor(ICollateralTracker collateralToken0) {
        s_collateralToken0 = collateralToken0;
    }

    function seedPremium(address account, uint256 tokenId, uint256 legIndex, int256 premium) external {
        premiumOwed[keccak256(abi.encode(account, tokenId, legIndex))] = premium;
    }

    function settleLongPremium(address longOwner, uint256 tokenId, uint256 legIndex) external {
        bytes32 key = keccak256(abi.encode(longOwner, tokenId, legIndex));
        int256 realizedPremia = premiumOwed[key];
        if (realizedPremia <= 0) {
            return;
        }

        premiumOwed[key] = 0;
        s_collateralToken0.exercise(longOwner, 0, 0, 0, -realizedPremia);
    }
}
