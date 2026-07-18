// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IPerpVenue {
    function addCollateral(uint256 positionId, uint256 amount) external;
    function removeCollateral(uint256 positionId, uint256 amount) external;
}

contract KangarooVaultPositive {
    struct PositionData {
        uint256 totalCollateral;
    }

    IPerpVenue public immutable EXCHANGE;
    PositionData public positionData;
    uint256 public positionId;
    uint256 public usedFunds;

    constructor(IPerpVenue venue) {
        EXCHANGE = venue;
    }

    function addCollateral(uint256 amount) external {
        EXCHANGE.addCollateral(positionId, amount);
        positionData.totalCollateral += amount;
        usedFunds += amount;
    }

    function removeCollateral(uint256 amount) external {
        require(amount <= positionData.totalCollateral, "too much");

        positionData.totalCollateral -= amount;
        usedFunds -= amount;
    }
}
