// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISortedTroves {
    function getLast() external view returns (address);
}

interface ITroveManager {
    function getCurrentICR(address borrower) external view returns (uint256);
}

contract StabilityPool {
    uint256 internal constant MCR = 110e16;
    ISortedTroves public sortedTroves;
    ITroveManager public troveManager;

    function _requireNoUnderCollateralizedTroves() internal view {
        address tail = sortedTroves.getLast();
        uint256 icr = troveManager.getCurrentICR(tail);
        require(icr >= MCR, "undercollateralized trove exists");
    }
}
