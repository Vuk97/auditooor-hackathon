// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InsufficientEquilibriumFeePoolCanCauseSwapsToFailPositive {
    struct SwapObj {
        uint256 amountSD;
        uint256 eqReward;
    }

    uint256 public eqFeePool;
    bool public stopSwap;

    function seedEqFeePool(uint256 newEqFeePool) external {
        eqFeePool = newEqFeePool;
    }

    function _computeEqReward(uint256 amountSD) internal pure returns (uint256) {
        return (amountSD / 2) + 1;
    }

    function swap(uint256 amountSD) external returns (uint256) {
        require(!stopSwap, "swap stopped");

        SwapObj memory s;
        s.amountSD = amountSD;
        s.eqReward = _computeEqReward(amountSD);

        eqFeePool = eqFeePool - s.eqReward;
        return s.eqReward;
    }
}
