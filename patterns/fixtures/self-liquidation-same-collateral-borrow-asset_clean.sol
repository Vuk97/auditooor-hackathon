// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract SelfLiquidationSameAssetClean {
    mapping(address => mapping(address => uint256)) public supplyBalance;
    mapping(address => mapping(address => uint256)) public accountBorrows;

    uint256 public constant LIQUIDATION_BONUS_BPS = 800;

    // CLEAN: explicit guard forbids degenerate same-asset liquidation.
    // Detector does NOT fire because the negative regex matches.
    function liquidateBorrow(
        address borrower,
        address borrowedAsset,
        address collateralAsset,
        uint256 repayAmount
    ) external returns (uint256) {
        require(collateralAsset != borrowedAsset, "same-asset liquidation");
        IERC20(borrowedAsset).transferFrom(msg.sender, address(this), repayAmount);
        accountBorrows[borrower][borrowedAsset] -= repayAmount;
        uint256 seize = repayAmount + (repayAmount * LIQUIDATION_BONUS_BPS) / 10_000;
        supplyBalance[borrower][collateralAsset] -= seize;
        IERC20(collateralAsset).transfer(msg.sender, seize);
        return 0;
    }
}
