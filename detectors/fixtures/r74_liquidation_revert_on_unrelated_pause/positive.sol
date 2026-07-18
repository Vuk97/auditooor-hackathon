// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MultiAssetLiquidationPositive {
    struct ReserveState {
        bool paused;
        uint256 price;
        uint256 collateralBalance;
        uint256 debtBalance;
    }

    address[] public assets;
    mapping(address => ReserveState) public reserves;
    mapping(address => address[]) public userReserves;
    uint256 public liquidationCount;

    function addUserReserve(address user, address asset, uint256 price, uint256 collateral, uint256 debt) external {
        if (reserves[asset].price == 0) {
            assets.push(asset);
        }
        reserves[asset] = ReserveState({
            paused: false,
            price: price,
            collateralBalance: collateral,
            debtBalance: debt
        });
        userReserves[user].push(asset);
    }

    function pauseReserve(address asset) external {
        reserves[asset].paused = true;
    }

    function liquidate(address borrower, address repayAsset, uint256 repayAmount) external returns (uint256 seizedValue) {
        address[] memory borrowerAssets = userReserves[borrower];
        uint256 totalCollateral;
        uint256 totalDebt;

        for (uint256 i = 0; i < borrowerAssets.length; ++i) {
            address asset = borrowerAssets[i];
            ReserveState memory reserve = _readReserve(asset);
            totalCollateral += reserve.collateralBalance * reserve.price;
            totalDebt += reserve.debtBalance * reserve.price;
        }

        require(totalDebt > totalCollateral, "healthy");
        require(repayAsset != address(0), "repay asset");
        liquidationCount += 1;
        seizedValue = repayAmount * 105 / 100;
    }

    function _readReserve(address asset) internal view returns (ReserveState memory reserve) {
        reserve = reserves[asset];
        require(!reserve.paused, "reserve paused");
        require(reserve.price != 0, "oracle unavailable");
    }
}
