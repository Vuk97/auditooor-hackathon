// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: vulnerable - demonstrates the perpetual-position-dust-or-stuck umbrella pattern
// This fixture covers the cross-class recall gap: a single broader detector that
// fires on all three perpetual-position-stuck shapes:
// 1. Rounding dust making position unliquidatable (fx-silo shape)
// 2. Uncapped position loop gas exhaustion (options shape)
// 3. Vault exit path broken post-liquidation (vault-exit shape)

// Shape 1: Floor division in liquidation leaves dust position permanently stuck
contract LiquidationRoundingDust {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    // VULNERABLE: floor division returns 0 for tiny positions, leaving them unliquidatable
    function computeSeizableCollateral(uint256 debtToRepay, uint256 totalCollateral, uint256 totalDebt)
        internal
        pure
        returns (uint256 seizable)
    {
        seizable = debtToRepay * totalCollateral / totalDebt; // floor - returns 0 for dust
    }

    function liquidate(address borrower, uint256 debtToRepay) external {
        uint256 seized = computeSeizableCollateral(debtToRepay, collateral[borrower], debt[borrower]);
        // If seized == 0 due to floor, position is permanently stuck
        require(seized > 0, "dust position");
        collateral[borrower] -= seized;
        debt[borrower] -= debtToRepay;
    }
}

// Shape 2: Uncapped position list makes account unliquidatable via gas exhaustion
contract UncappedPositionList {
    mapping(address => uint256[]) public positionIds;

    function openPosition(uint256 tokenId) external {
        positionIds[msg.sender].push(tokenId); // no cap check
    }

    function liquidate(address account) external returns (uint256 shortfall) {
        uint256[] storage ids = positionIds[account];
        for (uint256 i = 0; i < ids.length; ++i) { // unbounded loop
            shortfall += _valuePosition(ids[i]);
        }
        // gas exhausted before completion => position permanently stuck
    }

    function _valuePosition(uint256 id) internal pure returns (uint256) {
        return id; // placeholder
    }
}
