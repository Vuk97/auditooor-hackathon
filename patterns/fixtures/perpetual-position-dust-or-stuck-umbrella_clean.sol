// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: CLEAN - demonstrates safe patterns for perpetual-position-dust-or-stuck

// Shape 1: Ceiling division prevents dust positions
contract LiquidationRoundingCeil {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    // SAFE: ceiling division ensures non-zero collateral seized for any non-zero debt
    function computeSeizableCollateral(uint256 debtToRepay, uint256 totalCollateral, uint256 totalDebt)
        internal
        pure
        returns (uint256 seizable)
    {
        // Safe: round UP so even dust positions seize at least 1 wei of collateral
        seizable = (debtToRepay * totalCollateral + totalDebt - 1) / totalDebt;
    }

    function liquidate(address borrower, uint256 debtToRepay) external {
        uint256 seized = computeSeizableCollateral(debtToRepay, collateral[borrower], debt[borrower]);
        require(seized > 0, "dust position");
        collateral[borrower] -= seized;
        debt[borrower] -= debtToRepay;
    }
}

// Shape 2: Capped position list prevents gas exhaustion
contract CappedPositionList {
    uint256 public constant MAX_POSITIONS = 32;
    mapping(address => uint256[]) public positionIds;

    function openPosition(uint256 tokenId) external {
        require(positionIds[msg.sender].length < MAX_POSITIONS, "too many positions");
        positionIds[msg.sender].push(tokenId);
    }

    function liquidate(address account) external returns (uint256 shortfall) {
        uint256[] storage ids = positionIds[account];
        for (uint256 i = 0; i < ids.length; ++i) { // bounded by MAX_POSITIONS
            shortfall += _valuePosition(ids[i]);
        }
    }

    function _valuePosition(uint256 id) internal pure returns (uint256) {
        return id;
    }
}
