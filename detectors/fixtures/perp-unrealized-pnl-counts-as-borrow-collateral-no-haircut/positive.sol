pragma solidity ^0.8.20;

contract PerpUnrealizedPnlCollateralPositive {
    struct Position {
        uint256 collateral;
        uint256 entryPrice;
        uint256 size;
    }

    mapping(address => Position) internal positions;
    uint256 public lastBorrowable;

    function seedPosition(
        address account,
        uint256 collateral,
        uint256 entryPrice,
        uint256 size
    ) external {
        positions[account] = Position(collateral, entryPrice, size);
    }

    function getMaxBorrow(address account, uint256 markPrice) external returns (uint256) {
        Position storage position = positions[account];
        uint256 unrealizedPnl = (markPrice - position.entryPrice) * position.size;
        uint256 borrowable = position.collateral + unrealizedPnl;
        lastBorrowable = borrowable;
        return borrowable;
    }
}
