pragma solidity ^0.8.20;

contract PerpUnrealizedPnlCollateralClean {
    struct Position {
        uint256 collateral;
        uint256 entryPrice;
        uint256 size;
    }

    uint256 internal constant pnlHaircutBps = 5_000;

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
        uint256 effectivePnl = (unrealizedPnl * (10_000 - pnlHaircutBps)) / 10_000;
        uint256 borrowable = position.collateral + effectivePnl;
        lastBorrowable = borrowable;
        return borrowable;
    }
}
