pragma solidity ^0.8.20;

library ERC20 {
    function safeTransferFrom(address token, address from, address to, uint256 amount) internal pure {
        token;
        from;
        to;
        amount;
    }
}

contract LiquidationTransferfromMarketNotLiquidatorClean {
    struct QuotePool {
        address token;
    }

    struct PairStatus {
        QuotePool quotePool;
    }

    PairStatus internal pairStatus;

    function executeLiquidate(int256 remainingMargin) external {
        if (remainingMargin < 0) {
            ERC20.safeTransferFrom(
                pairStatus.quotePool.token,
                msg.sender,
                address(this),
                uint256(-remainingMargin)
            );
        }
    }
}
