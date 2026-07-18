pragma solidity ^0.8.20;

library Order {
    struct Flags {
        bool isLong;
        bool shouldUnwrapNativeToken;
    }
}

interface IPosition {
    function isLong() external view returns (bool);
}

contract LiquidationUtilsClean {
    function createLiquidationOrder(IPosition position)
        external
        view
        returns (Order.Flags memory flags)
    {
        uint256 srcChainId = 42161;
        bool shouldUnwrapNativeToken = srcChainId == 0 ? true : false;
        flags = Order.Flags(position.isLong(), shouldUnwrapNativeToken);
        if (shouldUnwrapNativeToken) {
            return flags;
        }
        return flags;
    }
}
