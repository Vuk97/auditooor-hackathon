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

contract LiquidationUtilsPositive {
    function createLiquidationOrder(IPosition position)
        external
        view
        returns (Order.Flags memory flags)
    {
        bool shouldUnwrapNativeToken = true;
        flags = Order.Flags(position.isLong(), true);
        if (shouldUnwrapNativeToken) {
            return flags;
        }
        return flags;
    }
}
