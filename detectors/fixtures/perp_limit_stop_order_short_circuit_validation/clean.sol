pragma solidity ^0.8.20;

contract PerpLimitStopOrderRouterClean {
    enum OrderType {
        MARKET,
        LIMIT,
        STOP,
        LIMIT_STOP
    }

    struct ConditionalOrder {
        OrderType orderType;
        uint256 limitPrice;
        uint256 stopPrice;
        bool isLong;
    }

    error InvalidLimitStopOrder();

    function executeOrder(
        ConditionalOrder calldata order,
        uint256 fillPrice,
        uint256 oraclePrice
    ) external {
        if (order.orderType == OrderType.LIMIT_STOP && order.limitPrice > 0 && order.stopPrice > 0) {
            if (!validateLimitPrice(order, fillPrice) || !validateStopPrice(order, oraclePrice)) {
                revert InvalidLimitStopOrder();
            }
        }

        _settle(order, fillPrice, oraclePrice);
    }

    function validateLimitPrice(ConditionalOrder calldata order, uint256 fillPrice) internal pure returns (bool) {
        if (order.isLong) {
            return fillPrice <= order.limitPrice;
        }
        return fillPrice >= order.limitPrice;
    }

    function validateStopPrice(ConditionalOrder calldata order, uint256 oraclePrice) internal pure returns (bool) {
        if (order.isLong) {
            return oraclePrice >= order.stopPrice;
        }
        return oraclePrice <= order.stopPrice;
    }

    function _settle(
        ConditionalOrder calldata order,
        uint256 fillPrice,
        uint256 oraclePrice
    ) internal pure {
        order;
        fillPrice;
        oraclePrice;
    }
}
