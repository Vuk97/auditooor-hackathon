// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library Order {
    struct Props {
        address owner;
        address marketToken;
        address collateralToken;
        bool longSide;
        bytes32 swapRoute;
    }

    function account(Props memory self) internal pure returns (address) {
        return self.owner;
    }

    function market(Props memory self) internal pure returns (address) {
        return self.marketToken;
    }

    function initialCollateralToken(Props memory self) internal pure returns (address) {
        return self.collateralToken;
    }

    function isLong(Props memory self) internal pure returns (bool) {
        return self.longSide;
    }

    function swapPath(Props memory self) internal pure returns (bytes32) {
        return self.swapRoute;
    }
}

library Position {
    function getPositionKey(
        address account,
        address market,
        address collateralToken,
        bool isLong
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, market, collateralToken, isLong));
    }
}

contract PerpPositionKeyCollisionPositive {
    using Order for Order.Props;

    mapping(bytes32 => uint256) public positionLastSrcChainId;

    function _updatePositionLastSrcChainId(
        Order.Props memory order,
        uint256 srcChainId
    ) internal {
        bytes32 positionKey = Position.getPositionKey(
            order.account(),
            order.market(),
            order.initialCollateralToken(),
            order.isLong()
        );

        if (order.swapPath() != bytes32(0)) {
            positionLastSrcChainId[positionKey] = srcChainId;
        }
    }

    function recordPosition(Order.Props memory order, uint256 srcChainId) external {
        _updatePositionLastSrcChainId(order, srcChainId);
    }
}
