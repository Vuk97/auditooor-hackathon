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

library SwapUtils {
    function getOutputToken(
        bytes32,
        bytes32 swapPath,
        address initialCollateralToken
    ) internal pure returns (address) {
        if (swapPath == bytes32(0)) {
            return initialCollateralToken;
        }
        return address(uint160(uint256(swapPath)));
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

contract PerpPositionKeyCollisionClean {
    using Order for Order.Props;

    bytes32 public dataStore;
    mapping(bytes32 => uint256) public positionLastSrcChainId;

    function _updatePositionLastSrcChainId(
        Order.Props memory order,
        uint256 srcChainId
    ) internal {
        address collateralToken = SwapUtils.getOutputToken(
            dataStore,
            order.swapPath(),
            order.initialCollateralToken()
        );
        bytes32 positionKey = Position.getPositionKey(
            order.account(),
            order.market(),
            collateralToken,
            order.isLong()
        );

        positionLastSrcChainId[positionKey] = srcChainId;
    }

    function recordPosition(Order.Props memory order, uint256 srcChainId) external {
        _updatePositionLastSrcChainId(order, srcChainId);
    }
}
