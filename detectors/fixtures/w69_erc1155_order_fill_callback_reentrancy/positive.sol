// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC1155Like {
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
}

contract W69Erc1155OrderFillCallbackPositive {
    struct Listing {
        address collection;
        address seller;
        uint256 tokenId;
        uint256 amount;
        uint256 filledAmount;
        bool cancelled;
    }

    mapping(bytes32 => Listing) public listings;

    event OrderFilled(bytes32 indexed orderId, address indexed buyer, uint256 amount);

    function fillOrder(bytes32 orderId, uint256 amount) external {
        Listing storage order = listings[orderId];
        require(!order.cancelled, "cancelled");
        require(order.filledAmount + amount <= order.amount, "too much");

        IERC1155Like(order.collection).safeTransferFrom(
            order.seller,
            msg.sender,
            order.tokenId,
            amount,
            ""
        );

        order.filledAmount += amount;
        if (order.filledAmount == order.amount) {
            order.cancelled = true;
        }
        emit OrderFilled(orderId, msg.sender, amount);
    }
}

