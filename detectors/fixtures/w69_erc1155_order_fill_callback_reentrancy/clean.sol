// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC1155Like {
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
}

contract W69Erc1155OrderFillCallbackClean {
    struct Listing {
        address collection;
        address seller;
        uint256 tokenId;
        uint256 amount;
        uint256 filledAmount;
        bool cancelled;
    }

    mapping(bytes32 => Listing) public listings;
    bool private locked;

    event OrderFilled(bytes32 indexed orderId, address indexed buyer, uint256 amount);

    modifier nonReentrant() {
        require(!locked, "locked");
        locked = true;
        _;
        locked = false;
    }

    function fillOrder(bytes32 orderId, uint256 amount) external nonReentrant {
        Listing storage order = listings[orderId];
        require(!order.cancelled, "cancelled");
        uint256 nextFilled = order.filledAmount + amount;
        require(nextFilled <= order.amount, "too much");

        order.filledAmount = nextFilled;
        if (nextFilled == order.amount) {
            order.cancelled = true;
        }

        IERC1155Like(order.collection).safeTransferFrom(
            order.seller,
            msg.sender,
            order.tokenId,
            amount,
            ""
        );
        emit OrderFilled(orderId, msg.sender, amount);
    }
}

