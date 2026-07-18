// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OrderbookClean {
    struct Order {
        address maker;
        uint256 quantity;
        uint256 price;
        bool isBuy;
        uint256 timestamp;
    }

    mapping(bytes32 => Order[]) public book;

    function addNewOrder(
        bytes32 pairId,
        uint256 _quantity,
        uint256 _price,
        bool _isBuy
    ) external {
        // CLEAN: timestamp set server-side, not trusted from caller
        book[pairId].push(Order({
            maker: msg.sender,
            quantity: _quantity,
            price: _price,
            isBuy: _isBuy,
            timestamp: block.timestamp
        }));
    }
}
