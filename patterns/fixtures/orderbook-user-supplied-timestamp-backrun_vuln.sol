// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OrderbookVuln {
    struct Order {
        address maker;
        uint256 quantity;
        uint256 price;
        bool isBuy;
        uint256 timestamp;
    }

    mapping(bytes32 => Order[]) public book;

    // VULN: accepts caller-supplied _timestamp and stores it
    function addNewOrder(
        bytes32 pairId,
        uint256 _quantity,
        uint256 _price,
        bool _isBuy,
        uint256 _timestamp
    ) external {
        book[pairId].push(Order({
            maker: msg.sender,
            quantity: _quantity,
            price: _price,
            isBuy: _isBuy,
            timestamp: _timestamp
        }));
    }
}
