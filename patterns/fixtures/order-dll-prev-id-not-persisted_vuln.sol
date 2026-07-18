// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OrderBookVuln {
    struct Order { uint256 prevOrderId; uint256 nextOrderId; uint256 price; }
    mapping(uint256 => Order) public orders;
    uint256 public head;

    function placeOrder(uint256 newId, uint256 price) external {
        Order memory memOrder = Order({prevOrderId: 0, nextOrderId: head, price: price});
        memOrder.prevOrderId = head > 0 ? head : 0;
        if (head != 0) orders[head].nextOrderId = newId;
        head = newId;
        // VULN: memOrder never written back; orders[newId] stays zero
    }
}
