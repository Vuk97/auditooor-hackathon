// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LimitOrderCancelVuln {
    struct Order { address maker; uint256 price; bool alive; }
    mapping(uint256 => Order) public orders;
    function cancelOrder(uint256 orderId) external {
        Order storage o = orders[orderId];
        require(o.maker == msg.sender);
        o.alive = false;
    }
}
