// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LimitOrderCancelClean {
    struct Order { address maker; uint256 price; bool alive; bool filling; }
    mapping(uint256 => Order) public orders;
    function cancelOrder(uint256 orderId) external {
        Order storage o = orders[orderId];
        require(o.maker == msg.sender);
        require(!o.filling, "fillInProgress");
        o.alive = false;
    }
}
