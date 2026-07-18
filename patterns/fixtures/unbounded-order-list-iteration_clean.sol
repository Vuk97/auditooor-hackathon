// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnboundedOrderListIterationClean {
    struct Order { address user; uint256 amount; bool isActive; }
    Order[] public orders;
    uint256 public totalActive;
    uint256 public constant MAX_BATCH = 100;

    function place(uint256 amount) external {
        orders.push(Order(msg.sender, amount, true));
    }

    function settle(uint256 start, uint256 end) external {
        require(end - start <= MAX_BATCH, "batch too large");
        require(end <= orders.length, "out of range");
        for (uint256 i = start; i < end; i++) {
            if (orders[i].isActive) {
                orders[i].isActive = false;
                totalActive++;
            }
        }
    }
}
