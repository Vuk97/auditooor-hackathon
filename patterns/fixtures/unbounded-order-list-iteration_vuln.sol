// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnboundedOrderListIterationVuln {
    struct Order { address user; uint256 amount; bool isActive; }
    Order[] public orders;
    uint256 public totalActive;

    function place(uint256 amount) external {
        orders.push(Order(msg.sender, amount, true));
    }

    function settleAll() external {
        uint256 count;
        // VULN: iterates the full orders[] with no bound.
        for (uint256 i = 0; i < orders.length; i++) {
            if (orders[i].isActive) {
                orders[i].isActive = false;
                count++;
            }
        }
        totalActive = count;
    }
}
