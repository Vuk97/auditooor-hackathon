// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MatcherVuln {
    struct Order { address maker; uint256 size; uint256 filled; }
    mapping(uint256 => Order) public orders;

    function amendOrder(uint256 id, uint256 newSize) external {
        Order storage o = orders[id];
        require(o.maker == msg.sender, "owner");
        // VULN: overwrites size, resets filled, ignores previous fills
        o.size = newSize;
        o.filled = 0;
    }
}
