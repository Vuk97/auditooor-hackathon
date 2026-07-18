// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MatcherClean {
    struct Order { address maker; uint256 size; uint256 filled; }
    mapping(uint256 => Order) public orders;

    function amendOrder(uint256 id, uint256 newSize) external {
        Order storage o = orders[id];
        require(o.maker == msg.sender, "owner");
        require(newSize >= o.filled, "below-filled");
        o.size = newSize;
        // filled preserved
    }
}
