// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MatchingEngineAmendInvariantGapVuln {
    struct Order { address owner; uint256 price; uint256 size; uint256 filled; }
    mapping(uint256 => Order) public orders;
    uint256 public floorPrice = 1000;
    uint256 public ceilingPrice = 2000;
    uint256 public maxLimitsPerTx = 10;
    mapping(address => uint256) internal _txCount;

    function assertLimitPriceInBounds(uint256 price) internal view {
        require(price >= floorPrice && price <= ceilingPrice, "oob");
    }

    function placeOrder(uint256 id, uint256 price, uint256 size) external {
        _txCount[msg.sender] += 1;
        require(_txCount[msg.sender] <= maxLimitsPerTx, "too many");
        assertLimitPriceInBounds(price);
        orders[id] = Order({owner: msg.sender, price: price, size: size, filled: 0});
    }

    function amendOrder(uint256 id, uint256 newPrice, uint256 newSize) external {
        Order storage o = orders[id];
        require(o.owner == msg.sender, "owner");
        o.price = newPrice;
        o.size = newSize;
        o.filled = 0;
    }
}
