// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OrderBookVuln {
    struct Order { uint256 price; uint256 size; address owner; }
    mapping(uint256 => Order) public orders;
    uint256 public floorPrice = 1000;
    uint256 public ceilingPrice = 2000;

    function assertLimitPriceInBounds(uint256 price) internal view {
        require(price >= floorPrice && price <= ceilingPrice, "oob");
    }

    function placeOrder(uint256 id, uint256 price, uint256 size) external {
        assertLimitPriceInBounds(price);
        orders[id] = Order({price: price, size: size, owner: msg.sender});
    }

    /// VULN: amendOrder writes price without calling assertLimitPriceInBounds
    function amendOrder(uint256 id, uint256 newPrice) external {
        require(orders[id].owner == msg.sender, "not owner");
        orders[id].price = newPrice;
    }
}
