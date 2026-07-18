// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MarketVuln {
    struct Position { bool forSale; uint256 price; address owner; }
    mapping(uint256 => Position) public positions;

    function sell(uint256 id, uint256 newPrice) external {
        Position storage p = positions[id];
        require(p.forSale, "not listed");
        p.price = newPrice;
    }

    /// VULN: compensate does not require forSale == true
    function compensate(uint256 id, address to) external {
        Position storage p = positions[id];
        // settle using listing-path pricing
        p.owner = to;
        p.forSale = false;
    }
}
