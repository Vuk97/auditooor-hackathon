// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CLOBVuln {
    struct Order { uint256 price; uint256 size; }
    mapping(uint256 => Order) public orders;
    uint256 public maxLimitsPerTx = 10;
    uint256 internal _txCount;

    function placeOrder(uint256 id, uint256 price, uint256 size) external {
        _txCount += 1;
        require(_txCount <= maxLimitsPerTx, "cap");
        orders[id] = Order({price: price, size: size});
    }

    // VULN: amend skips _txCount + cap check
    function amend(uint256 id, uint256 newPrice) external {
        orders[id].price = newPrice;
    }
}
