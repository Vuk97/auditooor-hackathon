// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CLOBClean {
    struct Order { uint256 price; uint256 size; }
    mapping(uint256 => Order) public orders;
    uint256 public maxLimitsPerTx = 10;
    uint256 internal _txCount;

    function _bumpTx() internal {
        _txCount += 1;
        require(_txCount <= maxLimitsPerTx, "cap");
    }

    function placeOrder(uint256 id, uint256 price, uint256 size) external {
        _bumpTx();
        orders[id] = Order({price: price, size: size});
    }

    function amend(uint256 id, uint256 newPrice) external {
        _bumpTx();
        orders[id].price = newPrice;
    }
}
