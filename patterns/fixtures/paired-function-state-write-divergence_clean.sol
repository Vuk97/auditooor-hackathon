// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CLOBClean {
    struct Order { uint256 price; uint256 qty; address maker; }
    mapping(uint256 => Order) public orders;
    mapping(address => uint256) public perTxCount;
    uint256 public constant MAX_LIMITS_PER_TX = 5;

    function _checkPerTxLimit(address m) internal {
        require(perTxCount[m] < MAX_LIMITS_PER_TX, "per-tx");
        perTxCount[m] += 1;
    }

    function placeOrder(uint256 id, uint256 price, uint256 qty) external {
        _checkPerTxLimit(msg.sender);
        orders[id] = Order({price: price, qty: qty, maker: msg.sender});
    }

    function amendOrder(uint256 id, uint256 price, uint256 qty) external {
        _checkPerTxLimit(msg.sender);
        orders[id] = Order({price: price, qty: qty, maker: msg.sender});
    }
}
