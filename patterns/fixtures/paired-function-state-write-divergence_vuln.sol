// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CLOBVuln {
    struct Order { uint256 price; uint256 qty; address maker; }
    mapping(uint256 => Order) public orders;
    mapping(address => uint256) public perTxCount;
    uint256 public constant MAX_LIMITS_PER_TX = 5;

    function placeOrder(uint256 id, uint256 price, uint256 qty) external {
        require(perTxCount[msg.sender] < MAX_LIMITS_PER_TX, "per-tx");
        perTxCount[msg.sender] += 1;
        orders[id] = Order({price: price, qty: qty, maker: msg.sender});
    }

    // VULN: amend writes orders[id] but doesn't enforce perTxCount
    function amendOrder(uint256 id, uint256 price, uint256 qty) external {
        orders[id] = Order({price: price, qty: qty, maker: msg.sender});
    }
}
