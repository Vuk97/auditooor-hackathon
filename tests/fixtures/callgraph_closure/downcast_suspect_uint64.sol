// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (a): a VALUE-MOVING `amount` (uint256) is silently NARROWED to uint64
// before being stored / moved (downcast_suspect=TRUE, kind=narrowing). An attacker
// passing amount > type(uint64).max has the high bits TRUNCATED - the stored /
// moved value differs from the credited value (classic accounting truncation).
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract DowncastSuspectUint64 {
    IERC20 public token;
    address public treasury;
    mapping(address => uint64) public credited;

    constructor(IERC20 _t) {
        token = _t;
    }

    // UNSAFE-DOWNCAST: raw uint64(amount) narrowing on a value operand. // DOWNCAST-TARGET
    function pay(uint256 amount) external {
        uint64 narrowed = uint64(amount);
        credited[msg.sender] = narrowed;
        token.transfer(treasury, amount);
    }
}
