// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// LOW: fresh msg.sender withdraw - weak signal (still emitted at severity=low).
contract Withdraw {
    mapping(address => uint256) bal;

    function withdraw() external {
        uint256 a = bal[msg.sender];
        bal[msg.sender] = 0;
        payable(msg.sender).transfer(a);   // <-- fires: transfer-stipend, low
    }
}
