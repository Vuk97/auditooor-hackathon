// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// (e) no inline assembly at all: has_inline_assembly=False, NOT flagged.
contract AsmNoneClean {
    mapping(address => uint256) balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
