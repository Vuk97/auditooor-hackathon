// SPDX-License-Identifier: UNLICENSED
// CE-concretizer fixture contract-under-test.
//
// `withdraw` has an accounting bug: it credits the caller's balance with
// the withdrawn amount instead of debiting it. A symbolic engine checking
// the invariant `balanceOf(caller) <= deposited(caller)` produces a
// counterexample: call withdraw(x) and balanceOf grows past the deposit.
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public deposited;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
        deposited[msg.sender] += msg.value;
    }

    // BUG: should be `balanceOf[msg.sender] -= amount;`
    function withdraw(uint256 amount) external {
        balanceOf[msg.sender] += amount;
    }
}
