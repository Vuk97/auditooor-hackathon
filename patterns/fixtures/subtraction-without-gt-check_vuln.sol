// SPDX-License-Identifier: MIT
// Fixture: subtraction-without-gt-check — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

// VULN: every balance/shares/total-mutating entrypoint subtracts without
// a dominating `require(x >= amount)` or `if (x < amount) revert …` guard.
// Post-0.8 these revert with an uninformative Panic(0x11), which is a
// DoS-shaped UX bug. Pre-0.8 each would underflow to 2^256-1.
contract SubWithoutGteVuln {
    mapping(address => uint256) public balance;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public shares;
    uint256 public totalSupply;
    uint256 public totalShares;

    // VULN: bare `balance[x] -= y` with no sufficiency check.
    function withdraw(uint256 amount) external {
        balance[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // VULN: plural-mapping form `balances[x] -= y` with no check.
    function burn(uint256 amount) external {
        balances[msg.sender] -= amount;
    }

    // VULN: shares-accounting form `shares[x] -= y` with no check.
    function unstake(uint256 amount) external {
        shares[msg.sender] -= amount;
    }

    // VULN: scalar aggregate `total* -= y` with no check.
    function debitTotal(uint256 amount) external {
        totalSupply -= amount;
    }

    // VULN: another total* with no check.
    function decreaseShares(uint256 amount) external {
        totalShares -= amount;
    }
}
