// SPDX-License-Identifier: MIT
// Fixture: balance-check-missing-on-action — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

contract BalanceCheckMissingVuln {
    // Precondition: state var name matches /balance|balances|account|accounts/.
    mapping(address => uint256) public balance;
    mapping(address => uint256) public accounts;

    // VULN: withdraw decrements balance[msg.sender] but never checks
    // balance[msg.sender] >= amount. On solc < 0.8 this is an underflow
    // drain; on >= 0.8 it is an uninformative revert-DoS.
    function withdraw(uint256 amount) external {
        balance[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // VULN: burn decrements a balance map with no sufficiency check.
    function burn(uint256 amount) external {
        balance[msg.sender] -= amount;
    }

    // VULN: redeem from an accounts map with no check.
    function redeem(uint256 amount) external {
        accounts[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // VULN: debit wording with no check.
    function debit(address user, uint256 amount) external {
        balance[user] -= amount;
    }
}
