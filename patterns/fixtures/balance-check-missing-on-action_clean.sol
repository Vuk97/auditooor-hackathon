// SPDX-License-Identifier: MIT
// Fixture: balance-check-missing-on-action — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

contract BalanceCheckMissingClean {
    mapping(address => uint256) public balance;
    mapping(address => uint256) public accounts;

    // CLEAN fix: explicit require(balance[msg.sender] >= amount) guard.
    function withdraw(uint256 amount) external {
        require(balance[msg.sender] >= amount, "INSUFFICIENT_BALANCE");
        balance[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // CLEAN fix: require(... >= amount) form — matches the generic
    // `>= amount` branch of the negative guard regex.
    function burn(uint256 amount) external {
        require(balance[msg.sender] >= amount, "INSUFFICIENT_BALANCE");
        balance[msg.sender] -= amount;
    }

    // CLEAN fix: custom-error `if (balance[...] < amount) revert …`
    // form — matches the custom-error branch of the negative guard regex.
    error InsufficientBalance();
    function redeem(uint256 amount) external {
        if (balance[msg.sender] < amount) revert InsufficientBalance();
        accounts[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // CLEAN fix: mapping-subscript require(balance[user] >= ...) form.
    function debit(address user, uint256 amount) external {
        require(balance[user] >= amount, "INSUFFICIENT_BALANCE");
        balance[user] -= amount;
    }
}
