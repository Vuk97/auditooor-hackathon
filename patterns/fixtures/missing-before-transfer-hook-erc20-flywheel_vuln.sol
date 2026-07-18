// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Flywheel {
    mapping(address => uint256) public rewardDebt;
    function accrue(address) public virtual;
}

contract MissingBeforeTransferHookErc20FlywheelVuln is Flywheel {
    mapping(address => uint256) internal _balances;

    function accrue(address u) public override {
        rewardDebt[u] += _balances[u] / 100;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        // VULN: no accrue(from) / accrue(to) before balance mutation.
        _balances[from] -= amount;
        _balances[to] += amount;
    }

    function transfer(address to, uint256 amount) external {
        _transfer(msg.sender, to, amount);
    }
}
