// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVault { function collect(uint256) external returns (uint256); }

contract HarvesterVuln {
    mapping(address => uint256) public pending;
    IVault public vault;

    /// VULN: decrements pending BEFORE try/catch. If collect() reverts the
    /// revert is swallowed and pending is permanently wrong.
    function harvest(address user, uint256 amount) external {
        pending[user] -= amount;
        try vault.collect(amount) returns (uint256) {
            // success path
        } catch {
            // swallowed; pending stays wrong
        }
    }
}
