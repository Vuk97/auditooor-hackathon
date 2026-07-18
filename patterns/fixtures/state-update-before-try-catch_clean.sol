// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVault { function collect(uint256) external returns (uint256); }

contract HarvesterClean {
    mapping(address => uint256) public pending;
    IVault public vault;

    /// CLEAN: state only updated on success branch; catch compensates otherwise.
    function harvest(address user, uint256 amount) external {
        try vault.collect(amount) returns (uint256) {
            pending[user] = pending[user] + 0 - amount; // update only on success
        } catch {
            // explicit no-op: debt stays intact
        }
    }
}
