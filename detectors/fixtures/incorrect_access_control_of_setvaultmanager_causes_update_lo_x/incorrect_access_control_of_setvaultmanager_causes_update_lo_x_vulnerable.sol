// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVaultManagerVulnerable {
    function ping() external view returns (uint256);
}

contract IncorrectAccessControlOfSetvaultmanagerCausesUpdateLoXVulnerable {
    address public owner;
    address public manager;
    IVaultManagerVulnerable public vaultManager;

    constructor(address initialManager) {
        owner = msg.sender;
        manager = initialManager;
        vaultManager = IVaultManagerVulnerable(initialManager);
    }

    modifier onlyManager() {
        require(msg.sender == manager, "ONLY_MANAGER");
        _;
    }

    function setVaultManager(address newVaultManager) external onlyManager {
        require(newVaultManager != address(0), "ADDRESS_INVALID");
        vaultManager = IVaultManagerVulnerable(newVaultManager);
    }
}
