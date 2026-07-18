// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVaultManagerClean {
    function ping() external view returns (uint256);
}

contract IncorrectAccessControlOfSetvaultmanagerCausesUpdateLoXClean {
    address public owner;
    address public manager;
    IVaultManagerClean public vaultManager;

    constructor(address initialManager) {
        owner = msg.sender;
        manager = initialManager;
        vaultManager = IVaultManagerClean(initialManager);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "ONLY_OWNER");
        _;
    }

    function setVaultManager(address newVaultManager) external onlyOwner {
        require(newVaultManager != address(0), "ADDRESS_INVALID");
        vaultManager = IVaultManagerClean(newVaultManager);
    }
}
