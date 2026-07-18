// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RestakingSlashTargetMismatchOperatorDeploysUnslashableVaultPositive {
    error NotSlashStore();

    struct VaultState {
        address slashStore;
        uint256 totalSlashableStake;
    }

    VaultState internal self;

    event StakeSlashed(uint256 amount);

    function initialize(address operatorChosenSlashStore) external {
        self.slashStore = operatorChosenSlashStore;
    }

    function slashAssets(uint256 amount, address slashingHandler) external {
        if (slashingHandler != self.slashStore) {
            revert NotSlashStore();
        }

        self.totalSlashableStake -= amount;
        emit StakeSlashed(amount);
    }
}
