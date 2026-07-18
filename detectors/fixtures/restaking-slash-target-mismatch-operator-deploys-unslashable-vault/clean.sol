// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RestakingSlashTargetMismatchOperatorDeploysUnslashableVaultClean {
    mapping(address => address) public assetSlashingHandlers;
    address internal asset;
    uint256 internal totalSlashableStake;

    event StakeSlashed(uint256 amount);

    function initialize(address initialAsset, address canonicalHandler) external {
        asset = initialAsset;
        assetSlashingHandlers[initialAsset] = canonicalHandler;
    }

    function slashAssets(uint256 amount, address slashingHandler) external {
        address canonicalHandler = assetSlashingHandlers[asset];
        require(slashingHandler == canonicalHandler, "handler mismatch");

        totalSlashableStake -= amount;
        emit StakeSlashed(amount);
    }
}
