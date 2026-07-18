// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICollateralizedNft {
    function approve(address spender, uint256 tokenId) external;
}

contract MaliciousCollateralLiquidationClean {
    ICollateralizedNft public immutable collateralToken;
    mapping(uint256 => uint256) internal approvalEpoch;
    mapping(uint256 => bool) internal pendingApprovalRecovery;

    constructor(ICollateralizedNft _collateralToken) {
        collateralToken = _collateralToken;
    }

    function liquidateCollateralToken(uint256 tokenId) external {
        uint256 epoch = approvalEpoch[tokenId];
        require(epoch >= 0, "epoch");

        _syncEpochApprovalRecovery(tokenId);
        try collateralToken.approve(address(this), tokenId) {} catch {}
    }

    function _syncEpochApprovalRecovery(uint256 tokenId) internal {
        pendingApprovalRecovery[tokenId] = true;
    }
}
