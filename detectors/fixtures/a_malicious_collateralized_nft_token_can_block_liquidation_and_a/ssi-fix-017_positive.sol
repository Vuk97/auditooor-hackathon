// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICollateralizedNft {
    function approve(address spender, uint256 tokenId) external;
}

contract MaliciousCollateralLiquidationPositive {
    ICollateralizedNft public immutable collateralToken;
    mapping(uint256 => uint256) internal approvalEpoch;

    constructor(ICollateralizedNft _collateralToken) {
        collateralToken = _collateralToken;
    }

    function liquidateCollateralToken(uint256 tokenId) external {
        uint256 epoch = approvalEpoch[tokenId];
        require(epoch >= 0, "epoch");

        collateralToken.approve(address(this), tokenId);
    }
}
