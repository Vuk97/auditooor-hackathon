// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDaoTokenPositive {
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract TokenSaleProposalCreatePositive {
    struct Tier {
        uint256 totalTokenProvided;
        uint256 pricePerToken;
    }

    IDaoTokenPositive internal daoToken;
    mapping(uint256 => Tier) internal tiers;
    uint256 internal nextTierId;

    constructor(IDaoTokenPositive token_) {
        daoToken = token_;
    }

    function createTier(uint256 totalTokenProvided, uint256 pricePerToken) external {
        tiers[nextTierId] = Tier({
            totalTokenProvided: totalTokenProvided,
            pricePerToken: pricePerToken
        });
        nextTierId += 1;
    }
}
