// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDaoTokenClean {
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract TokenSaleProposalCreateClean {
    struct Tier {
        uint256 totalTokenProvided;
        uint256 pricePerToken;
    }

    IDaoTokenClean internal daoToken;
    mapping(uint256 => Tier) internal tiers;
    uint256 internal nextTierId;

    constructor(IDaoTokenClean token_) {
        daoToken = token_;
    }

    function createTier(uint256 totalTokenProvided, uint256 pricePerToken) external {
        daoToken.safeTransferFrom(msg.sender, address(this), totalTokenProvided);
        tiers[nextTierId] = Tier({
            totalTokenProvided: totalTokenProvided,
            pricePerToken: pricePerToken
        });
        nextTierId += 1;
    }
}
