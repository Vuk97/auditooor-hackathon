// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// dutch-auction-parameter-manipulation detector. DO NOT DEPLOY.
///
/// Dutch-auction setters are admin-gated (as they should be) but accept
/// arbitrary values with no bounds and apply immediately even while an
/// auction is live. Admin can halt liquidation or spike starting price.
contract DutchAuctionVuln {
    address public owner;

    uint256 public auctionDecrement;
    uint256 public auctionMultiplier;
    uint256 public startPrice;

    struct Auction {
        uint256 startTime;
        bool active;
    }
    Auction public currentAuction;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setAuctionDecrement(uint256 newDecrement) external onlyOwner {
        // No bounds check, no active-auction guard. Applies in-flight.
        auctionDecrement = newDecrement;
    }

    function setAuctionMultiplier(uint256 newMultiplier) external onlyOwner {
        auctionMultiplier = newMultiplier;
    }

    function setStartPrice(uint256 newStartPrice) external onlyOwner {
        startPrice = newStartPrice;
    }
}
