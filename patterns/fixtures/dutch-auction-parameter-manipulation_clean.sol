// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the vuln
/// fixture, but every setter enforces (a) an explicit sanity bound on the
/// incoming value and (b) an active-auction guard that blocks in-flight
/// retuning.
contract DutchAuctionClean {
    address public owner;

    uint256 public auctionDecrement;
    uint256 public auctionMultiplier;
    uint256 public startPrice;

    uint256 public constant MAX_DECREMENT = 1e18;
    uint256 public constant MIN_MULTIPLIER = 1e17;
    uint256 public constant MAX_MULTIPLIER = 1e19;
    uint256 public constant MAX_START_PRICE = 1e24;

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
        require(newDecrement > 0 && newDecrement <= MAX_DECREMENT, "bounds");
        require(!currentAuction.active, "auction isActive");
        auctionDecrement = newDecrement;
    }

    function setAuctionMultiplier(uint256 newMultiplier) external onlyOwner {
        require(newMultiplier >= MIN_MULTIPLIER, "lo");
        require(newMultiplier <= MAX_MULTIPLIER, "hi");
        require(!currentAuction.active, "auctionStarted");
        auctionMultiplier = newMultiplier;
    }

    function setStartPrice(uint256 newStartPrice) external onlyOwner {
        require(newStartPrice <= MAX_START_PRICE, "start cap");
        require(!currentAuction.active, "isActive");
        startPrice = newStartPrice;
    }
}
