// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TtlAuctionNoEndConditionPositive {
    struct Auction {
        address seller;
        uint256 endTime;
        uint256 highestBid;
        address highestBidder;
        bool settled;
    }

    uint256 public ttl = 15 minutes;
    uint256 public minimumIncrement = 1 wei;
    mapping(uint256 => Auction) public auctions;

    function placeBid(uint256 auctionId) external payable {
        Auction storage auction = auctions[auctionId];
        require(!auction.settled, "settled");
        require(block.timestamp < auction.endTime, "ended");
        require(msg.value >= auction.highestBid + minimumIncrement, "low bid");

        auction.highestBid = msg.value;
        auction.highestBidder = msg.sender;

        auction.endTime = block.timestamp + ttl;
    }

    function settleAuction(uint256 auctionId) external {
        Auction storage auction = auctions[auctionId];
        require(block.timestamp >= auction.endTime, "still live");
        auction.settled = true;
    }
}
