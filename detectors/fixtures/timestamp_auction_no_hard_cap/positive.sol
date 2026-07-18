// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// VULN: Auction extends endTime on each bid without a hard-cap guard.
// Attacker can perpetually extend the auction, preventing settlement.
// Real-world basis: r74-ttl-auction-no-end-condition-dos (Code4rena finding).

contract AuctionNoHardCapVuln {
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

    event AuctionCreated(uint256 indexed id, address seller, uint256 endTime);
    event BidPlaced(uint256 indexed id, address bidder, uint256 amount, uint256 newEndTime);

    function createAuction(uint256 id) external {
        auctions[id] = Auction({
            seller: msg.sender,
            endTime: block.timestamp + 1 days,
            highestBid: 0,
            highestBidder: address(0),
            settled: false
        });
        emit AuctionCreated(id, msg.sender, auctions[id].endTime);
    }

    // VULN: resets endTime = block.timestamp + ttl on EVERY bid.
    // No hardEnd cap - attacker can extend indefinitely with 1-wei bids.
    function placeBid(uint256 auctionId) external payable {
        Auction storage auction = auctions[auctionId];
        require(!auction.settled, "settled");
        require(block.timestamp < auction.endTime, "ended");
        require(msg.value >= auction.highestBid + minimumIncrement, "low bid");

        if (auction.highestBidder != address(0)) {
            payable(auction.highestBidder).transfer(auction.highestBid);
        }

        auction.highestBid = msg.value;
        auction.highestBidder = msg.sender;

        // BUG: endTime reset with no hard cap
        auction.endTime = block.timestamp + ttl;
        emit BidPlaced(auctionId, msg.sender, msg.value, auction.endTime);
    }

    function settleAuction(uint256 auctionId) external {
        Auction storage auction = auctions[auctionId];
        require(block.timestamp >= auction.endTime, "still live");
        auction.settled = true;
        payable(auction.seller).transfer(auction.highestBid);
    }
}
