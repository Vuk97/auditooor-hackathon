// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// CLEAN: Auction extends endTime with a hard-cap guard.
// Attacker cannot extend beyond hardEnd - auction settles on schedule.

contract AuctionWithHardCapClean {
    struct Auction {
        address seller;
        uint256 endTime;
        uint256 hardEnd;       // GUARD: immutable hard deadline
        uint256 highestBid;
        address highestBidder;
        bool settled;
    }

    uint256 public ttl = 15 minutes;
    uint256 public minimumIncrement = 1 wei;
    mapping(uint256 => Auction) public auctions;

    event AuctionCreated(uint256 indexed id, address seller, uint256 endTime, uint256 hardEnd);
    event BidPlaced(uint256 indexed id, address bidder, uint256 amount, uint256 newEndTime);

    function createAuction(uint256 id) external {
        uint256 start = block.timestamp + 1 days;
        // hardEnd is set at creation and cannot be extended
        uint256 hardEnd = block.timestamp + 7 days;
        auctions[id] = Auction({
            seller: msg.sender,
            endTime: start,
            hardEnd: hardEnd,
            highestBid: 0,
            highestBidder: address(0),
            settled: false
        });
        emit AuctionCreated(id, msg.sender, start, hardEnd);
    }

    // CLEAN: endTime extension capped by hardEnd - attacker cannot extend indefinitely.
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

        // GUARD: extension is capped by hardEnd
        uint256 extendedEnd = block.timestamp + ttl;
        if (extendedEnd > auction.hardEnd) {
            extendedEnd = auction.hardEnd;
        }
        auction.endTime = extendedEnd;
        emit BidPlaced(auctionId, msg.sender, msg.value, auction.endTime);
    }

    function settleAuction(uint256 auctionId) external {
        Auction storage auction = auctions[auctionId];
        require(block.timestamp >= auction.endTime, "still live");
        auction.settled = true;
        payable(auction.seller).transfer(auction.highestBid);
    }
}
