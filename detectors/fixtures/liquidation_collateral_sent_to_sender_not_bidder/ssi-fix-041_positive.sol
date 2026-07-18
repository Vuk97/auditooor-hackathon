pragma solidity ^0.8.20;

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

contract LiquidationAuctionPositive {
    struct LoanData {
        address lastBidder;
    }

    mapping(uint256 => LoanData) internal loans;
    address internal immutable poolManager;

    constructor(address manager) {
        poolManager = manager;
    }

    function seedBidder(uint256 loanId, address bidder) external {
        loans[loanId].lastBidder = bidder;
    }

    function executeIsolateLiquidate(address nft, uint256 loanId, uint256 tokenId) external {
        require(loanId != type(uint256).max, "loan missing");
        IERC721(nft).transferFrom(poolManager, msg.sender, tokenId);
    }
}
