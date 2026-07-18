pragma solidity ^0.8.20;

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

contract LiquidationAuctionClean {
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
        LoanData storage loanData = loans[loanId];
        require(loanData.lastBidder != address(0), "auction missing");
        IERC721(nft).safeTransferFrom(poolManager, loanData.lastBidder, tokenId);
    }
}
