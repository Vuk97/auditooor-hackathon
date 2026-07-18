// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// erc2981-royalty-not-applied-on-sale detector. DO NOT DEPLOY.
///
/// `buyNow` and `fillOrder` settle an NFT sale: they move the NFT from
/// seller to buyer and pay the seller `salePrice - protocolFee`. Neither
/// path calls `royaltyInfo()` on the NFT contract, so any EIP-2981
/// royalty the creator configured is silently skipped. This is the
/// dominant shape in Solodit cluster C0157.

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Erc2981RoyaltyNotAppliedVuln {
    // Satisfies the contract-level precondition `nft|tokenAddress|collection`.
    address public nft;
    address public paymentToken;
    uint256 public protocolFeeBps; // e.g. 250 = 2.5%

    constructor(address _nft, address _paymentToken) {
        nft = _nft;
        paymentToken = _paymentToken;
        protocolFeeBps = 250;
    }

    // VULNERABLE: buy-now settlement. Transfers NFT seller->buyer, pays
    // seller `salePrice - fee`. Never invokes royaltyInfo(). Matches the
    // name_matches alternative `buyNow` and the positive body regex
    // (`safeTransferFrom`), and does NOT contain any royalty lookup token.
    function buyNow(address seller, uint256 tokenId, uint256 salePrice) external {
        uint256 fee = (salePrice * protocolFeeBps) / 10000;
        IERC20(paymentToken).transferFrom(msg.sender, address(this), salePrice);
        IERC20(paymentToken).transfer(seller, salePrice - fee);
        IERC721(nft).safeTransferFrom(seller, msg.sender, tokenId);
    }

    // VULNERABLE: generic order-fill path. Same shape, different entry
    // point name. Still no royalty lookup.
    function fillOrder(address seller, uint256 tokenId, uint256 salePrice) external {
        uint256 fee = (salePrice * protocolFeeBps) / 10000;
        IERC20(paymentToken).transferFrom(msg.sender, seller, salePrice - fee);
        IERC20(paymentToken).transferFrom(msg.sender, address(this), fee);
        IERC721(nft).safeTransferFrom(seller, msg.sender, tokenId);
    }
}
