// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// `buyNow` and `fillOrder` both query `royaltyInfo(tokenId, salePrice)` on
/// the NFT contract before paying the seller. The returned royalty is
/// subtracted from seller proceeds and forwarded to the creator. The
/// `(address(0), 0)` case is handled as a no-op. Because the function
/// body contains the royalty-lookup tokens the
/// `body_not_contains_regex` negative predicate evaluates false and the
/// detector does not fire.

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

interface IERC2981 {
    function royaltyInfo(uint256 tokenId, uint256 salePrice)
        external view returns (address receiver, uint256 royaltyAmount);
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Erc2981RoyaltyNotAppliedClean {
    address public nft;
    address public paymentToken;
    uint256 public protocolFeeBps;
    uint256 public maxRoyaltyBps = 1000; // 10% hard cap

    constructor(address _nft, address _paymentToken) {
        nft = _nft;
        paymentToken = _paymentToken;
        protocolFeeBps = 250;
    }

    // Internal helper: returns (receiver, cappedAmount) or (0,0).
    function _royalty(uint256 tokenId, uint256 salePrice)
        internal view returns (address receiver, uint256 amount)
    {
        (receiver, amount) = IERC2981(nft).royaltyInfo(tokenId, salePrice);
        uint256 cap = (salePrice * maxRoyaltyBps) / 10000;
        if (amount > cap) amount = cap;
    }

    // CLEAN: buy-now settlement. Calls royaltyInfo, subtracts from
    // seller proceeds, forwards to creator. The function body contains
    // `royaltyInfo` and `IERC2981`, so the negative predicate is true.
    function buyNow(address seller, uint256 tokenId, uint256 salePrice) external {
        uint256 fee = (salePrice * protocolFeeBps) / 10000;
        (address receiver, uint256 royalty) = _royalty(tokenId, salePrice);
        IERC20(paymentToken).transferFrom(msg.sender, address(this), salePrice);
        if (receiver != address(0) && royalty > 0) {
            IERC20(paymentToken).transfer(receiver, royalty);
        }
        IERC20(paymentToken).transfer(seller, salePrice - fee - royalty);
        IERC721(nft).safeTransferFrom(seller, msg.sender, tokenId);
    }

    // CLEAN: generic order fill. Same royalty handling, different name.
    function fillOrder(address seller, uint256 tokenId, uint256 salePrice) external {
        uint256 fee = (salePrice * protocolFeeBps) / 10000;
        (address royaltyReceiver, uint256 royaltyAmount) =
            IERC2981(nft).royaltyInfo(tokenId, salePrice);
        if (royaltyAmount > (salePrice * maxRoyaltyBps) / 10000) {
            royaltyAmount = (salePrice * maxRoyaltyBps) / 10000;
        }
        IERC20(paymentToken).transferFrom(msg.sender, address(this), salePrice);
        if (royaltyReceiver != address(0) && royaltyAmount > 0) {
            IERC20(paymentToken).transfer(royaltyReceiver, royaltyAmount);
        }
        IERC20(paymentToken).transfer(seller, salePrice - fee - royaltyAmount);
        IERC721(nft).safeTransferFrom(seller, msg.sender, tokenId);
    }
}
