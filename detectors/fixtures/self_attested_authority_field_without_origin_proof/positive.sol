// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library ECDSA {
    function recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length >= 20) {
            bytes20 raw;
            assembly {
                raw := mload(add(sig, 0x20))
            }
            return address(raw);
        }
        return address(uint160(uint256(digest)));
    }
}

contract MarketplaceAuthorityClaimWithoutOriginProofPositive {
    struct ListingInput {
        uint256 assetId;
        address seller;
        uint256 price;
    }

    mapping(address => bool) public operators;
    mapping(uint256 => address) internal owners;
    mapping(uint256 => uint256) public listedPrice;

    constructor(address operator, address seller) {
        operators[operator] = true;
        owners[1] = seller;
    }

    function ownerOf(uint256 assetId) public view returns (address) {
        return owners[assetId];
    }

    function _hashListing(ListingInput memory listing) internal pure returns (bytes32) {
        return keccak256(abi.encode(listing.assetId, listing.seller, listing.price));
    }

    function createListing(ListingInput memory listing, bytes memory operatorSig) external {
        address operator = ECDSA.recover(_hashListing(listing), operatorSig);
        require(operators[operator], "bad operator");
        require(ownerOf(listing.assetId) == listing.seller, "wrong seller");
        listedPrice[listing.assetId] = listing.price;
    }
}
