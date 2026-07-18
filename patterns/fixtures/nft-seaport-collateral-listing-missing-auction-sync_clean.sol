// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFixtureSeaport {
    function fulfillOrder(uint256 tokenId, uint256 price) external returns (bool);
}

contract NFTSeaportCollateralListingMissingAuctionSyncClean {
    struct AuctionData {
        uint256 price;
        bool active;
    }

    IFixtureSeaport public immutable seaport;
    mapping(uint256 => uint256) internal listForSaleOnSeaportPrice;
    mapping(uint256 => address) internal collateralOwner;
    mapping(uint256 => AuctionData) internal auctionData;

    constructor(IFixtureSeaport _seaport) {
        seaport = IFixtureSeaport(_seaport);
    }

    function seed(uint256 tokenId, address owner, uint256 price) external {
        collateralOwner[tokenId] = owner;
        listForSaleOnSeaportPrice[tokenId] = price;
    }

    function listForSaleOnSeaport(uint256 tokenId) external {
        uint256 price = listForSaleOnSeaportPrice[tokenId];
        require(collateralOwner[tokenId] == msg.sender, "not borrower");

        _syncAuctionData(tokenId, price);
        bool accepted = seaport.fulfillOrder(tokenId, price);
        require(accepted, "seaport failed");
    }

    function _syncAuctionData(uint256 tokenId, uint256 price) internal {
        auctionData[tokenId] = AuctionData({price: price, active: true});
    }
}
