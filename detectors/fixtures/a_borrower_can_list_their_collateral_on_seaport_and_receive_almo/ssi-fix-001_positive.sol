// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFixtureSeaport {
    function fulfillOrder(uint256 tokenId, uint256 price) external returns (bool);
}

contract AstariaSeaportListingVulnerable {
    IFixtureSeaport public immutable seaport;
    mapping(uint256 => uint256) internal listForSaleOnSeaportPrice;
    mapping(uint256 => address) internal collateralOwner;

    constructor(IFixtureSeaport _seaport) {
        seaport = _seaport;
    }

    function listForSaleOnSeaport(uint256 tokenId) external {
        uint256 price = listForSaleOnSeaportPrice[tokenId];
        require(collateralOwner[tokenId] == msg.sender, "not borrower");

        bool accepted = seaport.fulfillOrder(tokenId, price);
        require(accepted, "seaport failed");
    }
}
