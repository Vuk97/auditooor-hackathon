// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RentalTypeFlagIgnoredInOperationHandlersClean {
    struct Rental {
        address tenant;
        uint256 period;
        bool rentalType;
        uint256 amount;
    }

    struct Asset {
        Rental[] rentals;
    }

    mapping(uint256 => Asset) internal assets;
    mapping(address => uint256) public paidOut;

    function finalizeLongTermRental(uint256 tokenId, uint256 period) external {
        Asset storage asset = assets[tokenId];
        for (uint256 i = 0; i < asset.rentals.length; i++) {
            Rental storage item = asset.rentals[i];
            if (item.rentalType == false) {
                continue;
            }
            if (item.tenant == msg.sender && item.period == period) {
                paidOut[msg.sender] += item.amount;
            }
        }
    }
}
