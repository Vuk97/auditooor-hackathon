// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

library ShortPosition {
    struct Data {
        uint256 shortAmount;
        uint256 collateralAmount;
    }
}

contract ShortTokenPositive {
    mapping(uint256 => ShortPosition.Data) public positions;

    event Burned(uint256 indexed tokenId);

    function adjustPosition(
        uint256 tokenId,
        uint256 shortAmountDelta,
        uint256 collateralAmountDelta
    ) external {
        ShortPosition.Data storage position = positions[tokenId];

        if (shortAmountDelta >= position.shortAmount) {
            position.shortAmount = 0;
        } else {
            position.shortAmount -= shortAmountDelta;
        }

        if (collateralAmountDelta <= position.collateralAmount) {
            position.collateralAmount -= collateralAmountDelta;
        }

        if (position.shortAmount == 0) {
            _burn(tokenId);
        }
    }

    function _burn(uint256 tokenId) internal {
        delete positions[tokenId].shortAmount;
        emit Burned(tokenId);
    }
}
