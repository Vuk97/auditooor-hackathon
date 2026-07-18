// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MissingRecipientOrderMatchHardcodedMakerSinkPositive {
    enum MatchType {
        COMPLEMENTARY,
        MINT,
        MERGE
    }

    struct Order {
        address maker;
        uint256 tokenId;
    }

    function _matchOrders(
        Order memory takerOrder,
        Order[] memory makerOrders,
        uint256 takerFillAmount,
        uint256[] memory makerFillAmounts
    ) internal {
        uint256 makerAssetId = takerOrder.tokenId;
        uint256 takerAssetId = makerOrders.length;

        _transfer(takerOrder.maker, address(this), makerAssetId, takerFillAmount);
        _fillMakerOrders(takerOrder, makerOrders, makerFillAmounts);

        uint256 taking = _getBalance(takerAssetId);
        uint256 fee = taking / 100;

        _transfer(address(this), takerOrder.maker, takerAssetId, taking - fee);

        uint256 refund = _getBalance(makerAssetId);
        if (refund > 0) {
            _transfer(address(this), takerOrder.maker, makerAssetId, refund);
        }

        emit OrdersMatched(takerOrder.maker, makerAssetId, takerAssetId);
    }

    function _fillMakerOrders(Order memory, Order[] memory, uint256[] memory) internal {}

    function _getBalance(uint256) internal pure returns (uint256) {
        return 100;
    }

    function _transfer(address, address, uint256, uint256) internal {}

    event OrdersMatched(address indexed maker, uint256 makerAssetId, uint256 takerAssetId);
}
