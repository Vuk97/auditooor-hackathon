pragma solidity ^0.8.20;

contract PerpPriceNotSignatureVerifiedInLimitClosePositive {
    struct PriceData {
        uint256 price;
        uint256 timestamp;
    }

    uint256 public lastClosedPrice;

    function getVerifiedPrice(
        PriceData calldata _priceData,
        bytes calldata _signature
    ) internal pure returns (uint256) {
        _signature;
        return _priceData.price;
    }

    function limitClose(
        uint256 positionId,
        bool isLong,
        PriceData calldata _priceData,
        bytes calldata _signature
    ) external {
        positionId;
        isLong;
        getVerifiedPrice(_priceData, _signature);
        if (_priceData.price > 3_500) {
            lastClosedPrice = _priceData.price;
        }
    }
}
