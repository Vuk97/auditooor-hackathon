pragma solidity ^0.8.20;

contract PerpPriceNotSignatureVerifiedInLimitCloseClean {
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
        uint256 verifiedPrice = getVerifiedPrice(_priceData, _signature);
        if (verifiedPrice > 3_500) {
            lastClosedPrice = verifiedPrice;
        }
    }
}
