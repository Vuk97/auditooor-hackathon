pragma solidity ^0.8.0;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract OracleConsumer {
    AggregatorV3Interface public feed;

    constructor(address _feed) {
        feed = AggregatorV3Interface(_feed);
    }
}

contract PriceRouterVuln is OracleConsumer {
    constructor(address _feed) OracleConsumer(_feed) {}

    function getPrice() external view returns (int256) {
        (, int256 price, , , ) = feed.latestRoundData();
        return price;
    }

    function getPriceWithOffset(int256 offset) external view returns (int256) {
        (, int256 price, , , ) = feed.latestRoundData();
        return price + offset;
    }
}