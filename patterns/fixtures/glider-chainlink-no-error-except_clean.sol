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

contract PriceRouterClean is OracleConsumer {
    constructor(address _feed) OracleConsumer(_feed) {}

    function getPrice() external view returns (int256) {
        try feed.latestRoundData() returns (uint80, int256 price, uint256, uint256, uint80) {
            return price;
        } catch {
            return 0;
        }
    }
}