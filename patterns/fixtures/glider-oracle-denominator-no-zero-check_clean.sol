pragma solidity ^0.8.0;

interface IOracle {
    function getPrice() external view returns (uint256);
}

contract RateClean {
    IOracle public oracle;
    uint256 public exchangeRate;

    function updateExchangeRate() external {
        uint256 price = oracle.getPrice();
        require(price > 0);
        exchangeRate = 1e36 / price;
    }

    function deposit(uint256 amount) external {
        require(amount > 0);
    }
}