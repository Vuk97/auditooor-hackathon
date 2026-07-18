pragma solidity ^0.8.0;

interface IOracle {
    function getPrice() external view returns (uint256);
}

contract RateVuln {
    IOracle public oracle;
    uint256 public exchangeRate;

    function updateExchangeRate() external {
        exchangeRate = 1e36 / oracle.getPrice();
    }

    function deposit(uint256 amount) external {
        require(amount > 0);
    }
}