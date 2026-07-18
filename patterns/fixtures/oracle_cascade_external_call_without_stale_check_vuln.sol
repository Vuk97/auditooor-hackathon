// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IOracle {
    function latestAnswer() external view returns (int256);
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract OracleCascadeVuln {
    IOracle public priceFeed;
    address public vault;

    constructor(address _priceFeed, address _vault) {
        priceFeed = IOracle(_priceFeed);
        vault = _vault;
    }

    // VULN: reads oracle then makes external call without checking freshness
    function liquidate(address user, uint256 amount) external {
        int256 price = priceFeed.latestAnswer();
        require(price > 0, "invalid price");
        
        (bool success, ) = vault.call(abi.encodeWithSignature("seize(address,uint256)", user, amount * uint256(price)));
        require(success, "seize failed");
    }

    // VULN: reads oracle then transfers tokens without freshness check
    function swapAndSend(address token, uint256 amount) external {
        (, int256 price,,,) = priceFeed.latestRoundData();
        require(price > 0, "invalid price");
        
        uint256 value = amount * uint256(price);
        (bool success, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, value));
        require(success, "transfer failed");
    }
}
