// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IOracle {
    function latestAnswer() external view returns (int256);
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract OracleCascadeClean {
    IOracle public priceFeed;
    address public vault;
    uint256 public constant HEARTBEAT = 3600; // 1 hour

    constructor(address _priceFeed, address _vault) {
        priceFeed = IOracle(_priceFeed);
        vault = _vault;
    }

    // CLEAN: reads oracle, checks freshness, then makes external call
    function liquidate(address user, uint256 amount) external {
        (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
        require(price > 0, "invalid price");
        require(block.timestamp - updatedAt < HEARTBEAT, "stale price");
        
        uint256 value = amount * uint256(price);
        (bool success, ) = vault.call(abi.encodeWithSignature("seize(address,uint256)", user, value));
        require(success, "seize failed");
    }

    // CLEAN: reads oracle, checks roundId, then transfers
    function swapAndSend(address token, uint256 amount) external {
        (uint80 roundId, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
        require(price > 0, "invalid price");
        require(roundId > 0, "invalid round");
        require(block.timestamp - updatedAt < HEARTBEAT, "stale price");
        
        uint256 value = amount * uint256(price);
        (bool success, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, value));
        require(success, "transfer failed");
    }
}
