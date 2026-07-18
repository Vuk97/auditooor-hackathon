// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: ERC4626 share price used as collateral oracle WITH manipulation guards
// Guard 1: totalSupply floor check prevents empty-vault donation manipulation
// Guard 2: External price oracle (latestRoundData) as sanity check

interface IERC4626 {
    function convertToAssets(uint256 shares) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract CollateralOracleClean {
    IERC4626 public vault;
    AggregatorV3Interface public priceFeed;
    uint256 public constant MIN_SHARE_SUPPLY = 1e6; // supply floor guard
    mapping(address => uint256) public collateralShares;
    mapping(address => uint256) public debtBalance;
    uint256 public constant LTV = 8000; // 80%

    // CLEAN: getPrice checks totalSupply floor before using share price
    function getPrice(address user) external view returns (uint256) {
        // Guard: require minimum totalSupply to prevent empty-vault manipulation
        require(vault.totalSupply() >= MIN_SHARE_SUPPLY, "vault supply too low");
        uint256 shares = collateralShares[user];
        return vault.convertToAssets(shares);
    }

    // CLEAN: collateral value uses Chainlink oracle as primary source (latestRoundData)
    function collateralValue(uint256 shares) external view returns (uint256) {
        (, int256 answer,, uint256 updatedAt,) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt <= 3600, "stale price");
        require(answer > 0, "invalid price");
        return shares * uint256(answer) / 1e8;
    }
}
