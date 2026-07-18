pragma solidity ^0.8.20;

interface IYearnVaultLike {
    function balance() external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

contract VulnerableYTokenCollateralOracle {
    IYearnVaultLike public immutable yToken;
    uint256 public immutable underlyingPrice;

    constructor(IYearnVaultLike vault_, uint256 underlyingPrice_) {
        yToken = vault_;
        underlyingPrice = underlyingPrice_;
    }

    function getUnderlyingPrice() external view returns (uint256) {
        return yToken.balance() * underlyingPrice / yToken.totalSupply();
    }
}
