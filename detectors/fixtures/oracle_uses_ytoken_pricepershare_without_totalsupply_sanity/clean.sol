pragma solidity ^0.8.20;

interface IYearnVaultLike {
    function balance() external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

contract GuardedYTokenCollateralOracle {
    IYearnVaultLike public immutable yToken;
    uint256 public immutable underlyingPrice;
    uint256 public constant MIN_SHARE_SUPPLY = 1e18;

    constructor(IYearnVaultLike vault_, uint256 underlyingPrice_) {
        yToken = vault_;
        underlyingPrice = underlyingPrice_;
    }

    function getUnderlyingPrice() external view returns (uint256) {
        uint256 shares = yToken.totalSupply();
        require(shares >= MIN_SHARE_SUPPLY, "share supply too small");
        return yToken.balance() * underlyingPrice / shares;
    }
}
