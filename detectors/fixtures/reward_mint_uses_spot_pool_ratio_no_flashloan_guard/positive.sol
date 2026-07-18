// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract RewardVaultSpotMintPositive {
    IUniswapV2Pair public immutable rewardPair;
    mapping(address => uint256) public stakeShares;
    uint256 public totalMinted;

    constructor(IUniswapV2Pair pair) {
        rewardPair = pair;
    }

    function setStakeShares(uint256 shares) external {
        stakeShares[msg.sender] = shares;
    }

    function harvest() external returns (uint256 mintedOut) {
        uint256 userShares = stakeShares[msg.sender];
        require(userShares > 0, "no shares");

        (uint112 reserveReward, uint112 reserveQuote, ) = rewardPair.getReserves();
        uint256 spotQuotePerReward = (uint256(reserveQuote) * 1e18) / uint256(reserveReward);
        mintedOut = (userShares * spotQuotePerReward) / 1e18;
        totalMinted += mintedOut;
    }
}
