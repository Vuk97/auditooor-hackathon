pragma solidity ^0.8.20;

contract FreeLiquidityMintPositive {
    uint256 public reserve0 = 500_000;
    uint256 public totalSupply = 1_000_000;
    mapping(address => uint256) public sharesBalance;

    function mint(uint256 shares) external returns (uint256 amount) {
        amount = shares * reserve0 / totalSupply;
        sharesBalance[msg.sender] += shares;
        totalSupply += shares;
    }
}
