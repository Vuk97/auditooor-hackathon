pragma solidity ^0.8.20;

contract FreeLiquidityMintClean {
    uint256 public reserve0 = 500_000;
    uint256 public totalSupply = 1_000_000;
    mapping(address => uint256) public sharesBalance;

    function mint(uint256 shares) external returns (uint256 amount) {
        amount = ceilDiv(shares * reserve0, totalSupply);
        require(amount > 0, "zero input");
        sharesBalance[msg.sender] += shares;
        totalSupply += shares;
    }

    function ceilDiv(uint256 x, uint256 y) internal pure returns (uint256) {
        return x == 0 ? 0 : ((x - 1) / y) + 1;
    }
}
