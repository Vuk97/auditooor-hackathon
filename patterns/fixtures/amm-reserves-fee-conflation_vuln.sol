// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract LaunchpadPairVuln {
    uint112 public reserve0;
    uint112 public reserve1;
    uint256 public accruedFee;      // fees sit inside the pair balance
    uint256 public totalSupply;
    address public token0;
    address public token1;

    mapping(address => uint256) public balanceOf;

    // VULN: uses reserve0/reserve1 without subtracting accruedFee
    function burn(address to) external returns (uint256 a0, uint256 a1) {
        uint256 liquidity = balanceOf[address(this)];
        a0 = (liquidity * reserve0) / totalSupply;      // includes fee
        a1 = (liquidity * reserve1) / totalSupply;      // includes fee
        totalSupply -= liquidity;
        balanceOf[address(this)] = 0;
        IERC20(token0).transfer(to, a0);
        IERC20(token1).transfer(to, a1);
    }

    // VULN: k-check on raw reserves conflates fee float into k
    function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
        uint256 bal0 = IERC20(token0).balanceOf(address(this));
        uint256 bal1 = IERC20(token1).balanceOf(address(this));
        require(bal0 * bal1 >= uint256(reserve0) * uint256(reserve1), "K");
        reserve0 = uint112(bal0 - amount0Out);
        reserve1 = uint112(bal1 - amount1Out);
        IERC20(token0).transfer(to, amount0Out);
        IERC20(token1).transfer(to, amount1Out);
    }
}
