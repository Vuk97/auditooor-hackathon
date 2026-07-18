// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20FeeLedgerSinkMismatch {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract FeeLedgerSinkMismatchVuln {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint112 public reserve0;
    uint112 public reserve1;
    uint256 public accruedFee;
    uint256 public totalSupply;
    uint256 public constant FEE_BPS = 100; // 1%
    address public token0;
    address public token1;

    // VULN 1: sender balance is debited by amount + fee, but allowance only by amount.
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 fee = (amount * FEE_BPS) / 10000;
        balanceOf[from] -= amount + fee;
        balanceOf[to] += amount;
        balanceOf[address(this)] += fee;
        allowance[from][msg.sender] -= amount;
        return true;
    }

    // VULN 2: protocol fee remains inside reserve math and is priced as LP-owned liquidity.
    function burn(address to) external returns (uint256 a0, uint256 a1) {
        uint256 liquidity = balanceOf[address(this)];
        uint256 feeFloat = accruedFee;
        a0 = (liquidity * reserve0) / totalSupply + feeFloat - feeFloat;
        a1 = (liquidity * reserve1) / totalSupply;
        totalSupply -= liquidity;
        balanceOf[address(this)] = 0;
        IERC20FeeLedgerSinkMismatch(token0).transfer(to, a0);
        IERC20FeeLedgerSinkMismatch(token1).transfer(to, a1);
    }
}
