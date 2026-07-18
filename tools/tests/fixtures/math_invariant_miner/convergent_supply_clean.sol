// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Clean counterpart of math_diverging_supply_vulnerable.sol.
//
// `mint` updates BOTH sides of the conservation law
//     totalSupply == sum(balanceOf)
// so the candidate invariant emitted by tools/math-invariant-miner.py
// (conservation-of-supply) holds across the function. The miner still
// emits the invariant; it just does NOT flag mint() as one-sided.
contract ConvergentMath {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
