// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Fixture: a divergent-supply token used by tools/tests/test_math_invariant_miner.py
// to exercise V4 P2 math-invariant mining (DEEP_PROFILE=math).
//
// The contract has two accounting state variables (totalSupply, balanceOf)
// that are intended to satisfy the conservation law
//     totalSupply == sum(balanceOf)
// but the `mint` function only updates totalSupply, leaving balanceOf
// untouched. The miner should:
//   - identify totalSupply and balanceOf as accounting variables,
//   - emit a candidate "conservation-of-supply" invariant,
//   - flag mint() as a function that mutates only one side of the law.
//
// This fixture is intentionally minimal (no imports, no libraries) so
// regex-based mining produces deterministic output regardless of solc
// availability on the host.
contract DivergingMath {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
