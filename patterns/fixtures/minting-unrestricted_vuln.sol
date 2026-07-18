// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: public `mint` with no access-control modifier — anyone can mint
// to any address, inflating totalSupply at will.
contract VulnToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
    }
}
