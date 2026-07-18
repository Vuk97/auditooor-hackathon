// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: classic first-depositor share-inflation. Shares are computed as
// amount * totalSupply / reserve, with no MINIMUM_LIQUIDITY lock or virtual
// offsets. Attacker mints 1 wei, donates underlying, zeroes out everyone else.
contract LpFirstDepositVuln {
    uint256 public totalSupply;
    uint256 public reserve;
    mapping(address => uint256) public shares;
    address public lpToken;
    uint256 public liquidity;

    // VULN shape 1: deposit with the canonical vulnerable ratio.
    function deposit(uint256 amount) external returns (uint256 out) {
        if (totalSupply == 0) {
            out = amount;
        } else {
            out = amount * totalSupply / reserve;
        }
        shares[msg.sender] += out;
        totalSupply += out;
        reserve += amount;
    }

    // VULN shape 2: addLiquidity with the same math, no mitigation string.
    function addLiquidity(uint256 amount) external returns (uint256 s) {
        s = amount * totalSupply / reserve;
        shares[msg.sender] += s;
        totalSupply += s;
        reserve += amount;
    }

    // VULN shape 3: mint variant
    function mint(uint256 amount) external returns (uint256 s) {
        s = amount * totalSupply / reserve;
        shares[msg.sender] += s;
        totalSupply += s;
        reserve += amount;
    }
}
