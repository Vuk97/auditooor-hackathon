// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: ERC4626-style vault with classic first-depositor inflation shape.
// Shares are computed as `assets * totalSupply / totalAssets` with no
// virtualShares, _decimalsOffset, DEAD_SHARES burn, or initializer dust
// mitigation. First depositor donates underlying to inflate share price
// and steals later depositors' stakes.

interface IERC4626 {}

abstract contract ERC4626 is IERC4626 {
    // minimal ERC4626 base so `contract.inherits_any: [ERC4626, IERC4626]` fires.
}

contract InflatableVaultVuln is ERC4626 {
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    // VULN shape 1: deposit with canonical vulnerable ratio, no mitigation.
    function deposit(uint256 assets) external returns (uint256 s) {
        if (totalSupply == 0) {
            s = assets; // 1:1 bootstrap; no dust burn
        } else {
            s = assets * totalSupply / totalAssets;
        }
        shares[msg.sender] += s;
        totalSupply += s;
        totalAssets += assets;
    }

    // VULN shape 2: mint variant using the same ratio.
    function mint(uint256 assets) external returns (uint256 s) {
        s = assets * totalSupply / totalAssets;
        shares[msg.sender] += s;
        totalSupply += s;
        totalAssets += assets;
    }

    // VULN shape 3: internal _convertToShares exposed as public (re-implementations).
    function _convertToShares(uint256 assets) external returns (uint256 s) {
        s = assets * totalSupply / totalAssets;
        totalSupply += s; // mutating -> is_mutating:true matches
    }
}
