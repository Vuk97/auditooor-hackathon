// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: vault uses `shares = amount` when totalSupply == 0 and does NOT
// burn any dead-share seed on the first mint. Attacker front-runs the
// genuine first depositor, mints 1 share, donates reserves, steals.

contract FrontRunnableVaultVuln {
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    // VULN shape 1: deposit with 1:1 bootstrap branch, no dead-share burn.
    function deposit(uint256 amount) external returns (uint256 s) {
        if (totalSupply == 0) {
            s = amount; // 1:1 bootstrap, no burn
        } else {
            s = amount * totalSupply / totalAssets;
        }
        shares[msg.sender] += s;
        totalSupply += s;
        totalAssets += amount;
    }

    // VULN shape 2: _deposit exposed publicly with the same fallback.
    function _deposit(uint256 amount) external returns (uint256 s) {
        if (_totalSupply() == 0) {
            s = amount;
        } else {
            s = amount * totalSupply / totalAssets;
        }
        shares[msg.sender] += s;
        totalSupply += s;
        totalAssets += amount;
    }

    function _totalSupply() internal view returns (uint256) {
        return totalSupply;
    }

    // VULN shape 3: stake() variant using totalShares==0 as the guard.
    function stake(uint256 amount) external returns (uint256 s) {
        uint256 totalShares = totalSupply;
        if (totalShares == 0) {
            s = amount;
        } else {
            s = amount * totalShares / totalAssets;
        }
        shares[msg.sender] += s;
        totalSupply += s;
        totalAssets += amount;
    }
}
