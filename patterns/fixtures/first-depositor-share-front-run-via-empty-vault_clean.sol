// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: vault burns DEAD_SHARES on first mint (Uniswap V2 style), OR
// seeds via _initialize(<dust>), OR uses virtualShares on the share math.
// Any one of these mitigations should independently suppress the match.

contract FrontRunSafeVaultClean {
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    uint256 public constant DEAD_SHARES = 1000;
    uint256 public constant MIN_SHARES = 1000;
    uint256 public constant MINIMUM_LIQUIDITY = 1000;
    uint256 public constant virtualShares = 1e6;
    address public constant BURN_ADDRESS = address(0xdead);

    // CLEAN shape 1: deposit with DEAD_SHARES permanently burned on first
    // mint. `DEAD_SHARES` in the body suppresses the match.
    function deposit(uint256 amount) external returns (uint256 s) {
        if (totalSupply == 0) {
            s = amount - DEAD_SHARES;
            shares[BURN_ADDRESS] += DEAD_SHARES;
            totalSupply += amount;
        } else {
            s = amount * totalSupply / totalAssets;
        }
        shares[msg.sender] += s;
        totalAssets += amount;
    }

    // CLEAN shape 2: _deposit with _burn(MIN_SHARES) idiom.
    function _deposit(uint256 amount) external returns (uint256 s) {
        if (totalSupply == 0) {
            s = amount;
            _burn(msg.sender, MIN_SHARES);
        } else {
            s = amount * totalSupply / totalAssets;
        }
        shares[msg.sender] += s;
        totalSupply += s;
        totalAssets += amount;
    }

    function _burn(address, uint256) internal pure {}

    // CLEAN shape 3: mint using virtualShares offset in the share math.
    function mint(uint256 amount) external returns (uint256 s) {
        if (totalSupply == 0) {
            s = amount;
        } else {
            s = amount * (totalSupply + virtualShares) / (totalAssets + 1);
        }
        shares[msg.sender] += s;
        totalSupply += s;
        totalAssets += amount;
    }

    // CLEAN shape 4: stake seeded via _initialize(1e18, ...).
    function stake(uint256 amount) external returns (uint256 s) {
        if (totalSupply == 0) {
            _initialize(1e18, msg.sender);
            s = amount;
        } else {
            s = amount * totalSupply / totalAssets;
        }
        shares[msg.sender] += s;
        totalSupply += s;
        totalAssets += amount;
    }

    function _initialize(uint256, address) internal {
        totalSupply += MINIMUM_LIQUIDITY;
    }
}
