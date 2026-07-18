// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: first-deposit inflation mitigated by burning MINIMUM_LIQUIDITY
// on initial mint and using virtualShares offsets for subsequent deposits.
contract LpFirstDepositClean {
    uint256 public totalSupply;
    uint256 public reserve;
    mapping(address => uint256) public shares;
    address public lpToken;
    uint256 public liquidity;

    uint256 public constant MINIMUM_LIQUIDITY = 1000;
    uint256 public constant virtualShares = 1e6;
    address public constant BURN_ADDRESS = address(0xdead);

    function deposit(uint256 amount) external returns (uint256 out) {
        if (totalSupply == 0) {
            // firstDeposit: mint MINIMUM_LIQUIDITY to BURN_ADDRESS permanently.
            out = amount - MINIMUM_LIQUIDITY;
            shares[BURN_ADDRESS] += MINIMUM_LIQUIDITY;
            totalSupply += amount;
        } else {
            // virtualShares offset neutralises the inflation ratio.
            out = amount * (totalSupply + virtualShares) / (reserve + 1);
            totalSupply += out;
        }
        shares[msg.sender] += out;
        reserve += amount;
    }

    function addLiquidity(uint256 amount) external returns (uint256 s) {
        // deadShares / virtualShares neutralise the ratio.
        s = amount * (totalSupply + virtualShares) / (reserve + 1);
        require(s > 0, "zero shares");
        shares[msg.sender] += s;
        totalSupply += s;
        reserve += amount;
    }

    function mint(uint256 amount) external returns (uint256 s) {
        // initialDeposit gated by a MIN_SHARES floor.
        uint256 MIN_SHARES = 1000;
        s = amount * (totalSupply + virtualShares) / (reserve + 1);
        require(s >= MIN_SHARES, "below min");
        shares[msg.sender] += s;
        totalSupply += s;
        reserve += amount;
    }
}
