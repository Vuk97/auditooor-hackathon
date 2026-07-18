// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: ERC-4626-style vault uses balanceOf(address(this)) as the
// share-price denominator inside the mint/redeem path. With a rebasing
// or donatable underlying, the share price drifts silently — attackers
// arbitrage the next deposit/withdraw across the rebase boundary.

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract Erc4626BalanceOfShareCalcNarrowedVuln {
    IERC20 public immutable underlying;       // immutable decl: must be ignored by detector
    uint256 public totalSupply;               // shares
    mapping(address => uint256) public balances;

    constructor(IERC20 _u) {
        underlying = IERC20(address(_u));     // constructor cast: must be ignored
    }

    // VULN — preview path uses balanceOf(address(this)) co-located with
    // a share-mint arithmetic expression. This is the canonical RG-N4
    // narrowed shape.
    function _convertToShares(uint256 assets) internal view returns (uint256) {
        uint256 cash = underlying.balanceOf(address(this));
        if (cash == 0) return assets;
        return assets * totalSupply / cash;
    }

    // VULN — deposit path mints shares using the share-price denominator.
    // The pattern fires here because balanceOf(address(this)) is in the
    // same function body as a share-mint arithmetic & _mint sink.
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = assets * totalSupply / underlying.balanceOf(address(this));
        balances[msg.sender] += shares;
        totalSupply += shares;
        underlying.transferFrom(msg.sender, address(this), assets);
    }

    // VULN — redeem path uses the same denominator.
    function redeem(uint256 shares) external returns (uint256 assets) {
        assets = shares * underlying.balanceOf(address(this)) / totalSupply;
        balances[msg.sender] -= shares;
        totalSupply -= shares;
        underlying.transfer(msg.sender, assets);
    }
}
