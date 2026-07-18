// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
}

contract TokenDecimalsMismatchHardcodedVuln {
    IERC20 public token;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // VULN: hardcodes `amount * 1e18` when crediting shares. If `token` is
    // USDC (6 decimals), a 1 USDC deposit (1_000_000 units) gets credited as
    // 1_000_000 * 1e18 = 1e24 shares — overflow of the depositor's share of
    // the pool by 1e12x. Also breaks for WBTC (8) and any >18-decimal token.
    function _handleDeposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        uint256 credited = amount * 1e18;
        shares[msg.sender] += credited;
        totalShares += credited;
    }

    // VULN: withdraw path uses `/ 1e18` on a native 6- or 8-decimal amount.
    function _handleWithdraw(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "insufficient");
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        uint256 tokensOut = shareAmount / 1e18;
        token.transfer(msg.sender, tokensOut);
    }

    // VULN: pricing helper with `10 ** 18` hardcoded.
    function priceOf(uint256 amount) external pure returns (uint256) {
        return amount * (10 ** 18);
    }
}
