// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract DecimalPrecision18To6DownscaleLossVuln {
    IERC20 public usdc;
    mapping(address => uint256) public shares18;

    constructor(address _usdc) {
        usdc = IERC20(_usdc);
    }

    // VULN: deposit path stores `amount * 1e12` internally and credits shares
    // via floor `/ 1e12` on a different basis — small deposits round to zero
    // shares while the USDC is still pulled from the user.
    function deposit(uint256 amount6) external {
        usdc.transferFrom(msg.sender, address(this), amount6);
        // Internal math in 18-decimal precision:
        uint256 value18 = amount6 * 1e12;
        // Credit: floor-divide, no ceiling.
        uint256 credited = value18 / 1e12;
        shares18[msg.sender] += credited;
    }

    // VULN: withdraw downscales user's internal balance with floor division.
    // A user whose internal balance is 9.9e11 (i.e. 0.99 USDC units) gets
    // paid out zero and their 18-decimal balance is cleared.
    function withdraw(uint256 amount18) external {
        require(shares18[msg.sender] >= amount18, "insufficient");
        shares18[msg.sender] -= amount18;
        uint256 payout6 = amount18 / 1e12; // floors to zero for sub-1e12
        usdc.transfer(msg.sender, payout6);
    }

    // VULN: named downscale helper with no ceiling — the regex will also
    // catch the name `scaleDown`.
    function scaleDown(uint256 x18) public pure returns (uint256) {
        return x18 / 1e12;
    }
}
