// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library Math {
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return a == 0 ? 0 : (a - 1) / b + 1;
    }
}

contract DecimalPrecision18To6DownscaleLossClean {
    using Math for uint256;

    IERC20 public usdc;
    mapping(address => uint256) public shares18;

    constructor(address _usdc) {
        usdc = IERC20(_usdc);
    }

    // CLEAN: credit path uses ceilDiv so sub-1e12 remainders still credit one
    // share unit. `ceilDiv` in the body suppresses the detector.
    function deposit(uint256 amount6) external {
        usdc.transferFrom(msg.sender, address(this), amount6);
        uint256 value18 = amount6 * 1e12;
        uint256 credited = Math.ceilDiv(value18, 1e12);
        shares18[msg.sender] += credited;
    }

    // CLEAN: withdraw path uses the (x + 1e12 - 1) / 1e12 ceiling idiom and
    // reverts on zero payout instead of silently clearing dust.
    function withdraw(uint256 amount18) external {
        require(shares18[msg.sender] >= amount18, "insufficient");
        uint256 payout6 = (amount18 + 1e12 - 1) / 1e12;
        require(payout6 > 0, "dust");
        shares18[msg.sender] -= amount18;
        usdc.transfer(msg.sender, payout6);
    }

    // CLEAN: named roundUp helper — suppressor name appears in the body.
    function scaleDownRoundUp(uint256 x18) public pure returns (uint256) {
        return roundUp(x18, 1e12);
    }

    function roundUp(uint256 x, uint256 d) internal pure returns (uint256) {
        return (x + d - 1) / d;
    }
}
