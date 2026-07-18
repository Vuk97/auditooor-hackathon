// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function balanceOf(address) external view returns (uint256); }

contract BondingCurveVuln {
    IERC20 public quoteToken;
    uint256 public constant GRADUATION_THRESHOLD = 1_000_000e18;
    bool public graduated;

    // VULN: graduation triggered by spot balance inside one tx
    function checkGraduation() external {
        require(!graduated, "already");
        uint256 bal = quoteToken.balanceOf(address(this));
        if (bal >= GRADUATION_THRESHOLD) {
            graduated = true;
            // migrate liquidity, flip fee schedule, etc.
        }
    }
}
