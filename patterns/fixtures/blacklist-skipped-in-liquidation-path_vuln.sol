// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BlacklistSkippedInLiquidationPathVuln {
    mapping(address => bool) public blacklisted;
    mapping(address => uint256) public collateral;

    function setBlack(address u, bool b) external { blacklisted[u] = b; }

    function repayBorrow(address borrower, uint256 amount) external {
        require(!blacklisted[borrower], "blacklisted");
        collateral[borrower] -= amount;
    }

    function liquidate(address borrower, uint256 amount) external {
        // VULN: no blacklist check on liquidation path.
        collateral[borrower] -= amount;
    }
}
