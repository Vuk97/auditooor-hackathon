// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InterestTokenVuln {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public userIndex;
    uint256 public interestIndex = 1e18;

    function _updateInterestIndex(address) internal {
        // accrues interest to the user based on index drift
    }

    /// VULN: _transfer does not update interest index for from/to.
    function _transfer(address from, address to, uint256 amt) internal {
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _transfer(msg.sender, to, amt);
        return true;
    }
}
