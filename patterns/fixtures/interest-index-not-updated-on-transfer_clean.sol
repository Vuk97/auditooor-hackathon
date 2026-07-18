// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InterestTokenClean {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public userIndex;
    uint256 public interestIndex = 1e18;

    function _updateInterestIndex(address u) internal {
        userIndex[u] = interestIndex;
    }

    function _transfer(address from, address to, uint256 amt) internal {
        _updateInterestIndex(from);
        _updateInterestIndex(to);
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _transfer(msg.sender, to, amt);
        return true;
    }
}
