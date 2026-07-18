// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BridgeTokenClean {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public bridgedAmount; // track amount, not sticky bool

    function _creditBridged(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        bridgedAmount[to] += amount;
    }

    function bridgeIn(address to, uint256 amount) external {
        _creditBridged(to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 fromBridged = bridgedAmount[msg.sender];
        // restriction proportional to actually-held bridged balance, not sticky
        if (amount <= fromBridged) {
            bridgedAmount[msg.sender] -= amount;
        }
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
