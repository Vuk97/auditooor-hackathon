// SPDX-License-Identifier: MIT
// Fixture: tx-refund-native-eth-unchecked — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

contract VulnRefunder {
    mapping(address => uint256) public pending;

    function deposit() external payable {
        pending[msg.sender] += msg.value;
    }

    // VULN: state cleared first (good CEI ordering) BUT the low-level call
    // return value is discarded. A reverting / selfdestructed recipient
    // silently fails the refund while `pending` has already been zeroed —
    // funds are stuck with no recovery.
    function withdraw() external {
        uint256 amt = pending[msg.sender];
        require(amt > 0, "nothing");
        pending[msg.sender] = 0;
        msg.sender.call{value: amt}("");
    }

    // VULN variant: refund of excess payment, return value also discarded.
    function buy(uint256 price) external payable {
        require(msg.value >= price, "underpaid");
        uint256 excess = msg.value - price;
        if (excess > 0) {
            msg.sender.call{value: excess}("");
        }
    }
}
