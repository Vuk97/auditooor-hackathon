// SPDX-License-Identifier: MIT
// Fixture: tx-refund-native-eth-unchecked — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

contract CleanRefunder {
    mapping(address => uint256) public pending;

    function deposit() external payable {
        pending[msg.sender] += msg.value;
    }

    // CLEAN: captures the returned bool and requires success.
    function withdraw() external {
        uint256 amt = pending[msg.sender];
        require(amt > 0, "nothing");
        pending[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok, "refund failed");
    }

    // CLEAN variant: explicit `success` naming and require check.
    function buy(uint256 price) external payable {
        require(msg.value >= price, "underpaid");
        uint256 excess = msg.value - price;
        if (excess > 0) {
            (bool success,) = msg.sender.call{value: excess}("");
            require(success, "refund failed");
        }
    }
}
