// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMessageBridge {
    function sendMessage(address target, bytes calldata data, uint256 gasLimit) external payable;
}

contract StickyReceiptFlagVuln {
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public hasReceived;

    function receiveReceipt(address receiver, uint256 amount) external {
        balanceOf[receiver] += amount;
        hasReceived[receiver] = true;
    }

    function claimUnlocked() external {
        require(!hasReceived[msg.sender], "receipt locked");
    }
}

contract RawCrossChainGasCapVuln {
    IMessageBridge public bridge;

    constructor(IMessageBridge bridge_) {
        bridge = bridge_;
    }

    function sendCrossChain(
        address target,
        bytes calldata data,
        uint256 gasLimit
    ) external payable {
        bridge.sendMessage{value: msg.value}(target, data, gasLimit);
    }
}
