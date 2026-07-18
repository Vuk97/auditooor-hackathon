// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMessageBridge {
    function sendMessage(address target, bytes calldata data, uint256 gasLimit) external payable;
}

contract StickyReceiptFlagClean {
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public hasReceived;

    function receiveReceipt(address receiver, uint256 amount) external {
        balanceOf[receiver] += amount;
        hasReceived[receiver] = true;
    }

    function clearReceipt(address receiver) external {
        hasReceived[receiver] = false;
    }

    function claimUnlocked() external {
        require(!hasReceived[msg.sender], "receipt locked");
    }
}

contract PaddedCrossChainGasCapClean {
    IMessageBridge public bridge;
    uint256 public constant INTRINSIC_GAS = 21000;
    uint256 public constant OVERHEAD_GAS = 50000;
    uint256 internal constant _minGasPerByte = 16;

    constructor(IMessageBridge bridge_) {
        bridge = bridge_;
    }

    function sendCrossChain(
        address target,
        bytes calldata data,
        uint256 gasLimit
    ) external payable {
        uint256 paddedGas = gasLimit + INTRINSIC_GAS + OVERHEAD_GAS + data.length * _minGasPerByte;
        bridge.sendMessage{value: msg.value}(target, data, paddedGas);
    }

    function retryMessage(address target, bytes calldata data, uint256 gasLimit) external payable {
        uint256 paddedGas = gasLimit + INTRINSIC_GAS + OVERHEAD_GAS + data.length * _minGasPerByte;
        bridge.sendMessage{value: msg.value}(target, data, paddedGas);
    }
}
