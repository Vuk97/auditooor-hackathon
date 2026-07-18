// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBridgeMessenger {
    function messageSender() external view returns (address);
}

contract GnosisTargetDispenserL2Clean {
    address public immutable OMNIBRIDGE;
    IBridgeMessenger public immutable BRIDGE_MESSENGER;
    address public immutable L1_DISPATCHER;

    mapping(address => uint256) public stakingQueueingNonces;
    uint256 public bridgedBalance;

    constructor(address omnibridge, IBridgeMessenger bridgeMessenger, address l1Dispatcher) {
        OMNIBRIDGE = omnibridge;
        BRIDGE_MESSENGER = bridgeMessenger;
        L1_DISPATCHER = l1Dispatcher;
    }

    function onTokenBridged(address token, uint256 amount, bytes calldata data) external {
        require(msg.sender == OMNIBRIDGE, "bridge only");
        token;
        data;
        bridgedBalance += amount;
    }

    function receiveMessage(bytes calldata data) external {
        require(msg.sender == address(BRIDGE_MESSENGER), "messenger only");
        require(BRIDGE_MESSENGER.messageSender() == L1_DISPATCHER, "bad l1 sender");
        _processData(data);
    }

    function _processData(bytes memory data) internal {
        (address stakingTarget, uint256 rewardAmount) = abi.decode(data, (address, uint256));
        stakingQueueingNonces[stakingTarget] += rewardAmount;
    }
}
