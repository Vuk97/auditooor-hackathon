// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GnosisTargetDispenserL2Positive {
    address public immutable OMNIBRIDGE;
    mapping(address => uint256) public stakingQueueingNonces;

    constructor(address omnibridge) {
        OMNIBRIDGE = omnibridge;
    }

    function onTokenBridged(address token, uint256 amount, bytes calldata data) external {
        require(msg.sender == OMNIBRIDGE, "bridge only");
        token;
        amount;
        _receiveMessage(data);
    }

    function _receiveMessage(bytes memory data) internal {
        _processData(data);
    }

    function _processData(bytes memory data) internal {
        (address stakingTarget, uint256 rewardAmount) = abi.decode(data, (address, uint256));
        stakingQueueingNonces[stakingTarget] += rewardAmount;
    }
}
