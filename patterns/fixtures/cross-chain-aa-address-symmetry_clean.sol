// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: recipient is explicit parameter OR pulled from a per-user
// per-chain registry.

struct SendParam {
    uint32 dstEid;
    bytes32 to;
    uint256 amountLD;
    uint256 minAmountLD;
    bytes extraOptions;
    bytes composeMsg;
    bytes oftCmd;
}

struct MessagingFee {
    uint256 nativeFee;
    uint256 lzTokenFee;
}

interface IOFT {
    function send(SendParam calldata, MessagingFee calldata, address) external payable;
}

abstract contract OAppReceiver {}

contract CleanBridge is OAppReceiver {
    IOFT public immutable oft;
    uint32 public immutable remoteEid;
    mapping(address => mapping(uint32 => bytes32)) public destinationOf;

    constructor(address _oft, uint32 _eid) {
        oft = IOFT(_oft);
        remoteEid = _eid;
    }

    // CLEAN 1: explicit recipient parameter.
    function unstake(uint256 amount, bytes32 destinationRecipient) external payable {
        require(destinationRecipient != bytes32(0), "no recipient");
        SendParam memory p = SendParam({
            dstEid: remoteEid,
            to: destinationRecipient,
            amountLD: amount,
            minAmountLD: amount,
            extraOptions: "",
            composeMsg: "",
            oftCmd: ""
        });
        oft.send{value: msg.value}(p, MessagingFee(msg.value, 0), msg.sender);
    }

    // CLEAN 2: registry-resolved destination.
    function fastRedeem(uint256 amount) external payable {
        bytes32 to = destinationOf[msg.sender][remoteEid];
        require(to != bytes32(0), "register dest first");
        SendParam memory p;
        p.dstEid = remoteEid;
        p.to = to;
        p.amountLD = amount;
        p.minAmountLD = amount;
        oft.send{value: msg.value}(p, MessagingFee(msg.value, 0), msg.sender);
    }

    function registerDestination(uint32 eid, bytes32 dst) external {
        destinationOf[msg.sender][eid] = dst;
    }
}
