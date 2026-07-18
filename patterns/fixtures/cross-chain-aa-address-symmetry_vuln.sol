// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: cross-chain entrypoint hardcodes destination = msg.sender.
// Modeled on Brix Money M-03 (Code4rena 2025-11).

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

// OApp / OFT style marker (matches preconditions regex).
abstract contract OAppReceiver {}

contract VulnBridge is OAppReceiver {
    IOFT public immutable oft;
    uint32 public immutable remoteEid;

    constructor(address _oft, uint32 _eid) {
        oft = IOFT(_oft);
        remoteEid = _eid;
    }

    function addressToBytes32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    // VULN 1: recipient hardcoded to msg.sender.
    function unstake(uint256 amount) external payable {
        SendParam memory p = SendParam({
            dstEid: remoteEid,
            to: addressToBytes32(msg.sender), // bug: breaks AA wallets
            amountLD: amount,
            minAmountLD: amount,
            extraOptions: "",
            composeMsg: "",
            oftCmd: ""
        });
        oft.send{value: msg.value}(p, MessagingFee(msg.value, 0), msg.sender);
    }

    // VULN 2: fastRedeem same bug.
    function fastRedeem(uint256 amount) external payable {
        SendParam memory p;
        p.dstEid = remoteEid;
        p.to = addressToBytes32(msg.sender); // same bug
        p.amountLD = amount;
        p.minAmountLD = amount;
        oft.send{value: msg.value}(p, MessagingFee(msg.value, 0), msg.sender);
    }
}
