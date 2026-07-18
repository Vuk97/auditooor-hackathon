// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library OFTComposeMsgCodec {
    function composeFrom(bytes calldata message) internal pure returns (address sender) {
        (sender,) = abi.decode(message, (address, uint256));
    }
}

interface ILayerZeroComposer {
    function lzCompose(
        address _from,
        bytes32 _guid,
        bytes calldata _message,
        address _executor,
        bytes calldata _extraData
    ) external payable;
}

contract MissingOriginValidationInLayerzeroV2LzcomposeClean is ILayerZeroComposer {
    address public immutable endpoint;
    address public immutable trustedOft;
    address public immutable trustedSourceSender;
    mapping(address => uint256) public credits;

    constructor(address endpoint_, address trustedOft_, address trustedSourceSender_) {
        endpoint = endpoint_;
        trustedOft = trustedOft_;
        trustedSourceSender = trustedSourceSender_;
    }

    function lzCompose(
        address _from,
        bytes32,
        bytes calldata _message,
        address,
        bytes calldata
    ) external payable override {
        require(msg.sender == endpoint, "not endpoint");
        require(_from == trustedOft, "not trusted oft");
        address sourceSender = OFTComposeMsgCodec.composeFrom(_message);
        require(sourceSender == trustedSourceSender, "not source sender");

        (, uint256 amountLD) = abi.decode(_message, (address, uint256));
        credits[sourceSender] += amountLD;
    }
}
