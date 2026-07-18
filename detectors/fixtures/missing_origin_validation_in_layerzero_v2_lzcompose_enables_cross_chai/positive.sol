// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILayerZeroComposer {
    function lzCompose(
        address _from,
        bytes32 _guid,
        bytes calldata _message,
        address _executor,
        bytes calldata _extraData
    ) external payable;
}

contract MissingOriginValidationInLayerzeroV2LzcomposePositive is ILayerZeroComposer {
    address public immutable endpoint;
    mapping(address => uint256) public credits;

    constructor(address endpoint_) {
        endpoint = endpoint_;
    }

    function lzCompose(
        address _from,
        bytes32,
        bytes calldata _message,
        address,
        bytes calldata
    ) external payable override {
        require(msg.sender == endpoint, "not endpoint");
        (address recipient, uint256 amountLD) = abi.decode(_message, (address, uint256));
        credits[recipient] += amountLD;
        _from;
    }
}
