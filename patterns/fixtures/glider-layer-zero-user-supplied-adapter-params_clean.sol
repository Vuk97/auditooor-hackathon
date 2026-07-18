// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILayerZeroEndpoint {
    function send(uint16 dstId, bytes calldata dstAddr, bytes calldata payload, address payable refund, address zro, bytes calldata adapterParams) external payable;
}

contract LzAdapterParamsClean {
    ILayerZeroEndpoint public endpoint;
    uint256 public constant MIN_GAS = 200000;

    function bridge(uint16 dstId, bytes calldata payload) external payable {
        bytes memory adapterParams = abi.encodePacked(uint16(1), MIN_GAS);
        endpoint.send{value: msg.value}(dstId, hex"", payload, payable(msg.sender), address(0), adapterParams);
    }
}
