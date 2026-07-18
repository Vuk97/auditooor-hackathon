// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AbiWriteOutputsMemoryCorruptionClean {
    bytes32 public lastOutput;

    function writeOutput(uint256 index, bytes32 value) external returns (bytes32[] memory outputs) {
        outputs = new bytes32[](2);
        require(index < outputs.length, "output index out of bounds");
        assembly {
            mstore(add(add(outputs, 0x20), mul(index, 0x20)), value)
        }
        lastOutput = outputs[0];
    }
}
