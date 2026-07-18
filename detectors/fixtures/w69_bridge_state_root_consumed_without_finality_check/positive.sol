// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOutputOraclePositive {
    function outputRootAt(uint256 index) external view returns (bytes32);
    function isFinalized(uint256 index) external view returns (bool);
}

contract W69BridgeStateRootConsumedWithoutFinalityCheckPositive {
    IOutputOraclePositive public immutable oracle;

    constructor(IOutputOraclePositive oracle_) {
        oracle = oracle_;
    }

    function verifyConsensusProof(
        uint256 index,
        bytes32 claimedStateRoot,
        bytes calldata proof
    ) external view returns (bytes32) {
        proof;
        bytes32 outputRoot = oracle.outputRootAt(index);
        require(claimedStateRoot == outputRoot, "root mismatch");
        return outputRoot;
    }
}
