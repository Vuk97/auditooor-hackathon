// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOutputOracleClean {
    function outputRootAt(uint256 index) external view returns (bytes32);
    function isFinalized(uint256 index) external view returns (bool);
}

contract W69BridgeStateRootConsumedWithoutFinalityCheckClean {
    error NotFinalized();

    IOutputOracleClean public immutable oracle;

    constructor(IOutputOracleClean oracle_) {
        oracle = oracle_;
    }

    function verifyConsensusProof(
        uint256 index,
        bytes32 claimedStateRoot,
        bytes calldata proof
    ) external view returns (bytes32) {
        proof;
        if (!oracle.isFinalized(index)) revert NotFinalized();
        bytes32 outputRoot = oracle.outputRootAt(index);
        require(claimedStateRoot == outputRoot, "root mismatch");
        return outputRoot;
    }
}
