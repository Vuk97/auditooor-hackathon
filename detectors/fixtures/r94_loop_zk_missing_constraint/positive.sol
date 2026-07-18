pragma solidity ^0.8.20;

contract R94LoopZkMissingConstraintVerifierPositive {
    function verifyProof(
        uint256 proverSuppliedOpening,
        uint256 logBlowup
    ) external pure returns (bytes32) {
        uint256 alphaPows = proverSuppliedOpening * (logBlowup + 1);
        return keccak256(abi.encode(alphaPows, proverSuppliedOpening, logBlowup));
    }
}
