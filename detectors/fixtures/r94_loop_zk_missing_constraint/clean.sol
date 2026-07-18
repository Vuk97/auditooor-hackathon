pragma solidity ^0.8.20;

contract R94LoopZkMissingConstraintVerifierClean {
    uint256 internal constant FIELD_MODULUS = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;

    function verifyProof(
        uint256 proverSuppliedOpening,
        uint256 logBlowup
    ) external pure returns (bytes32) {
        require(proverSuppliedOpening < FIELD_MODULUS, "opening");
        require(logBlowup <= 4, "blowup");
        uint256 alphaPows = proverSuppliedOpening * (logBlowup + 1);
        return keccak256(abi.encode(alphaPows, proverSuppliedOpening, logBlowup));
    }
}
