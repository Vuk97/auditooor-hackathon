pragma solidity ^0.8.20;

library Bitfield {
    function subsample(
        uint256,
        uint256[] calldata,
        uint256,
        uint256
    ) internal pure returns (uint256[] memory out) {
        out = new uint256[](1);
    }
}

contract BridgeFiatShamirCallerOmitsValidatorSetIdentityPositive {
    uint256 public fiatShamirRequiredSignatures = 10;

    function createFiatShamirHash(
        bytes32 commitmentHash,
        bytes32 bitFieldHash,
        bytes32 validatorSetRoot
    ) internal pure returns (bytes32) {
        return sha256(
            bytes.concat(sha256(bytes.concat(commitmentHash, bitFieldHash, validatorSetRoot)))
        );
    }

    function fiatShamirFinalBitfield(
        bytes32 commitmentHash,
        uint256[] calldata bitfield,
        uint256 validatorSetLength,
        bytes32 validatorSetRoot
    ) internal view returns (uint256[] memory) {
        bytes32 bitFieldHash = keccak256(abi.encodePacked(bitfield));
        bytes32 fiatShamirHash =
            createFiatShamirHash(commitmentHash, bitFieldHash, validatorSetRoot);
        return Bitfield.subsample(
            uint256(fiatShamirHash),
            bitfield,
            validatorSetLength,
            fiatShamirRequiredSignatures
        );
    }
}
