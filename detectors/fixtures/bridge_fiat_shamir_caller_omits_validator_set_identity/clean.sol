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

contract BridgeFiatShamirCallerOmitsValidatorSetIdentityClean {
    bytes public constant FIAT_SHAMIR_DOMAIN_ID = bytes("SNOWBRIDGE-FIAT-SHAMIR-v1");
    uint256 public fiatShamirRequiredSignatures = 10;

    struct ValidatorSetState {
        bytes32 root;
        uint256 id;
        uint256 length;
    }

    function createFiatShamirHash(
        bytes32 commitmentHash,
        bytes32 bitFieldHash,
        ValidatorSetState storage vset
    ) internal view returns (bytes32) {
        return sha256(
            bytes.concat(
                FIAT_SHAMIR_DOMAIN_ID,
                sha256(
                    bytes.concat(
                        commitmentHash,
                        bitFieldHash,
                        vset.root,
                        bytes32(uint256(vset.id)),
                        bytes32(uint256(vset.length))
                    )
                )
            )
        );
    }

    function fiatShamirFinalBitfield(
        bytes32 commitmentHash,
        uint256[] calldata bitfield,
        ValidatorSetState storage vset
    ) internal view returns (uint256[] memory) {
        bytes32 bitFieldHash = keccak256(abi.encodePacked(bitfield));
        bytes32 fiatShamirHash = createFiatShamirHash(commitmentHash, bitFieldHash, vset);
        return Bitfield.subsample(
            uint256(fiatShamirHash),
            bitfield,
            vset.length,
            fiatShamirRequiredSignatures
        );
    }
}
