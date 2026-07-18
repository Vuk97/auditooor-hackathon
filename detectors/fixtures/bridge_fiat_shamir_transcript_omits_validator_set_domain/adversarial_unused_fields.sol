pragma solidity ^0.8.20;

contract BridgeFiatShamirTranscriptUnusedFields {
    bytes public constant FIAT_SHAMIR_DOMAIN_ID = bytes("SNOWBRIDGE-FIAT-SHAMIR-v1");

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
        bytes memory unused = abi.encode(FIAT_SHAMIR_DOMAIN_ID, vset.id, vset.length);
        unused;
        return sha256(bytes.concat(sha256(bytes.concat(commitmentHash, bitFieldHash, vset.root))));
    }
}
