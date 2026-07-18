pragma solidity ^0.8.20;

library ECDSA {
    function recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        digest;
        signature;
        return address(0xBEEF);
    }
}

abstract contract EIP712Base {
    bytes32 internal constant DOMAIN_SEPARATOR = keccak256("domain");

    function _hashTypedDataV4(bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }
}

contract VeGovernorPositive is EIP712Base {
    bytes32 internal constant VOTE_TYPEHASH =
        keccak256("Vote(address voter,uint256 proposalId,uint8 support,uint256 nonce,uint256 deadline)");

    mapping(uint256 => address) internal owners;
    mapping(uint256 => mapping(uint256 => uint8)) public votes;

    function ownerOf(uint256 tokenId) public view returns (address) {
        return owners[tokenId];
    }

    function castVoteBySig(
        uint256 tokenId,
        address voter,
        uint256 proposalId,
        uint8 support,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external {
        bytes32 structHash = keccak256(
            abi.encode(VOTE_TYPEHASH, voter, proposalId, support, nonce, deadline)
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        require(ownerOf(tokenId) == signer, "wrong token owner");
        require(block.timestamp <= deadline, "expired");
        votes[tokenId][proposalId] = support;
    }
}
