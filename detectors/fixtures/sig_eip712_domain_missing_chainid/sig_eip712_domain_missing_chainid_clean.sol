// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: EIP-712 domain separator includes chainId in both the typehash
// and the encoded value.
contract DomainMissingChainIdClean {
    bytes32 private constant TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    function buildDomainSeparator() public view returns (bytes32) {
        bytes32 domainSeparator = keccak256(abi.encode(
            TYPEHASH,
            keccak256("MyApp"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
        return domainSeparator;
    }

    function verify(bytes32 structHash, uint8 v, bytes32 r, bytes32 s)
        external
        view
        returns (address)
    {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", buildDomainSeparator(), structHash)
        );
        return ecrecover(digest, v, r, s);
    }
}
