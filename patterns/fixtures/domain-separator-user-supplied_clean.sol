// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MetaTxClean {
    mapping(address => uint256) public nonces;
    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("MetaTx"),
            block.chainid,
            address(this)
        ));
    }

    // CLEAN: DOMAIN_SEPARATOR is immutable, not user-supplied
    function executeMetaTx(
        address from,
        uint256 nonce,
        bytes calldata data,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 structHash = keccak256(abi.encode(from, nonce, keccak256(data)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer == from, "bad sig");
        require(nonces[from]++ == nonce, "bad nonce");
        (bool ok, ) = address(this).call(data);
        require(ok, "call fail");
    }
}
