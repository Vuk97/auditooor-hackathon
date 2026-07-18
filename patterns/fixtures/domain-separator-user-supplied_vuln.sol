// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MetaTxVuln {
    mapping(address => uint256) public nonces;

    // VULN: domainSeparator supplied by caller - no chain/contract binding
    function executeMetaTx(
        bytes32 domainSeparator,
        address from,
        uint256 nonce,
        bytes calldata data,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 structHash = keccak256(abi.encode(from, nonce, keccak256(data)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer == from, "bad sig");
        require(nonces[from]++ == nonce, "bad nonce");
        (bool ok, ) = address(this).call(data);
        require(ok, "call fail");
    }
}
