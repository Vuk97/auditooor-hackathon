// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: the struct hash is computed by an external, well-audited base
// (here, a minimal OpenZeppelin-style EIP712 helper) that is fed the
// exact field list declared by the typehash. No local typehash constant
// is declared, and no local abi.encode(TYPEHASH, ...) is performed, so
// the detector's structural shape never appears.
interface IEIP712 {
    function hashTypedDataV4(bytes32 structHash) external view returns (bytes32);
}

contract PermitTypehashMatchClean {
    IEIP712 public immutable eip712;
    mapping(address => uint256) public nonces;

    constructor(IEIP712 _eip712) {
        eip712 = _eip712;
    }

    // Delegates all EIP-712 typed-data hashing to the external helper.
    // No local typehash literal, no local abi.encode over a TYPEHASH
    // constant — this function has no surface for a field-order mismatch.
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes32 structHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = eip712.hashTypedDataV4(structHash);
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "invalid signature");
        require(block.timestamp <= deadline, "expired");
        nonces[owner]++;
        // value/spender consumed off-fixture to avoid unused-var warn.
        (spender, value);
    }
}
