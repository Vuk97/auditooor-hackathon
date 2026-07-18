// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: calls ecrecover but first bounds `s` to the lower half of the
// secp256k1 group (EIP-2), which eliminates the malleable twin. The
// bound constant is 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
// (secp256k1n / 2), exactly the value OpenZeppelin's ECDSA library uses.
contract SigGuardClean {
    mapping(bytes32 => bool) public usedSig;

    function execute(bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) external {
        // EIP-2 s-bound check — kills malleability
        require(
            uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "bad s"
        );
        require(v == 27 || v == 28, "bad v");

        bytes32 sigKey = keccak256(abi.encodePacked(v, r, s));
        require(!usedSig[sigKey], "replay");
        usedSig[sigKey] = true;

        address signer = ecrecover(messageHash, v, r, s);
        require(signer != address(0), "bad sig");

        // ... effects on behalf of `signer` ...
    }
}
