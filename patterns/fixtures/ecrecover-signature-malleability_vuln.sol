// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: the contract uses `ecrecover` directly with no bound on `s`.
// Any attacker who sees a valid signature can compute its malleable twin
// (v XOR 1, r, N - s) and produce a second distinct (v, r, s) tuple that
// also recovers to the signer. A replay guard keyed on the signature
// tuple is therefore bypassable.
contract SigGuardVuln {
    // replay guard keyed on raw signature bytes — broken under malleability
    mapping(bytes32 => bool) public usedSig;

    function execute(bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 sigKey = keccak256(abi.encodePacked(v, r, s));
        require(!usedSig[sigKey], "replay");
        usedSig[sigKey] = true;

        // direct ecrecover call, NO s-bound check anywhere in this function
        address signer = ecrecover(messageHash, v, r, s);
        require(signer != address(0), "bad sig");

        // ... effects on behalf of `signer` ...
    }
}
