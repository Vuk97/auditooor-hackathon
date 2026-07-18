// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. The contract stores
/// a KECCAK COMMITMENT (`passwordHash`) rather than a secret itself.
/// None of the state var names contain the sensitive substrings
/// (`password` / `secret` / `privateKey` / `apiKey` / `seedPhrase` /
/// `mnemonic`) in a position where the regex would match an
/// assignment, so `body_contains_regex` does not trigger.
contract PrivateDataOnChainStorageClean {
    // A commitment is public — that is correct and intentional. The
    // preimage stays with the user and is supplied at verification time.
    bytes32 public passwordHash;
    bytes32 public secretHash;

    address public owner;

    constructor(bytes32 _passwordHash) {
        owner = msg.sender;
        passwordHash = _passwordHash;
    }

    // CLEAN: the argument is a precomputed hash, and the state var
    // name is `passwordHash` — the regex targeting
    // `(password|_password|secret|_secret|privateKey|_privateKey|
    // apiKey|_apiKey)\s*=` does not match `passwordHash =` because
    // the capture group requires the end of a word boundary before
    // the `=`. (The hash suffix is part of the identifier, not
    // whitespace.) The detector does NOT fire.
    function setPasswordHash(bytes32 _hash) external {
        require(msg.sender == owner, "not owner");
        passwordHash = _hash;
    }

    function setSecretHash(bytes32 _hash) external {
        require(msg.sender == owner, "not owner");
        secretHash = _hash;
    }

    // A normal non-sensitive setter.
    function setOwner(address _owner) external {
        require(msg.sender == owner, "not owner");
        owner = _owner;
    }

    // Verify by preimage — the secret never lives on chain, only the
    // commitment does. The user supplies the preimage in calldata
    // at verification, where it is ephemeral (not persisted to a slot).
    function verify(bytes calldata preimage) external view returns (bool) {
        return keccak256(preimage) == passwordHash;
    }
}
