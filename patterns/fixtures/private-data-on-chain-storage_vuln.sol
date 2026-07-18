// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// private-data-on-chain-storage detector. DO NOT DEPLOY.
///
/// Each setter writes a value whose NAME implies secrecy to a storage
/// slot. The `private` visibility keyword in Solidity prevents other
/// Solidity contracts from reading via a generated getter, but it does
/// NOT encrypt the slot. Every value below is readable by anyone via
/// `eth_getStorageAt` and is permanently recorded in the calldata of
/// the setting transaction.
contract PrivateDataOnChainStorageVuln {
    bytes32 private password;
    bytes32 private secret;
    bytes32 private privateKey;
    bytes32 private apiKey;
    string  private seedPhrase;
    string  private mnemonic;

    // VULN: password written to storage.
    function setPassword(bytes32 _password) external {
        password = _password;
    }

    // VULN: secret written to storage.
    function setSecret(bytes32 _secret) external {
        secret = _secret;
    }

    // VULN: privateKey written to storage.
    function setPrivateKey(bytes32 _privateKey) external {
        privateKey = _privateKey;
    }

    // VULN: apiKey written to storage.
    function setApiKey(bytes32 _apiKey) external {
        apiKey = _apiKey;
    }

    // VULN: seedPhrase written to storage.
    function setSeedPhrase(string calldata _seed) external {
        seedPhrase = _seed;
    }

    // VULN: mnemonic written to storage.
    function setMnemonic(string calldata _mnemonic) external {
        mnemonic = _mnemonic;
    }
}
