// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICallee { function onExec(bytes calldata data) external; }

// VULN: threshold-gated execute makes an external call and then mutates the
// nonce / signer bookkeeping, with no nonReentrant guard. A malicious callee
// can re-enter a signer-set mutator before the outer state write commits,
// lowering the effective threshold below `requiredSignatures`.
contract MultisigThresholdBypassVuln {
    uint256 public threshold;
    uint256 public requiredSignatures;
    uint256 public signerCount;
    uint256 public nonce;
    mapping(address => bool) public isSigner;

    constructor(uint256 _threshold) {
        threshold = _threshold;
        requiredSignatures = _threshold;
    }

    // VULN shape 1: execute performs external call then writes nonce.
    function execute(address target, bytes calldata data, bytes[] calldata sigs) external {
        require(sigs.length >= threshold, "under threshold");
        ICallee(target).onExec(data);
        // Post-external-call state mutation — classic CEI violation.
        nonce += 1;
    }

    // VULN shape 2: executeTx name variant, same bug pattern.
    function executeTx(address target, bytes calldata data) external {
        require(signerCount >= requiredSignatures, "not enough signers");
        ICallee(target).onExec(data);
        signerCount -= 1;
    }

    // VULN shape 3: checkSignatures style used by HatsSignerGate.
    function checkSignatures(address target, bytes calldata data) external {
        ICallee(target).onExec(data);
        threshold = threshold; // touch state after external call
        nonce += 1;
    }
}
