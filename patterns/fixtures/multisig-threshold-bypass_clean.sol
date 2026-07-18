// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICallee { function onExec(bytes calldata data) external; }

abstract contract Guard {
    uint256 private _s = 1;
    modifier nonReentrant() { require(_s != 2, "reenter"); _s = 2; _; _s = 1; }
}

// CLEAN: same multisig surface but every threshold-sensitive entrypoint either
// has a nonReentrant guard, or is refactored to strict CEI (state mutated
// before the external call).
contract MultisigThresholdBypassClean is Guard {
    uint256 public threshold;
    uint256 public requiredSignatures;
    uint256 public signerCount;
    uint256 public nonce;

    constructor(uint256 _threshold) {
        threshold = _threshold;
        requiredSignatures = _threshold;
    }

    // CLEAN: nonReentrant guard present.
    function execute(address target, bytes calldata data, bytes[] calldata sigs) external nonReentrant {
        require(sigs.length >= threshold, "under threshold");
        ICallee(target).onExec(data);
        nonce += 1;
    }

    // CLEAN: strict CEI — state updated BEFORE external call, so even a
    // re-entrant callee observes post-commit state.
    function executeTx(address target, bytes calldata data) external {
        require(signerCount >= requiredSignatures, "not enough signers");
        nonce += 1;
        ICallee(target).onExec(data);
    }

    // CLEAN: nonReentrant on checkSignatures-style entrypoint.
    function checkSignatures(address target, bytes calldata data) external nonReentrant {
        ICallee(target).onExec(data);
        nonce += 1;
    }
}
