// SPDX-License-Identifier: UNLICENSED
// Synthetic test contract for Auditooor Phase 8. Demonstrates the Kelp rsETH
// exploit class — has intentional bugs that our detectors should catch.
//
// Do NOT deploy. Do NOT use. This file deliberately omits every safeguard
// that a real LayerZero / OFT / Bridge adapter MUST have. It exists purely
// so that `make test-pattern` and `python3 tools/run_custom.py` fire on
// predictable locations.
//
// Expected detector hits (see test_poc/README.md for how to invoke):
//   1. r94-loop-oapp-config-safe-dvn-threshold-not-enforced-on-setconfig
//   2. r94-loop-oft-adapter-lzreceive-no-source-burn-proof
//   3. r94-loop-oft-adapter-release-no-post-release-min-supply-cap
//   4. r94-loop-bridge-destination-adapter-ignores-source-pause-state
//   5. r94-loop-bridge-pause-only-tokens-not-attestation-layer

pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount), "SafeERC20: transfer failed");
    }
}

// Inheritance-less on purpose — all contract-level preconditions are
// satisfied by name/source matches on "OFT", "Adapter", "Bridge",
// "LayerZero", "Config", "Pause".
contract OFTAdapter {
    using SafeERC20 for IERC20;

    struct UlnConfig {
        uint8 requiredDVNCount;
        uint8 optionalDVNCount;
        uint8 optionalDVNThreshold;
        address[] requiredDVNs;
    }

    address public owner;
    IERC20 public underlying;          // the wrapped/bridged asset (token.transfer target)
    UlnConfig public ulnConfig;         // LayerZero ULN attestation config
    bool public paused;                 // token-transfer pause only
    uint256 public inventory;           // adapter's held balance

    // Deliberately absent: verifyPaused / commitPaused / attestationPaused /
    //                    pauseReceiveLibrary / bridgeFullyPaused
    // Deliberately absent: maxPerMessage / MIN_RESERVE / rateLimiter
    // Deliberately absent: any lightClientVerify / verifySourceBurn /
    //                    merkleProofOfBurn / assertSourceStateRoot
    // Deliberately absent: isSourcePaused / querySourcePauseState /
    //                    crossChainPauseSync / sourcePauseOracle

    constructor(address _underlying) {
        owner = msg.sender;
        underlying = IERC20(_underlying);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // BUG #1 — oapp-config-safe-dvn-threshold-not-enforced-on-setconfig
    // Writes a new UlnConfig without asserting requiredDVNCount >= 2 or
    // optionalDVNThreshold >= 1. A single-DVN config is accepted silently,
    // which was the root cause of the Kelp rsETH $220M exploit — one
    // compromised DVN could forge attestations.
    function setConfig(uint8 requiredDVNCount, uint8 optionalDVNCount) external onlyOwner {
        address[] memory empty = new address[](0);
        ulnConfig = UlnConfig({
            requiredDVNCount: requiredDVNCount,
            optionalDVNCount: optionalDVNCount,
            optionalDVNThreshold: 0,
            requiredDVNs: empty
        });
        // NOTE: No `require(requiredDVNCount >= 2)`, no MIN_REQUIRED_DVN_COUNT,
        //       no SAFE_DVN_THRESHOLD, no validateDVNThreshold — this is the
        //       bug. setConfig(1, 0) succeeds.
    }

    // BUGS #2/#3/#4 — the multi-bug LayerZero OFT receive path.
    // BUG #2 (oft-adapter-lzreceive-no-source-burn-proof):
    //   Releases adapter inventory on bridge attestation only. There is no
    //   lightClientVerify / merkleProofOfBurn / sourceNonceEcho — if DVNs
    //   lie, the adapter still pays out.
    // BUG #3 (oft-adapter-release-no-post-release-min-supply-cap):
    //   No maxPerMessage / dailyLimit / MIN_RESERVE / rateLimiter — a single
    //   forged message can drain the full adapter inventory.
    // BUG #4 (bridge-destination-adapter-ignores-source-pause-state):
    //   No isSourcePaused / querySourcePauseState — even if the source chain
    //   halted mints, this adapter keeps releasing.
    function lzReceive(address recipient, uint256 amount) external {
        // trusted-but-unverified: caller is supposed to be the LayerZero
        // endpoint, but there is no source-chain proof of burn.
        inventory -= amount;
        underlying.safeTransfer(recipient, amount);
    }

    // BUG #5 — bridge-pause-only-tokens-not-attestation-layer.
    // Freezes token transfers but leaves the attestation layer running, so
    // an attacker can still commit further attestations post-freeze. This
    // is exactly how Kelp nonce 309 landed AFTER the sweep began.
    function pause() external onlyOwner {
        paused = true;
        // NOTE: No `verifyPaused = true`, no `attestationPaused = true`,
        //       no `endpoint.pause()`, no `pauseReceiveLibrary()`,
        //       no `bridgeFullyPaused = true`.
    }

    // Minimal helper so Slither considers the contract nontrivial.
    function fundInventory(uint256 amount) external onlyOwner {
        inventory += amount;
    }
}
