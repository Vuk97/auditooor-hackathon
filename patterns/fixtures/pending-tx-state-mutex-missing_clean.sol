// SPDX-License-Identifier: MIT
// Fixture: pending-tx-state-mutex-missing — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IBridgeReceiver {
    function onReceive(bytes32 msgId, bytes calldata payload) external;
}

contract PendingMutexClean {
    mapping(bytes32 => bool) public inFlight;

    IBridgeReceiver public relayer;

    // CLEAN: uses try/catch around the external call. If the call reverts,
    // the catch arm explicitly clears inFlight[msgId] so the mutex never
    // stays stuck.
    function send(bytes32 msgId, bytes calldata payload) external {
        require(!inFlight[msgId], "already pending");
        inFlight[msgId] = true;
        try relayer.onReceive(msgId, payload) {
            // happy path — callback will clear on success
        } catch {
            // liveness rescue: mutex must not stay stuck on revert
            inFlight[msgId] = false;
        }
    }
}
