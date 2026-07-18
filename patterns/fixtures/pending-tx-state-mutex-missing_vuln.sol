// SPDX-License-Identifier: MIT
// Fixture: pending-tx-state-mutex-missing — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IBridgeReceiver {
    function onReceive(bytes32 msgId, bytes calldata payload) external;
}

contract PendingMutexVuln {
    // State-var name matches the precondition regex (pending|status|executing|locked|inFlight|processing).
    mapping(bytes32 => bool) public inFlight;

    IBridgeReceiver public relayer;

    // VULN: sets inFlight[msgId] = true, calls out to the relayer, and
    // relies on a separate callback path to clear the flag. If the external
    // call reverts OR the async callback never fires, the mutex is stuck
    // at `true` forever and every future call with the same msgId reverts.
    // No try/catch, no explicit `inFlight[x] = false` on any path.
    function send(bytes32 msgId, bytes calldata payload) external {
        require(!inFlight[msgId], "already pending");
        inFlight[msgId] = true;
        relayer.onReceive(msgId, payload);
        // no clear — depends on async callback that may never come
    }
}
