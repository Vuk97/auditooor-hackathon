// SPDX-License-Identifier: MIT
// A8 FP-GUARD fixture: an idempotent one-shot init that reaches a reinit step
// AND a value-move but has NO observable intermediate (no external call, no
// event, no lazy per-entity guard, no non-atomic revert path). This is an
// atomic deploy-time init - NOT a re-establishment obligation. The FP-guard
// MUST drop it -> detector SILENT.
pragma solidity ^0.8.0;

contract InitOnce {
    bool private inited;
    uint256 bal;

    function initializeV2(uint256 a) public {
        _reinit();
        transfer(a);
    }

    function _reinit() internal { inited = true; }
    function transfer(uint256 a) internal { bal = a; }
}
