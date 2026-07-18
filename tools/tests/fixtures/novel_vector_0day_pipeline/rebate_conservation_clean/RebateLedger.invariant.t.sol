// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./RebateLedger.sol";

interface Vm {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
}

/// @notice NOVEL-VECTOR / true-0-day NEGATIVE-CONTROL harness for the clean
/// RebateLedger. Identical to the vulnerable harness; asserts the same
/// spec-derived invariant INV-REBATE-CONSERVATION (totalCredits <= rebatePool).
/// On the fixed ledger the boundary sequence cannot break conservation, so the
/// assertion PASSES (Rule 40 point 4: the clean variant must pass).
///
/// Expected outcome: the conservation assertion PASSES here.
/// Run:  forge test --match-path '*RebateLedger.invariant.t.sol'
contract RebateLedgerConservationTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    RebateLedger internal ledger;
    address internal admin = address(this);
    address internal maker = address(0xBEEF);

    function setUp() public {
        ledger = new RebateLedger();
    }

    function invariant_rebateConservation() public view {
        require(
            ledger.totalCredits() <= ledger.rebatePool(),
            "INV-REBATE-CONSERVATION violated: total credits exceed funded pool"
        );
    }

    /// @notice Same boundary sequence as the vulnerable harness. On the clean
    /// ledger the unconditional ceiling check makes the second cross-epoch
    /// settle revert with "exceeds pool", so conservation is never broken. The
    /// control fund is sized so the first settle succeeds and the second cannot
    /// over-credit.
    function test_conservation_holds_on_epoch_boundary() public {
        // Fund the standing pool ceiling, matching the vulnerable PoC.
        ledger.fundPool(100 ether);

        // First settle succeeds: ceiling 0 + 100 <= 100 holds; credits=100.
        ledger.settleEpoch(maker, 100 ether);

        // Roll epoch and attempt the second settle. The fix runs the ceiling
        // check unconditionally: 100 + 100 <= 100 is false, so this reverts and
        // cannot inflate credits past the funded pool.
        ledger.rollEpoch();
        try ledger.settleEpoch(maker, 100 ether) {
            // If it did NOT revert, conservation must still hold.
        } catch {
            // Expected: exceeds-pool revert keeps conservation intact.
        }

        // Spec-derived conservation invariant holds for the reachable state.
        invariant_rebateConservation();
    }
}
