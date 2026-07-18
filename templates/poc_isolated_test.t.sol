// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

// =============================================================================
// auditooor — Isolated-logic PoC template
//
// Use this template when the finding can be reproduced in a local storage
// context without needing the full contract environment. Ideal for:
//   - Assembly pack/unpack overflow
//   - Rounding direction bugs in helper math
//   - State-machine edge cases
//   - Hash computation parity
//
// The PoC MIRRORS the production function EXACTLY (copy the assembly as-is)
// and tests it in isolation. This is faster, more deterministic, and easier
// for triage to verify than a full fork test.
// =============================================================================

import { Test } from "@forge-std/src/Test.sol";

/// @title MyIsolatedPoC
/// @notice 2-line description of the finding. Example: proves that
///         `_updateOrderStatus` assembly pack/unpack truncates the `remaining`
///         field when makerAmount > 2^248, enabling partial-fill replay.
contract MyIsolatedPoC is Test {
    // =============== LOCAL STORAGE MIRROR ===========================

    // Storage slot mirroring the production OrderStatus packed slot.
    // Layout: { bool filled (1 byte); uint248 remaining (31 bytes) }
    uint256 slot;

    // =============== PRODUCTION LOGIC (MIRRORED) ====================

    /// Mirror of the production `_updateOrderStatus` assembly from
    /// `src/exchange/mixins/Trading.sol:684-716`. Copy verbatim — do NOT
    /// simplify or "clean up" the production code, since the bug may depend
    /// on the exact assembly behavior.
    function _updateOrderStatus(uint256 makerAmount, uint256 makingAmount) internal returns (uint256 remainingOut) {
        bool filled;
        uint256 remaining;
        uint256 s = slot;
        assembly {
            filled := and(s, 0xff)
            remaining := shr(8, s)
        }

        require(!filled, "OrderAlreadyFilled");
        remaining = remaining == 0 ? makerAmount : remaining;
        require(makingAmount <= remaining, "MakingGtRemaining");

        unchecked {
            remaining = remaining - makingAmount;
        }

        uint256 packed;
        assembly {
            packed := or(shl(8, remaining), iszero(remaining))
        }
        slot = packed;

        return remaining;
    }

    function _readSlot() internal view returns (bool filled, uint256 remaining) {
        uint256 s = slot;
        assembly {
            filled := and(s, 0xff)
            remaining := shr(8, s)
        }
    }

    // =============== TESTS ==========================================

    /// Baseline: normal-sized input behaves correctly.
    function test_NormalCase_Works() public {
        uint256 r = _updateOrderStatus(1_000_000e6, 100_000e6);
        assertEq(r, 900_000e6);

        (bool filled, uint256 rem) = _readSlot();
        assertFalse(filled);
        assertEq(rem, 900_000e6);
    }

    /// The bug: adversarial input reproduces the truncation.
    function test_BugReproduces_AtBoundary() public {
        // Replace with your specific adversarial input.
        uint256 TWO_248 = 1 << 248;
        uint256 makerAmount = TWO_248 + 256;
        uint256 makingAmount = 256;

        // After first call, remaining = 2^248, which is outside uint248 when shl(8)ed
        uint256 r1 = _updateOrderStatus(makerAmount, makingAmount);
        assertEq(r1, TWO_248);

        (bool filled1, uint256 stored1) = _readSlot();
        assertFalse(filled1, "filled should be false");
        assertEq(stored1, 0, "BUG: slot should be 0 due to overflow");

        // Second call: ternary resets `remaining` to full makerAmount because
        // stored == 0. The partial fill is erased.
        uint256 r2 = _updateOrderStatus(makerAmount, makingAmount);
        assertEq(r2, TWO_248, "PROOF: order replayed");
    }

    /// Control: the safe boundary (just below the adversarial threshold)
    /// packs correctly. Proves the bug is specifically at the overflow edge.
    function test_SafeBoundary_PacksCorrectly() public {
        uint256 UINT248_MAX = (1 << 248) - 1;
        uint256 makerAmount = UINT248_MAX + 50;
        uint256 makingAmount = 50;

        _updateOrderStatus(makerAmount, makingAmount);
        (bool filled, uint256 rem) = _readSlot();
        assertFalse(filled);
        assertEq(rem, UINT248_MAX, "safe boundary works");
    }

    /// Documentation test: confirm the bound is absent from production
    /// source. This is a read-only test that does not exercise the bug;
    /// it exists to make the finding self-contained.
    function test_Documentation_NoBoundInSource() public pure {
        // Grep `src/exchange/mixins/Trading.sol` for `type(uint248)` — zero hits.
        // Grep for `MakerAmountTooLarge` — zero hits.
        // Conclusion: no bound is enforced, so the overflow path is reachable.
        assertTrue(true);
    }
}
