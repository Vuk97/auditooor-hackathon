#!/usr/bin/env python3
"""Unit tests for tools/rounding-drain-lane.py (RDL).

Run with:
  cd /Users/wolf/auditooor-mcp && python3 -m unittest tools.tests.test_rounding_drain_lane -v

Test groups:
  1. SAFE-round skips (protocol-favoring rounding -> 0 hypotheses).
  2. DRAINABLE-round flags (user-favoring rounding -> >=1 hypothesis, verdict=needs-fuzz).
  3. AMBIGUOUS-round flags (undeterminable side -> flagged, needs-fuzz).
  4. Go sdk.Dec.Quo drain on intake path -> flagged.
  5. Rust integer div drain -> flagged.
  6. No-flood rule: a single function with only clearly-safe rounds -> 0 hypotheses.
  7. Multiple rounding ops in one function: deduplicated (only one hit per op_label).
  8. attack_class is "rounding-drain" on all emitted records.
  9. All emitted records carry verdict="needs-fuzz".
  10. No em-dash in any emitted record.
  11. VCIS-miss note present on every emitted hypothesis.
  12. conservation_invariant is non-empty on all emitted hypotheses.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------
_REPO = Path(__file__).resolve().parent.parent.parent
_TOOLS = _REPO / "tools"
_RDL_PATH = _TOOLS / "rounding-drain-lane.py"


def _load_rdl():
    spec = importlib.util.spec_from_file_location("rounding_drain_lane", _RDL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rounding_drain_lane"] = mod
    spec.loader.exec_module(mod)
    return mod


_RDL = None


def _rdl():
    global _RDL
    if _RDL is None:
        _RDL = _load_rdl()
    return _RDL


# ---------------------------------------------------------------------------
# Solidity fixture helpers
# ---------------------------------------------------------------------------

def _sol_payout_safe() -> str:
    """Protocol pays out to user via mulDivDown - SAFE (protocol-favoring).

    The user receives floor(amount * price / WAD): mulDivDown on payout = safe.
    This must produce 0 hypotheses.
    """
    return """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library FixedPoint {
    uint256 constant WAD = 1e18;
    function mulDivDown(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return a * b / c;
    }
}

contract SafePayout {
    using FixedPoint for uint256;

    mapping(address => uint256) public balances;

    // Protocol pays OUT to user: mulDivDown on payout -> SAFE (user gets floor).
    function redeem(uint256 units, uint256 price) external {
        uint256 payoutAmount = units.mulDivDown(price, 1e18);
        balances[msg.sender] -= units;
        safeTransfer(msg.sender, payoutAmount);
    }

    function safeTransfer(address to, uint256 amount) internal {}
}
"""


def _sol_intake_drain() -> str:
    """Protocol intakes from user via mulDivDown on fee path - DRAINABLE.

    The protocol collects floor(fee) instead of ceil(fee): mulDivDown on intake =
    drainable. This must produce >=1 hypothesis.
    """
    return """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library FixedPoint {
    uint256 constant WAD = 1e18;
    function mulDivDown(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return a * b / c;
    }
}

contract DrainableFee {
    using FixedPoint for uint256;

    mapping(address => uint256) public pendingFee;

    // Protocol collects fee via mulDivDown: rounds DOWN on intake -> DRAINABLE.
    // Morpho Midnight.sol line 386 analog: fee accrued to protocol rounds DOWN.
    function accrueInterest(uint256 units, uint256 continuousFee, uint256 timeToMaturity) external {
        // Protocol's fee intake is rounded down - under-collects 1 wei per call.
        uint256 feeAccrued = units.mulDivDown(continuousFee * timeToMaturity, 1e18);
        pendingFee[msg.sender] += feeAccrued;
    }
}
"""


def _sol_payout_drain() -> str:
    """Protocol pays out via mulDivUp on payout path - DRAINABLE.

    The user receives ceil(amount): mulDivUp on payout = drainable.
    Morpho Midnight.sol line 388/490 analog (pendingFeeDecrease = returned to user).
    Must produce >=1 hypothesis.
    """
    return """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library FixedPoint {
    uint256 constant WAD = 1e18;
    function mulDivUp(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return (a * b + c - 1) / c;
    }
}

contract DrainablePayout {
    using FixedPoint for uint256;

    mapping(address => uint256) public credit;

    // pendingFeeDecrease: amount returned to user on partial exit.
    // mulDivUp on payout path -> user gets ceiling -> protocol releases more than exact.
    function exitPartial(uint256 units, uint256 price) external {
        uint256 pendingFeeDecrease = units.mulDivUp(price, 1e18);
        credit[msg.sender] += pendingFeeDecrease;
        safeTransfer(msg.sender, pendingFeeDecrease);
    }

    function safeTransfer(address to, uint256 amount) internal {}
}
"""


def _sol_ambiguous() -> str:
    """Function with a mulDiv whose direction is ambiguous from context alone.

    The value path cannot be determined without inter-procedural analysis.
    Must produce >=1 hypothesis with verdict=needs-fuzz.
    """
    return """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library FullMath {
    function mulDiv(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return a * b / c;
    }
}

contract AmbiguousRounding {
    // FullMath.mulDiv: the result flows to a mapping field with no clear direction.
    function compute(uint256 a, uint256 b, uint256 denominator) external pure returns (uint256 result) {
        result = FullMath.mulDiv(a, b, denominator);
    }
}
"""


def _go_intake_drain() -> str:
    """Go/Cosmos: sdk.Dec.Quo on a fee path - DRAINABLE.

    Quo truncates (floor for positive decimals) on an intake path.
    Must produce >=1 hypothesis.
    """
    return """\
package keeper

import (
    sdk "github.com/cosmos/cosmos-sdk/types"
)

// CalcFee calculates the protocol fee using sdk.Dec.Quo (truncates).
// The fee is what the protocol collects - truncation = under-collection.
func (k Keeper) CalcFee(ctx sdk.Context, amount sdk.Int, rate sdk.Dec) sdk.Int {
    decAmount := sdk.NewDecFromInt(amount)
    // fee intake calculation: Quo truncates down on intake -> DRAINABLE
    fee := decAmount.Quo(rate)
    // Protocol stores the fee as its intake
    pendingFee := fee.TruncateInt()
    k.bankKeeper.SendCoinsFromModuleToModule(ctx, "user", "protocol", sdk.NewCoins(sdk.NewCoin("uatom", pendingFee)))
    return pendingFee
}
"""


def _rs_intake_drain() -> str:
    """Rust: integer division on a fee/intake path - DRAINABLE.

    checked_div truncates (floor for positive integers) on an intake path.
    Must produce >=1 hypothesis.
    """
    return """\
use cosmwasm_std::{Uint128, Decimal};

pub fn calc_protocol_fee(amount: Uint128, rate: Uint128) -> Uint128 {
    // Protocol fee: integer division truncates -> protocol under-collects
    // checked_div on intake/fee path -> DRAINABLE
    let fee = amount.checked_div(rate).unwrap_or(Uint128::zero());
    // Store as protocol's fee intake
    fee
}
"""


def _sol_clearly_safe_only() -> str:
    """A function with ONLY clearly-safe rounding (mulDivDown on payout).

    Must produce 0 hypotheses (no-flood rule).
    """
    return """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library FixedPoint {
    uint256 constant WAD = 1e18;
    function mulDivDown(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return a * b / c;
    }
}

contract SafeOnly {
    using FixedPoint for uint256;

    // Both rounding ops are on payout path with mulDivDown -> both SAFE -> 0 hypotheses.
    function withdraw(uint256 shares, uint256 priceA, uint256 priceB) external pure returns (uint256, uint256) {
        // mulDivDown on payout path: user gets floor -> SAFE
        uint256 amountA = shares.mulDivDown(priceA, 1e18);
        // mulDivDown on payout path again: user gets floor -> SAFE
        uint256 amountB = shares.mulDivDown(priceB, 1e18);
        return (amountA, amountB);
    }
}
"""


# ---------------------------------------------------------------------------
# Test Group 1: SAFE rounds produce 0 hypotheses
# ---------------------------------------------------------------------------
class TestSafeRoundingSkipped(unittest.TestCase):

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def test_payout_muldivdown_safe_produces_zero_hypotheses(self):
        """mulDivDown on payout path = SAFE; must produce 0 hypotheses."""
        mod = _rdl()
        source = _sol_payout_safe()
        hyps, invs = mod.hypotheses_from_source(
            source=source,
            language="sol",
            fn_name="redeem",
            file_rel="SafePayout.sol",
        )
        # The redeem function pays OUT to user via mulDivDown = protocol-favoring.
        # No hypothesis should be emitted.
        self.assertEqual(len(hyps), 0,
                         f"Safe payout mulDivDown must produce 0 hypotheses; got {len(hyps)}")

    def test_safe_only_function_produces_zero_hypotheses(self):
        """A function with only protocol-favoring rounding -> 0 hypotheses (no-flood)."""
        mod = _rdl()
        source = _sol_clearly_safe_only()
        hyps, invs = mod.hypotheses_from_source(
            source=source,
            language="sol",
            fn_name="withdraw",
            file_rel="SafeOnly.sol",
        )
        self.assertEqual(len(hyps), 0,
                         f"All-safe-rounding function must produce 0 hypotheses; got {len(hyps)}")


# ---------------------------------------------------------------------------
# Test Group 2: DRAINABLE rounds are flagged
# ---------------------------------------------------------------------------
class TestDrainableRoundingFlagged(unittest.TestCase):

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def test_intake_muldivdown_flagged(self):
        """mulDivDown on intake/fee path -> DRAINABLE -> flagged."""
        mod = _rdl()
        source = _sol_intake_drain()
        hyps, invs = mod.hypotheses_from_source(
            source=source,
            language="sol",
            fn_name="accrueInterest",
            file_rel="DrainableFee.sol",
        )
        self.assertGreater(len(hyps), 0,
                           "mulDivDown on intake path must produce >=1 hypothesis")
        for h in hyps:
            self.assertEqual(h["verdict"], "needs-fuzz",
                             "All hypotheses must carry verdict=needs-fuzz")
            self.assertEqual(h["attack_class"], "rounding-drain")

    def test_payout_muldivup_flagged(self):
        """mulDivUp on payout path -> DRAINABLE -> flagged.

        Morpho Midnight.sol pendingFeeDecrease analog.
        """
        mod = _rdl()
        source = _sol_payout_drain()
        hyps, invs = mod.hypotheses_from_source(
            source=source,
            language="sol",
            fn_name="exitPartial",
            file_rel="DrainablePayout.sol",
        )
        self.assertGreater(len(hyps), 0,
                           "mulDivUp on payout path must produce >=1 hypothesis")
        for h in hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")
            self.assertEqual(h["attack_class"], "rounding-drain")


# ---------------------------------------------------------------------------
# Test Group 3: AMBIGUOUS rounding flagged
# ---------------------------------------------------------------------------
class TestAmbiguousRoundingFlagged(unittest.TestCase):

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def test_ambiguous_muldiv_flagged(self):
        """A mulDiv whose value path is ambiguous -> flagged with verdict=needs-fuzz."""
        mod = _rdl()
        source = _sol_ambiguous()
        hyps, invs = mod.hypotheses_from_source(
            source=source,
            language="sol",
            fn_name="compute",
            file_rel="AmbiguousRounding.sol",
        )
        self.assertGreater(len(hyps), 0,
                           "Ambiguous rounding must produce >=1 hypothesis")
        for h in hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")
            self.assertEqual(h["attack_class"], "rounding-drain")


# ---------------------------------------------------------------------------
# Test Group 4: Go sdk.Dec.Quo on intake path -> flagged
# ---------------------------------------------------------------------------
class TestGoSDKDecQuoDrain(unittest.TestCase):

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def test_go_quo_on_fee_path_flagged(self):
        """Go sdk.Dec.Quo on fee/intake path -> DRAINABLE -> flagged."""
        mod = _rdl()
        source = _go_intake_drain()
        hyps, invs = mod.hypotheses_from_source(
            source=source,
            language="go",
            fn_name="CalcFee",
            file_rel="keeper.go",
        )
        self.assertGreater(len(hyps), 0,
                           "Go sdk.Dec.Quo on fee path must produce >=1 hypothesis")
        for h in hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")
            self.assertEqual(h["attack_class"], "rounding-drain")
            self.assertEqual(h["language"], "go")


# ---------------------------------------------------------------------------
# Test Group 5: Rust checked_div on fee path -> flagged
# ---------------------------------------------------------------------------
class TestRustCheckedDivDrain(unittest.TestCase):

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def test_rust_checked_div_on_fee_path_flagged(self):
        """Rust checked_div on intake/fee path -> DRAINABLE -> flagged."""
        mod = _rdl()
        source = _rs_intake_drain()
        hyps, invs = mod.hypotheses_from_source(
            source=source,
            language="rs",
            fn_name="calc_protocol_fee",
            file_rel="fees.rs",
        )
        self.assertGreater(len(hyps), 0,
                           "Rust checked_div on fee path must produce >=1 hypothesis")
        for h in hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")
            self.assertEqual(h["attack_class"], "rounding-drain")
            self.assertEqual(h["language"], "rs")


# ---------------------------------------------------------------------------
# Test Group 6: No-flood - verify NOT every mulDiv is flagged
# ---------------------------------------------------------------------------
class TestNoFloodRule(unittest.TestCase):

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def test_payout_muldivdown_not_flagged(self):
        """Proves that a clearly safe mulDivDown on payout is NOT flagged.

        This is the anti-flood assertion: the tool must not flag every mulDiv.
        """
        mod = _rdl()
        source = _sol_payout_safe()
        hyps, _ = mod.hypotheses_from_source(
            source=source,
            language="sol",
            fn_name="redeem",
            file_rel="SafePayout.sol",
        )
        self.assertEqual(len(hyps), 0,
                         "Anti-flood: safe payout mulDivDown must NOT be flagged")

    def test_safe_only_not_flagged(self):
        """Anti-flood: all-safe function produces exactly 0 hypotheses."""
        mod = _rdl()
        source = _sol_clearly_safe_only()
        hyps, _ = mod.hypotheses_from_source(
            source=source,
            language="sol",
            fn_name="withdraw",
            file_rel="SafeOnly.sol",
        )
        self.assertEqual(len(hyps), 0,
                         "Anti-flood: safe-only function must produce 0 hypotheses")


# ---------------------------------------------------------------------------
# Test Group 7: Schema invariants on all emitted records
# ---------------------------------------------------------------------------
class TestSchemaInvariants(unittest.TestCase):

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def _all_drain_hyps(self):
        """Collect hypotheses from all drain fixtures."""
        mod = _rdl()
        results = []
        for source_fn, lang, fn_name, file_rel in [
            (_sol_intake_drain, "sol", "accrueInterest", "DrainableFee.sol"),
            (_sol_payout_drain, "sol", "exitPartial",    "DrainablePayout.sol"),
            (_sol_ambiguous,    "sol", "compute",        "AmbiguousRounding.sol"),
            (_go_intake_drain,  "go",  "CalcFee",        "keeper.go"),
            (_rs_intake_drain,  "rs",  "calc_protocol_fee", "fees.rs"),
        ]:
            hyps, _ = mod.hypotheses_from_source(
                source=source_fn(),
                language=lang,
                fn_name=fn_name,
                file_rel=file_rel,
            )
            results.extend(hyps)
        return results

    def test_all_emitted_records_have_verdict_needs_fuzz(self):
        """Every emitted hypothesis must carry verdict=needs-fuzz (no-auto-credit)."""
        for h in self._all_drain_hyps():
            self.assertEqual(h.get("verdict"), "needs-fuzz",
                             f"Record for {h.get('function')} missing verdict=needs-fuzz")

    def test_all_emitted_records_have_attack_class_rounding_drain(self):
        """Every emitted hypothesis must have attack_class=rounding-drain."""
        for h in self._all_drain_hyps():
            self.assertEqual(h.get("attack_class"), "rounding-drain",
                             f"Record for {h.get('function')} wrong attack_class")

    def test_all_emitted_records_have_conservation_invariant(self):
        """Every hypothesis must include a non-empty conservation_invariant."""
        for h in self._all_drain_hyps():
            ci = h.get("conservation_invariant", "")
            self.assertTrue(ci, f"Record for {h.get('function')} missing conservation_invariant")

    def test_all_emitted_records_have_vcis_miss_note(self):
        """Every hypothesis must include a vcis_miss_reason (explains why VCIS misses it)."""
        for h in self._all_drain_hyps():
            reason = h.get("vcis_miss_reason", "")
            self.assertTrue(reason,
                            f"Record for {h.get('function')} missing vcis_miss_reason")

    def test_no_em_dash_in_emitted_records(self):
        """No em-dash (U+2014) or en-dash (U+2013) in any emitted record."""
        for h in self._all_drain_hyps():
            serialized = json.dumps(h)
            self.assertNotIn("—", serialized,
                             f"Em-dash found in record for {h.get('function')}")
            self.assertNotIn("–", serialized,
                             f"En-dash found in record for {h.get('function')}")

    def test_all_emitted_records_have_source_rdl(self):
        """Every hypothesis must have source=RDL."""
        for h in self._all_drain_hyps():
            self.assertEqual(h.get("source"), "RDL",
                             f"Record for {h.get('function')} missing source=RDL")


# ---------------------------------------------------------------------------
# Test Group 8: Workspace-level runner writes .jsonl sidecars
# ---------------------------------------------------------------------------
class TestWorkspaceRunner(unittest.TestCase):

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def _make_vmf_json(self, ws: Path, file_rel: str, fn_name: str, lang: str) -> Path:
        vmf_path = ws / ".auditooor" / "value_moving_functions.json"
        vmf_path.parent.mkdir(parents=True, exist_ok=True)
        vmf_path.write_text(json.dumps({
            "schema": "auditooor.value_moving_functions.v1",
            "functions": [
                {
                    "file":     file_rel,
                    "function": fn_name,
                    "language": lang,
                    "transfer_hit": True,
                    "ledger_write_hit": False,
                    "transfer_evidence": [],
                    "ledger_write_evidence": [],
                }
            ],
        }), encoding="utf-8")
        return vmf_path

    def test_workspace_runner_writes_hypotheses_jsonl(self):
        """run_rdl() must write rounding_drain_hypotheses.jsonl."""
        mod = _rdl()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()

            # Write a drainable Solidity source file.
            src_file = ws / "DrainableFee.sol"
            src_file.write_text(_sol_intake_drain(), encoding="utf-8")
            vmf_path = self._make_vmf_json(ws, "DrainableFee.sol", "accrueInterest", "sol")

            hyps, invs = mod.run_rdl(workspace=ws, vmf_json_path=vmf_path)

            out_jsonl = ws / ".auditooor" / "rounding_drain_hypotheses.jsonl"
            self.assertTrue(out_jsonl.is_file(),
                            "run_rdl must write rounding_drain_hypotheses.jsonl")

            records = [json.loads(l) for l in out_jsonl.read_text().splitlines() if l.strip()]
            self.assertGreater(len(records), 0,
                               "rounding_drain_hypotheses.jsonl must have >=1 record")
            for r in records:
                self.assertEqual(r["verdict"], "needs-fuzz")
                self.assertEqual(r["attack_class"], "rounding-drain")
                self.assertEqual(r["source"], "RDL")

    def test_workspace_runner_writes_invariants_jsonl(self):
        """run_rdl() must write rounding_drain_invariants.jsonl."""
        mod = _rdl()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()

            src_file = ws / "DrainableFee.sol"
            src_file.write_text(_sol_intake_drain(), encoding="utf-8")
            vmf_path = self._make_vmf_json(ws, "DrainableFee.sol", "accrueInterest", "sol")

            hyps, invs = mod.run_rdl(workspace=ws, vmf_json_path=vmf_path)

            out_inv = ws / ".auditooor" / "rounding_drain_invariants.jsonl"
            self.assertTrue(out_inv.is_file(),
                            "run_rdl must write rounding_drain_invariants.jsonl")

    def test_workspace_runner_safe_only_writes_empty_jsonl(self):
        """run_rdl() on a safe-only workspace must write an empty hypotheses file."""
        mod = _rdl()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()

            src_file = ws / "SafeOnly.sol"
            src_file.write_text(_sol_clearly_safe_only(), encoding="utf-8")
            vmf_path = self._make_vmf_json(ws, "SafeOnly.sol", "withdraw", "sol")

            hyps, invs = mod.run_rdl(workspace=ws, vmf_json_path=vmf_path)

            self.assertEqual(len(hyps), 0,
                             "Safe-only workspace must produce 0 hypotheses")
            out_jsonl = ws / ".auditooor" / "rounding_drain_hypotheses.jsonl"
            self.assertTrue(out_jsonl.is_file(),
                            "run_rdl must still write the .jsonl file (empty)")
            records = [json.loads(l) for l in out_jsonl.read_text().splitlines() if l.strip()]
            self.assertEqual(len(records), 0,
                             "Safe-only workspace must produce empty hypotheses jsonl")


# ---------------------------------------------------------------------------
# Test Group 9: finditer regression - two rounding ops on one line, first SAFE,
# second DRAINABLE -> drainable IS flagged (guards the finditer fix).
# ---------------------------------------------------------------------------

def _sol_two_ops_one_line_first_safe_second_drainable() -> str:
    """A function containing two mulDivDown occurrences: the FIRST on a payout path
    (SAFE - user gets floor via safeTransfer/mint) and the SECOND on a pure
    fee/interest intake path (DRAINABLE - protocol under-collects).

    The old search()+seen_op_labels design found the first mulDivDown, classified
    it SAFE, skipped it, added op_label='mulDivDown' to seen_op_labels, and then
    NEVER evaluated the second mulDivDown because op_label was already in seen.
    With finditer() both occurrences are classified independently; the second IS
    flagged.

    We use enough blank lines between the two uses so the 5-line context window
    does NOT bleed 'safeTransfer' from the first use into the second.  The second
    use's local context contains only fee/interest/debt signals so its value_path
    resolves to 'intake', making the down-round DRAINABLE.
    """
    return """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library FixedPoint {
    uint256 constant WAD = 1e18;
    function mulDivDown(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return a * b / c;
    }
}

contract TwoOpsInOneFn {
    using FixedPoint for uint256;

    mapping(address => uint256) public pendingFee;

    // mixedRounding exercises BOTH safe and drainable mulDivDown in one function.
    function mixedRounding(
        uint256 units,
        uint256 price,
        uint256 feeRate
    ) external {
        // ---------- SAFE block: payout path ----------
        // mulDivDown here: user receives floor -> protocol-favoring -> SAFE.
        uint256 payoutAmount = units.mulDivDown(price, 1e18);
        safeTransfer(msg.sender, payoutAmount);
        // end of safe payout block
        // padding line A
        // padding line B
        // padding line C
        // padding line D
        // padding line E
        // padding line F
        // ---------- DRAINABLE block: fee/interest intake path ----------
        // mulDivDown here: protocol collects floor(fee) -> under-collects -> DRAINABLE.
        // interest accrual: borrowRate drives a debt obligation owed TO the protocol.
        uint256 interestAccrued = units.mulDivDown(feeRate, 1e18);
        // record the fee the protocol is owed (debt / interest)
        pendingFee[address(this)] += interestAccrued;
    }

    function safeTransfer(address to, uint256 amount) internal {}
}
"""


class TestFindiIterFix(unittest.TestCase):
    """Regression tests that guard the finditer() fix."""

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def test_two_muldivdown_same_fn_first_safe_second_drainable_second_is_flagged(self):
        """REGRESSION: two mulDivDown in same fn; first=SAFE (payout), second=DRAINABLE
        (intake/fee).  With old search()+seen_op_labels the second was silently dropped.
        With finditer() the drainable occurrence IS flagged.
        """
        mod = _rdl()
        source = _sol_two_ops_one_line_first_safe_second_drainable()
        hyps, invs = mod.hypotheses_from_source(
            source=source,
            language="sol",
            fn_name="mixedRounding",
            file_rel="TwoOpsOneLine.sol",
        )
        self.assertGreater(
            len(hyps), 0,
            "finditer regression: second mulDivDown (DRAINABLE/intake) must be flagged "
            "even though the first mulDivDown on the same fn was SAFE and skipped.",
        )
        # All emitted records must carry verdict=needs-fuzz.
        for h in hyps:
            self.assertEqual(
                h["verdict"], "needs-fuzz",
                f"All hypotheses must carry verdict=needs-fuzz; got {h['verdict']}",
            )
        # At least one flagged record must relate to mulDivDown.
        op_labels = {h["rounding_op"].split("(")[0].strip() for h in hyps}
        self.assertTrue(
            any("mulDivDown" in s for s in op_labels),
            f"Expected at least one mulDivDown-related hit; got op_labels={op_labels}",
        )


# ---------------------------------------------------------------------------
# Test Group 10: Comment-line suppression - matches on comment/doc lines must
# NOT be emitted even when the op pattern fires on the comment text.
# ---------------------------------------------------------------------------

def _go_quo_in_comment_only() -> str:
    """Go function where .Quo( appears only in a comment, never in live code.

    The function does a pure ratio computation (display-only, no value-flow
    signals) and the only Quo reference is in a comment explaining the formula.
    Must produce 0 hypotheses because the only pattern match is on a comment line.
    """
    return """\
package keeper

// ComputeRatio returns the display ratio of a / b for UI only.
// It uses sdk.Dec.Quo(b) internally.
func (k Keeper) ComputeRatio(a, b int64) string {
    // This function is display-only; result is never stored or transferred.
    // ratio = sdk.Dec.Quo(b) conceptually, but we just do string formatting here.
    if b == 0 {
        return "N/A"
    }
    return fmt.Sprintf("%d/%d", a, b)
}
"""


def _go_quo_display_ratio_no_value_flow() -> str:
    """Go function that calls sdk.Dec.Quo but only for a ratio/display value.

    The local context around the Quo call has NO payout or intake signals -
    no transfer, no fee, no mint, no credit, no deposit.  The result is stored
    in a variable named 'ratio' and returned (no value-transfer call nearby).
    This is the 'ambiguous non-settlement Quo' case: it IS flagged (direction
    ambiguous, path ambiguous) because RDL cannot rule it out without
    inter-procedural analysis - but the test documents that it fires as
    AMBIGUOUS/needs-fuzz rather than DRAINABLE, and confirms the comment
    suppression does NOT accidentally drop the live-code Quo.
    """
    return """\
package keeper

func (k Keeper) GetFillRatio(filled, total int64) string {
    decFilled := sdk.NewDecFromInt(sdk.NewInt(filled))
    decTotal := sdk.NewDecFromInt(sdk.NewInt(total))
    ratio := decFilled.Quo(decTotal)
    return ratio.String()
}
"""


def _go_payout_muldivdown_in_comment_no_real_op() -> str:
    """Go function where a comment mentions TruncateInt but code has none.

    The function body contains a comment that says '// TruncateInt would lose
    precision' but the actual implementation uses a safe method.  No rounding
    op in live code -> 0 hypotheses.
    """
    return """\
package keeper

func (k Keeper) SafeTransferExact(amount int64) error {
    // TruncateInt would lose precision; we use exact integer arithmetic here.
    exactAmt := sdk.NewInt(amount)
    return k.bankKeeper.SendCoins(k.ctx, k.sender, k.receiver,
        sdk.NewCoins(sdk.NewCoin("uatom", exactAmt)))
}
"""


def _sol_morpho_pending_fee_style() -> str:
    """Morpho pendingFee-style: mulDivDown on a fee/interest intake path.

    Analog of Morpho Midnight.sol accrueInterest: the protocol accrues a fee
    (pendingFee) by rounding DOWN with mulDivDown.  The protocol under-collects
    1 wei per call.  This IS the canonical rounding-drain; must produce >=1 hyp.
    """
    return """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library MathLib {
    function mulDivDown(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return a * b / c;
    }
}

contract MorphoLike {
    using MathLib for uint256;

    uint256 public pendingFee;
    uint256 public continuousFee = 5e16; // 5% annualised

    // accrueInterest: Morpho Midnight.sol line 386 analog.
    // Protocol collects fee via mulDivDown(continuousFee, ...) -> rounds DOWN.
    // Each call under-collects 1 wei from protocol's fee intake.
    function accrueInterest(uint256 totalBorrowAssets, uint256 elapsed) external {
        uint256 feeIncrease = totalBorrowAssets.mulDivDown(continuousFee * elapsed, 1e18);
        pendingFee += feeIncrease;
    }
}
"""


class TestCommentLineSuppression(unittest.TestCase):
    """Guards comment-line suppression: matches inside // comments must be dropped."""

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def test_go_quo_in_comment_only_produces_zero(self):
        """A Quo reference that appears ONLY in a // comment must produce 0 hypotheses."""
        mod = _rdl()
        source = _go_quo_in_comment_only()
        hyps, _ = mod.hypotheses_from_source(
            source=source,
            language="go",
            fn_name="ComputeRatio",
            file_rel="keeper.go",
        )
        self.assertEqual(
            len(hyps), 0,
            "Quo referenced only inside a // comment must NOT produce a hypothesis; "
            f"got {len(hyps)} hypotheses",
        )

    def test_go_truncateint_in_comment_only_produces_zero(self):
        """TruncateInt mentioned only in a comment, no live rounding op -> 0 hyps."""
        mod = _rdl()
        source = _go_payout_muldivdown_in_comment_no_real_op()
        hyps, _ = mod.hypotheses_from_source(
            source=source,
            language="go",
            fn_name="SafeTransferExact",
            file_rel="keeper.go",
        )
        self.assertEqual(
            len(hyps), 0,
            "TruncateInt in comment only must NOT produce a hypothesis; "
            f"got {len(hyps)} hypotheses",
        )


class TestPayoutRoundUpDrainable(unittest.TestCase):
    """Guards payout+round-up = DRAINABLE (user gets ceiling, protocol overpays)."""

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def test_sol_payout_muldivup_is_drainable(self):
        """mulDivUp on a payout/mint path must be flagged as DRAINABLE (needs-fuzz)."""
        mod = _rdl()
        source = _sol_payout_drain()
        hyps, _ = mod.hypotheses_from_source(
            source=source,
            language="sol",
            fn_name="exitPartial",
            file_rel="DrainablePayout.sol",
        )
        self.assertGreater(
            len(hyps), 0,
            "mulDivUp on payout/credit path must produce >=1 DRAINABLE hypothesis",
        )
        for h in hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")
            self.assertEqual(h["attack_class"], "rounding-drain")
        # The flagged op must reference the mulDivUp call.
        self.assertTrue(
            any("mulDivUp" in h["rounding_op"] for h in hyps),
            "Expected mulDivUp-related hit in hypotheses",
        )


class TestMorphoPendingFeeStyle(unittest.TestCase):
    """Guards the morpho pendingFee-style rounding-drain (mulDivDown on fee intake)."""

    def setUp(self):
        if not _RDL_PATH.is_file():
            self.skipTest("rounding-drain-lane.py not found")

    def test_morpho_accrueinterest_muldivdown_on_fee_flagged(self):
        """Morpho-style accrueInterest: mulDivDown on fee/interest intake -> flagged."""
        mod = _rdl()
        source = _sol_morpho_pending_fee_style()
        hyps, _ = mod.hypotheses_from_source(
            source=source,
            language="sol",
            fn_name="accrueInterest",
            file_rel="MorphoLike.sol",
        )
        self.assertGreater(
            len(hyps), 0,
            "Morpho pendingFee-style: mulDivDown on fee/interest intake must produce "
            ">=1 hypothesis (this class must NEVER be suppressed by tightening)",
        )
        for h in hyps:
            self.assertEqual(h["verdict"], "needs-fuzz",
                             "All morpho-style hypotheses must carry verdict=needs-fuzz")
            self.assertEqual(h["attack_class"], "rounding-drain")
        # Confirm direction/path classification is correct.
        drain_hyps = [h for h in hyps if h.get("value_path") == "intake"]
        self.assertGreater(
            len(drain_hyps), 0,
            "At least one hypothesis must be classified with value_path=intake "
            "for the fee/interest intake context",
        )


if __name__ == "__main__":
    unittest.main()
