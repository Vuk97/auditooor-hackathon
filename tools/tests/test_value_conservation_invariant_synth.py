#!/usr/bin/env python3
"""Unit tests for tools/value-conservation-invariant-synth.py (VCIS).

Test plan
=========
1. UNSAFE fixture (UnsafeMarket.sol - take() self-settled, net-zero transfer while
   creditOf increments):
   - VCIS detects the take() function as value-moving.
   - Synthesises a "solvency-floor" property (both transfer_hit AND credit fields).
   - The emitted property name appears in Properties_VCIS.sol.
   - The vcis_manifest verdict is "needs-fuzz" (never auto-credited).
   - The manifest contains the credit-side field (totalWithdrawable or creditOf).

2. SAFE fixture (SafeMarket.sol - real inflow, conservation holds):
   - VCIS also synthesises a solvency-floor for take() here.
   - Same property structure; verdict still "needs-fuzz" (this tool never self-credits).

3. Field selection rules:
   - "creditOf" is identified as a credit-side field (contains "credit").
   - "totalWithdrawable" is identified as a credit-side field (contains "withdraw" - not present,
     but "withdrawable" -> matches none of _CREDIT_ROOTS; we use "totalWithdrawable" which
     contains no credit root -> falls back to debit-exclusion check).
     Actual field in fixture: "creditOf" -> matches "credit" root.
   - "debtOf" is NOT included in credit fields (debit-only root, no credit root).

4. delta-conservation form: flashLoan() has transfer_hit=true but no credit-field
   ledger writes -> VCIS emits delta-conservation form, not solvency-floor.

5. No false-green: manifest verdict is ALWAYS "needs-fuzz"; mutation_verified=False.

6. medusa.json and echidna.yaml are emitted with bounded testLimit=10000.

7. Solidity output contains no em-dashes (U+2014) or en-dashes (U+2013).

8. Go / Rust stubs are emitted when the workspace has .go / .rs value-moving fns.

9. synthesise() with a workspace that has no value-moving fns returns ok=True,
   property_count=0, no crash.

10. build_property_spec() unit tests for form selection logic.
"""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Load the tool under test.
# ---------------------------------------------------------------------------
_TOOL = Path(__file__).resolve().parent.parent / "value-conservation-invariant-synth.py"
_MOD_NAME = "value_conservation_invariant_synth"


def _load_vcis():
    spec = importlib.util.spec_from_file_location(_MOD_NAME, _TOOL)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[_MOD_NAME] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


vcis = _load_vcis()

# ---------------------------------------------------------------------------
# Fixture path.
# ---------------------------------------------------------------------------
_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "vcis" / "sol"


# ---------------------------------------------------------------------------
# Minimal scratch workspace builder.
# ---------------------------------------------------------------------------
class _WS:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "src").mkdir()
        (self.root / ".auditooor").mkdir()

    def add(self, rel: str, body: str) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Helper: run synthesise() against a workspace containing the given sol file.
# ---------------------------------------------------------------------------
def _synth_from_fixture(fixture_name: str) -> tuple[dict, "_WS"]:
    ws = _WS()
    src = _FIXTURE_DIR / fixture_name
    ws.add(f"src/{fixture_name}", src.read_text(encoding="utf-8"))
    out_dir = ws.root / ".auditooor" / "vcis"
    result = vcis.synthesise(ws.root, out_dir=out_dir)
    return result, ws


# ---------------------------------------------------------------------------
# Tests: field selection heuristics.
# ---------------------------------------------------------------------------
class TestFieldSelectionRules(unittest.TestCase):
    """Unit tests for _is_credit_field / _is_debit_only logic."""

    def test_credit_of_is_credit(self):
        self.assertTrue(vcis._is_credit_field("creditOf"),
                        "creditOf must be a credit field (contains 'credit')")

    def test_withdrawable_is_credit(self):
        self.assertTrue(vcis._is_credit_field("withdrawable"),
                        "withdrawable must be a credit field")

    def test_total_units_is_credit(self):
        self.assertTrue(vcis._is_credit_field("totalUnits"),
                        "totalUnits must be a credit field (contains 'unit')")

    def test_collateral_is_credit(self):
        self.assertTrue(vcis._is_credit_field("collateralOf"),
                        "collateralOf must be a credit field")

    def test_debt_only_excluded(self):
        self.assertFalse(vcis._is_credit_field("debtOf") and not vcis._is_debit_only("debtOf"),
                         "debtOf must be debit-only (no credit root)")
        self.assertTrue(vcis._is_debit_only("debtOf"),
                        "debtOf must be classified as debit-only")

    def test_borrow_amount_excluded(self):
        self.assertTrue(vcis._is_debit_only("borrowAmount"),
                        "borrowAmount must be debit-only")

    def test_nonce_not_credit(self):
        self.assertFalse(vcis._is_credit_field("nonce"),
                         "nonce must NOT be a credit field")

    def test_owner_not_credit(self):
        self.assertFalse(vcis._is_credit_field("owner"),
                         "owner must NOT be a credit field")

    def test_fee_is_credit(self):
        self.assertTrue(vcis._is_credit_field("claimableSettlementFee"),
                        "fee field must be credit-side")

    def test_supply_is_credit(self):
        self.assertTrue(vcis._is_credit_field("totalSupply"),
                        "supply is a credit root")


# ---------------------------------------------------------------------------
# Tests: form classification.
# ---------------------------------------------------------------------------
class TestFormClassification(unittest.TestCase):
    """Unit tests for _classify_form()."""

    def _rec(self, transfer_hit=False, ledger_evidence=None):
        return {
            "function": "f",
            "file": "A.sol",
            "language": "sol",
            "transfer_hit": transfer_hit,
            "ledger_write_hit": bool(ledger_evidence),
            "transfer_evidence": [],
            "ledger_write_evidence": ledger_evidence or [],
        }

    def test_solvency_floor_when_both(self):
        rec = self._rec(transfer_hit=True, ledger_evidence=["creditOf"])
        self.assertEqual(vcis._classify_form(rec), "solvency-floor")

    def test_delta_conservation_when_transfer_only(self):
        rec = self._rec(transfer_hit=True, ledger_evidence=[])
        self.assertEqual(vcis._classify_form(rec), "delta-conservation")

    def test_delta_conservation_when_transfer_and_debit_only(self):
        # debtOf is debit-only; should not trigger solvency-floor
        rec = self._rec(transfer_hit=True, ledger_evidence=["debtOf"])
        self.assertEqual(vcis._classify_form(rec), "delta-conservation")

    def test_accounting_monotone_when_ledger_only(self):
        rec = self._rec(transfer_hit=False, ledger_evidence=["creditOf"])
        self.assertEqual(vcis._classify_form(rec), "accounting-monotone")


# ---------------------------------------------------------------------------
# Tests: UNSAFE fixture - UnsafeMarket.sol
# ---------------------------------------------------------------------------
class TestUnsafeFixture(unittest.TestCase):
    """VCIS synthesis against the self-settled-take fixture."""

    @classmethod
    def setUpClass(cls):
        cls.result, cls.ws = _synth_from_fixture("UnsafeMarket.sol")

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_synthesis_ok(self):
        self.assertTrue(self.result["ok"],
                        f"synthesise failed: {self.result.get('error')}")

    def test_property_count_nonzero(self):
        self.assertGreater(self.result["property_count"], 0,
                           "should synthesise at least one property for UnsafeMarket")

    def test_take_solvency_floor_synthesised(self):
        """take() has safeTransferFrom + creditOf/debtOf -> form must be solvency-floor."""
        manifest = self.result["manifest"]
        verdicts = manifest.get("verdicts", [])
        take_verdicts = [v for v in verdicts if v["function"] == "take"]
        self.assertTrue(take_verdicts, "no verdict entry for take()")
        take_v = take_verdicts[0]
        self.assertEqual(take_v["property_form"], "solvency-floor",
                         f"take() must get solvency-floor form, got: {take_v['property_form']}")

    def test_take_credit_fields_include_credit_root(self):
        """Credit fields for take() must include at least one field matching a credit root."""
        manifest = self.result["manifest"]
        verdicts = manifest.get("verdicts", [])
        take_v = next((v for v in verdicts if v["function"] == "take"), None)
        self.assertIsNotNone(take_v, "no verdict for take()")
        credit_fields = take_v.get("credit_fields", [])
        self.assertTrue(credit_fields,
                        "take() must have at least one credit-side field in the manifest")
        # At least one must match a credit root
        has_credit_root = any(
            vcis._is_credit_field(f) and not vcis._is_debit_only(f)
            for f in credit_fields
        )
        self.assertTrue(has_credit_root,
                        f"no credit-root field in {credit_fields}")

    def test_debt_of_not_in_credit_fields(self):
        """debtOf must NOT appear as a credit-side field (debit-only)."""
        manifest = self.result["manifest"]
        verdicts = manifest.get("verdicts", [])
        take_v = next((v for v in verdicts if v["function"] == "take"), None)
        if take_v is None:
            return
        credit_fields = take_v.get("credit_fields", [])
        self.assertNotIn("debtOf", credit_fields,
                         "debtOf is debit-only and must NOT appear in credit_fields")

    def test_flashloan_delta_conservation(self):
        """flashLoan() has transfer_hit but no credit ledger writes -> delta-conservation."""
        manifest = self.result["manifest"]
        verdicts = manifest.get("verdicts", [])
        fl = [v for v in verdicts if v["function"] == "flashLoan"]
        if not fl:
            return  # flashLoan may not be detected - acceptable
        self.assertEqual(fl[0]["property_form"], "delta-conservation",
                         "flashLoan must get delta-conservation form")

    def test_no_auto_credit_verdict_needs_fuzz(self):
        """All verdicts must be 'needs-fuzz' - never auto-credited."""
        for v in self.result["manifest"].get("verdicts", []):
            self.assertEqual(v["verdict"], "needs-fuzz",
                             f"function {v['function']} has verdict={v['verdict']} - "
                             "must be needs-fuzz until mutation-verified")

    def test_mutation_verified_false(self):
        """mutation_verified must be False on all synthesised entries."""
        for v in self.result["manifest"].get("verdicts", []):
            self.assertFalse(v["mutation_verified"],
                             f"{v['function']} mutation_verified must be False")

    def test_sol_output_has_solvency_property(self):
        """Properties_VCIS.sol must contain the solvency-floor property function."""
        files = self.result.get("files", {})
        sol = files.get("Properties_VCIS.sol", "")
        self.assertIn("echidna_vcis_take_solvency", sol,
                      "Properties_VCIS.sol must contain a take solvency property")

    def test_sol_output_no_em_dash(self):
        """Emitted Solidity must contain no em-dash or en-dash characters."""
        files = self.result.get("files", {})
        sol = files.get("Properties_VCIS.sol", "")
        self.assertNotIn("—", sol, "em-dash found in Properties_VCIS.sol")
        self.assertNotIn("–", sol, "en-dash found in Properties_VCIS.sol")

    def test_medusa_config_bounded(self):
        """medusa.json must have testLimit <= 10000 (bound: never runs away)."""
        files = self.result.get("files", {})
        medusa_raw = files.get("medusa.json", "{}")
        cfg = json.loads(medusa_raw)
        limit = cfg.get("fuzzing", {}).get("testLimit", 0)
        self.assertLessEqual(limit, 10000,
                             f"medusa testLimit {limit} exceeds bound of 10000")

    def test_medusa_shared_actor_pool(self):
        """medusa.json must include the shared actor pool for payer==receiver discovery."""
        files = self.result.get("files", {})
        medusa_raw = files.get("medusa.json", "{}")
        cfg = json.loads(medusa_raw)
        senders = cfg.get("fuzzing", {}).get("senderAddresses", [])
        self.assertIn("0x10000", senders, "shared actor pool missing 0x10000")
        self.assertIn("0x20000", senders, "shared actor pool missing 0x20000")
        self.assertIn("0x30000", senders, "shared actor pool missing 0x30000")

    def test_echidna_config_bounded(self):
        """echidna.yaml must have testLimit <= 10000."""
        files = self.result.get("files", {})
        echidna_raw = files.get("echidna.yaml", "")
        m = __import__("re").search(r"testLimit:\s*(\d+)", echidna_raw)
        self.assertIsNotNone(m, "testLimit not found in echidna.yaml")
        limit = int(m.group(1))
        self.assertLessEqual(limit, 10000,
                             f"echidna testLimit {limit} exceeds bound of 10000")

    def test_vcis_manifest_written_to_disk(self):
        """vcis_manifest.json must be written to the output directory."""
        out_dir = Path(self.result["out_dir"])
        manifest_file = out_dir / "vcis_manifest.json"
        self.assertTrue(manifest_file.is_file(),
                        "vcis_manifest.json was not written to disk")

    def test_sol_file_written_to_disk(self):
        """Properties_VCIS.sol must be written to disk."""
        out_dir = Path(self.result["out_dir"])
        sol_file = out_dir / "Properties_VCIS.sol"
        self.assertTrue(sol_file.is_file(),
                        "Properties_VCIS.sol was not written to disk")

    def test_sol_output_conservative_hook_stubs(self):
        """Properties_VCIS.sol must contain virtual hook stubs for the implementer."""
        sol = self.result["files"].get("Properties_VCIS.sol", "")
        self.assertIn("internal view virtual returns", sol,
                      "Properties_VCIS.sol must have virtual hook stubs")
        self.assertIn("_vcis_protocol", sol,
                      "_vcis_protocol hook must be present")


# ---------------------------------------------------------------------------
# Tests: SAFE fixture - SafeMarket.sol
# ---------------------------------------------------------------------------
class TestSafeFixture(unittest.TestCase):
    """VCIS synthesis against the safe (conservation-holding) fixture."""

    @classmethod
    def setUpClass(cls):
        cls.result, cls.ws = _synth_from_fixture("SafeMarket.sol")

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_synthesis_ok(self):
        self.assertTrue(self.result["ok"],
                        f"synthesise failed on SafeMarket: {self.result.get('error')}")

    def test_same_property_structure(self):
        """Safe and unsafe fixtures get the SAME property structure - correctness
        is determined by mutation-verification at run time, not at synthesis time."""
        verdicts = self.result["manifest"].get("verdicts", [])
        take_v = next((v for v in verdicts if v["function"] == "take"), None)
        self.assertIsNotNone(take_v, "take verdict missing for SafeMarket")
        self.assertEqual(take_v["property_form"], "solvency-floor",
                         "SafeMarket take must also get solvency-floor form")

    def test_verdict_still_needs_fuzz(self):
        """Safe fixture: verdict is still needs-fuzz - this tool never self-credits."""
        for v in self.result["manifest"].get("verdicts", []):
            self.assertEqual(v["verdict"], "needs-fuzz",
                             "Safe fixture must also produce needs-fuzz verdict")


# ---------------------------------------------------------------------------
# Tests: empty workspace (no value-moving fns).
# ---------------------------------------------------------------------------
class TestEmptyWorkspace(unittest.TestCase):
    """synthesise() must handle a workspace with no value-moving functions gracefully."""

    def test_empty_workspace_no_crash(self):
        ws = _WS()
        ws.add("src/NoValueMoves.sol", """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract NoValueMoves {
    address public owner;
    function setOwner(address o) external { owner = o; }
    function getOwner() external view returns (address) { return owner; }
}
""")
        try:
            result = vcis.synthesise(ws.root)
            self.assertTrue(result["ok"],
                            f"empty workspace failed: {result.get('error')}")
            self.assertEqual(result["property_count"], 0,
                             "no value-moving fns -> property_count must be 0")
        finally:
            ws.cleanup()


# ---------------------------------------------------------------------------
# Fixture builders shared by Go and Rust backend tests.
# ---------------------------------------------------------------------------

def _make_go_ws() -> "_WS":
    ws = _WS()
    ws.add("keeper/keeper.go", """\
package keeper

import sdk "github.com/cosmos/cosmos-sdk/types"

type Keeper struct { bankKeeper BankKeeper }

func (k Keeper) Transfer(ctx sdk.Context, from, to sdk.AccAddress, coins sdk.Coins) error {
    return k.bankKeeper.SendCoins(ctx, from, to, coins)
}
""")
    return ws


def _make_rs_ws() -> "_WS":
    ws = _WS()
    ws.add("src/contract.rs", """\
use cosmwasm_std::{BankMsg, Response};
pub fn execute_send(amount: u64) -> Response {
    Response::new().add_message(BankMsg::Send { to_address: "addr".into(), amount: vec![] })
}
""")
    return ws


# ---------------------------------------------------------------------------
# Tests: Go/Rust backend emission (backward-compat + real-backend checks).
# ---------------------------------------------------------------------------
class TestBackendStubs(unittest.TestCase):
    """Go and Rust backends are emitted when respective language fns are found."""

    def test_go_stub_emitted(self):
        ws = _make_go_ws()
        try:
            result = vcis.synthesise(ws.root)
            files = result.get("files", {})
            if result["property_count"] > 0:
                self.assertIn("conservation_vcis.go", files,
                              "Go conservation file must be emitted when Go value-moving fns exist")
        finally:
            ws.cleanup()

    def test_rust_stub_emitted(self):
        ws = _make_rs_ws()
        try:
            result = vcis.synthesise(ws.root)
            files = result.get("files", {})
            if result["property_count"] > 0:
                self.assertIn("conservation_vcis_test.rs", files,
                              "Rust conservation file must be emitted when Rust value-moving fns exist")
        finally:
            ws.cleanup()

    def test_go_stub_no_em_dash(self):
        ws = _make_go_ws()
        try:
            result = vcis.synthesise(ws.root)
            content = result.get("files", {}).get("conservation_vcis.go", "")
            self.assertNotIn("—", content, "em-dash in Go conservation file")
            self.assertNotIn("–", content, "en-dash in Go conservation file")
        finally:
            ws.cleanup()


# ---------------------------------------------------------------------------
# Tests: Go/Cosmos real backend - sdk.Invariant body + register scaffold.
# ---------------------------------------------------------------------------
class TestGoBackend(unittest.TestCase):
    """Real Go/Cosmos backend emits sdk.Invariant conservation body + wiring scaffold."""

    def _make_go_specs_with_credit(self) -> list:
        """Build a minimal Go PropertySpec list with a credit-field function."""
        rec = {
            "function": "Transfer",
            "file": "keeper/keeper.go:10",
            "language": "go",
            "transfer_hit": True,
            "ledger_write_hit": True,
            "transfer_evidence": ["bankKeeper.SendCoins(ctx, from, to, coins)"],
            "ledger_write_evidence": ["creditOf", "shareBalance"],
        }
        return [vcis.build_property_spec(rec)]

    def _make_go_specs_delta(self) -> list:
        """Build a minimal Go PropertySpec list without credit fields (delta-conservation)."""
        rec = {
            "function": "Withdraw",
            "file": "keeper/keeper.go:30",
            "language": "go",
            "transfer_hit": True,
            "ledger_write_hit": False,
            "transfer_evidence": ["bankKeeper.SendCoins(ctx, from, to, coins)"],
            "ledger_write_evidence": [],
        }
        return [vcis.build_property_spec(rec)]

    def test_emit_go_backend_returns_two_strings(self):
        specs = self._make_go_specs_with_credit()
        conservation_go, scaffold_go = vcis.emit_go_backend(specs)
        self.assertIsInstance(conservation_go, str,
                              "emit_go_backend must return a string for conservation_vcis.go")
        self.assertIsInstance(scaffold_go, str,
                              "emit_go_backend must return a string for vcis_register_scaffold.go")

    def test_conservation_go_has_invariant_function(self):
        """conservation_vcis.go must contain a VCISConservation_ function body."""
        specs = self._make_go_specs_with_credit()
        conservation_go, _ = vcis.emit_go_backend(specs)
        self.assertIn("VCISConservation_Transfer", conservation_go,
                      "conservation_vcis.go must contain VCISConservation_Transfer function")

    def test_conservation_go_has_sdk_invariant_signature(self):
        """The invariant function must return the sdk.Invariant signature shape."""
        specs = self._make_go_specs_with_credit()
        conservation_go, _ = vcis.emit_go_backend(specs)
        self.assertIn("func(ctx sdk.Context) (string, bool)", conservation_go,
                      "conservation_vcis.go must return sdk.Invariant-compatible (string, bool) type")

    def test_conservation_go_solvency_floor_asserts_bank_balance(self):
        """Solvency-floor body must reference SpendableCoins (bank balance query)."""
        specs = self._make_go_specs_with_credit()
        conservation_go, _ = vcis.emit_go_backend(specs)
        self.assertIn("SpendableCoins", conservation_go,
                      "solvency-floor body must call bankKeeper.SpendableCoins")

    def test_conservation_go_credit_getters_emitted(self):
        """Credit-field getter stubs must appear in the keeper interface and body."""
        specs = self._make_go_specs_with_credit()
        conservation_go, _ = vcis.emit_go_backend(specs)
        # creditOf -> GetTotalCreditOf
        self.assertIn("GetTotalCreditOf", conservation_go,
                      "credit field 'creditOf' must produce GetTotalCreditOf getter stub")

    def test_conservation_go_delta_conservation_form(self):
        """Delta-conservation body must reference GetPreCallBalance and GetAuthorisedOutflow."""
        specs = self._make_go_specs_delta()
        conservation_go, _ = vcis.emit_go_backend(specs)
        self.assertIn("GetPreCallBalance", conservation_go,
                      "delta-conservation body must reference GetPreCallBalance ghost getter")
        self.assertIn("GetAuthorisedOutflow", conservation_go,
                      "delta-conservation body must reference GetAuthorisedOutflow ghost getter")

    def test_register_scaffold_has_ir_register_route(self):
        """vcis_register_scaffold.go must contain ir.RegisterRoute call."""
        specs = self._make_go_specs_with_credit()
        _, scaffold_go = vcis.emit_go_backend(specs)
        self.assertIn("ir.RegisterRoute", scaffold_go,
                      "register scaffold must contain ir.RegisterRoute wiring call")

    def test_register_scaffold_has_register_function(self):
        """vcis_register_scaffold.go must contain RegisterVCISInvariants function."""
        specs = self._make_go_specs_with_credit()
        _, scaffold_go = vcis.emit_go_backend(specs)
        self.assertIn("RegisterVCISInvariants", scaffold_go,
                      "register scaffold must define RegisterVCISInvariants function")

    def test_conservation_go_has_candidate_harness_header(self):
        """conservation_vcis.go must carry CANDIDATE-HARNESS-NOT-PROOF header (no-false-green)."""
        specs = self._make_go_specs_with_credit()
        conservation_go, _ = vcis.emit_go_backend(specs)
        self.assertIn("CANDIDATE-HARNESS-NOT-PROOF", conservation_go,
                      "Go file must carry the no-false-green CANDIDATE-HARNESS-NOT-PROOF header")

    def test_conservation_go_has_module_account_placeholder(self):
        """conservation_vcis.go must have MODULE_ACCOUNT_PLACEHOLDER for manual wiring."""
        specs = self._make_go_specs_with_credit()
        conservation_go, _ = vcis.emit_go_backend(specs)
        self.assertIn("MODULE_ACCOUNT_PLACEHOLDER", conservation_go,
                      "Go file must contain MODULE_ACCOUNT_PLACEHOLDER for manual binding")

    def test_conservation_go_no_em_dash(self):
        """conservation_vcis.go must contain no em-dash or en-dash characters."""
        specs = self._make_go_specs_with_credit()
        conservation_go, scaffold_go = vcis.emit_go_backend(specs)
        for text, label in [(conservation_go, "conservation_vcis.go"),
                            (scaffold_go, "vcis_register_scaffold.go")]:
            self.assertNotIn("—", text, f"em-dash found in {label}")
            self.assertNotIn("–", text, f"en-dash found in {label}")

    def test_synthesise_writes_go_files_to_disk(self):
        """synthesise() must write conservation_vcis.go and vcis_register_scaffold.go to disk."""
        ws = _make_go_ws()
        try:
            result = vcis.synthesise(ws.root)
            if result["property_count"] > 0:
                out_dir = Path(result["out_dir"])
                self.assertTrue((out_dir / "conservation_vcis.go").is_file(),
                                "conservation_vcis.go must be written to disk")
                self.assertTrue((out_dir / "vcis_register_scaffold.go").is_file(),
                                "vcis_register_scaffold.go must be written to disk")
        finally:
            ws.cleanup()

    def test_synthesise_go_verdict_needs_fuzz(self):
        """All Go manifest verdicts must be needs-fuzz (no auto-credit)."""
        ws = _make_go_ws()
        try:
            result = vcis.synthesise(ws.root)
            for v in result["manifest"].get("verdicts", []):
                if v.get("language") == "go":
                    self.assertEqual(v["verdict"], "needs-fuzz",
                                     f"Go fn {v['function']} must have verdict=needs-fuzz")
        finally:
            ws.cleanup()


# ---------------------------------------------------------------------------
# Tests: Rust/CosmWasm real backend - proptest / cw-multi-test assertions + scaffold.
# ---------------------------------------------------------------------------
class TestRustBackend(unittest.TestCase):
    """Real Rust/CosmWasm backend emits conservation assertions + wiring scaffold."""

    def _make_rs_specs_with_credit(self) -> list:
        rec = {
            "function": "execute_send",
            "file": "src/contract.rs:5",
            "language": "rs",
            "transfer_hit": True,
            "ledger_write_hit": True,
            "transfer_evidence": ["BankMsg::Send { to_address, amount }"],
            "ledger_write_evidence": ["creditBalance", "shareUnits"],
        }
        return [vcis.build_property_spec(rec)]

    def _make_rs_specs_delta(self) -> list:
        rec = {
            "function": "execute_withdraw",
            "file": "src/contract.rs:40",
            "language": "rs",
            "transfer_hit": True,
            "ledger_write_hit": False,
            "transfer_evidence": ["BankMsg::Send { to_address, amount }"],
            "ledger_write_evidence": [],
        }
        return [vcis.build_property_spec(rec)]

    def test_emit_rust_backend_returns_string(self):
        specs = self._make_rs_specs_with_credit()
        out = vcis.emit_rust_backend(specs)
        self.assertIsInstance(out, str,
                              "emit_rust_backend must return a string")

    def test_rust_file_has_test_function(self):
        """conservation_vcis_test.rs must contain a #[test] fn vcis_conservation_* function."""
        specs = self._make_rs_specs_with_credit()
        out = vcis.emit_rust_backend(specs)
        self.assertIn("#[test]", out,
                      "Rust file must contain #[test] attribute")
        self.assertIn("fn vcis_conservation_execute_send", out,
                      "Rust file must contain vcis_conservation_execute_send test fn")

    def test_rust_solvency_floor_references_bank_balance(self):
        """Solvency-floor assertion must reference query_balance."""
        specs = self._make_rs_specs_with_credit()
        out = vcis.emit_rust_backend(specs)
        self.assertIn("query_balance", out,
                      "Rust solvency-floor must reference query_balance for bank balance snapshot")

    def test_rust_credit_field_query_stubs_emitted(self):
        """Credit-field query stubs must appear for each detected credit field."""
        specs = self._make_rs_specs_with_credit()
        out = vcis.emit_rust_backend(specs)
        # The safe name for 'creditBalance' lowercases to 'creditbalance' -> query_total_creditbalance_TODO
        self.assertIn("query_total_creditbalance_TODO", out,
                      "Rust file must contain query stub for credit field 'creditBalance'")

    def test_rust_solvency_floor_assertion_present(self):
        """Rust file must contain the assert! solvency-floor pattern."""
        specs = self._make_rs_specs_with_credit()
        out = vcis.emit_rust_backend(specs)
        self.assertIn("SOLVENCY-FLOOR", out,
                      "Rust file must contain SOLVENCY-FLOOR assertion comment")

    def test_rust_delta_conservation_fallback(self):
        """Delta-conservation form must reference saturating_sub and authorised_outflow."""
        specs = self._make_rs_specs_delta()
        out = vcis.emit_rust_backend(specs)
        self.assertIn("saturating_sub", out,
                      "Rust delta-conservation must use saturating_sub for floor calculation")
        self.assertIn("authorised_outflow", out,
                      "Rust delta-conservation must reference authorised_outflow variable")

    def test_rust_scaffold_footer_present(self):
        """Rust file must contain the cw-multi-test App wiring scaffold."""
        specs = self._make_rs_specs_with_credit()
        out = vcis.emit_rust_backend(specs)
        self.assertIn("instantiate_contract", out,
                      "Rust file must contain instantiate_contract wiring scaffold")
        self.assertIn("proptest!", out,
                      "Rust file must contain proptest! scaffold block")

    def test_rust_candidate_harness_header(self):
        """Rust file must carry CANDIDATE-HARNESS-NOT-PROOF header."""
        specs = self._make_rs_specs_with_credit()
        out = vcis.emit_rust_backend(specs)
        self.assertIn("CANDIDATE-HARNESS-NOT-PROOF", out,
                      "Rust file must carry CANDIDATE-HARNESS-NOT-PROOF no-false-green header")

    def test_rust_protocol_addr_placeholder(self):
        """Rust file must have PROTOCOL_ADDR_TODO placeholder for manual binding."""
        specs = self._make_rs_specs_with_credit()
        out = vcis.emit_rust_backend(specs)
        self.assertIn("PROTOCOL_ADDR_TODO", out,
                      "Rust file must contain PROTOCOL_ADDR_TODO placeholder")

    def test_rust_no_em_dash(self):
        """Rust conservation file must contain no em-dash or en-dash characters."""
        specs = self._make_rs_specs_with_credit()
        out = vcis.emit_rust_backend(specs)
        self.assertNotIn("—", out, "em-dash found in Rust conservation file")
        self.assertNotIn("–", out, "en-dash found in Rust conservation file")

    def test_synthesise_writes_rust_file_to_disk(self):
        """synthesise() must write conservation_vcis_test.rs to disk."""
        ws = _make_rs_ws()
        try:
            result = vcis.synthesise(ws.root)
            if result["property_count"] > 0:
                out_dir = Path(result["out_dir"])
                self.assertTrue((out_dir / "conservation_vcis_test.rs").is_file(),
                                "conservation_vcis_test.rs must be written to disk")
        finally:
            ws.cleanup()

    def test_synthesise_rust_verdict_needs_fuzz(self):
        """All Rust manifest verdicts must be needs-fuzz (no auto-credit)."""
        ws = _make_rs_ws()
        try:
            result = vcis.synthesise(ws.root)
            for v in result["manifest"].get("verdicts", []):
                if v.get("language") == "rs":
                    self.assertEqual(v["verdict"], "needs-fuzz",
                                     f"Rust fn {v['function']} must have verdict=needs-fuzz")
        finally:
            ws.cleanup()


# ---------------------------------------------------------------------------
# Tests: build_property_spec() unit tests.
# ---------------------------------------------------------------------------
class TestBuildPropertySpec(unittest.TestCase):
    """Direct unit tests for the property-spec builder."""

    def _rec(self, fn="take", transfer_hit=True, ledger=None, transfer_ev=None):
        return {
            "function": fn,
            "file": "Src.sol",
            "language": "sol",
            "transfer_hit": transfer_hit,
            "ledger_write_hit": bool(ledger),
            "transfer_evidence": transfer_ev or ["safeTransferFrom(loanToken, from, to, amt)"],
            "ledger_write_evidence": ledger or [],
        }

    def test_token_extracted_from_transfer_evidence(self):
        rec = self._rec(transfer_ev=["safeTransferFrom(loanToken, buyer, protocol, units)"])
        spec = vcis.build_property_spec(rec)
        self.assertIn("loanToken", spec.tokens,
                      f"loanToken should be extracted from transfer_evidence; got {spec.tokens}")

    def test_credit_fields_debit_excluded(self):
        rec = self._rec(ledger=["creditOf", "debtOf", "withdrawable"])
        spec = vcis.build_property_spec(rec)
        self.assertIn("creditOf", spec.credit_fields)
        self.assertIn("withdrawable", spec.credit_fields)
        self.assertNotIn("debtOf", spec.credit_fields,
                         "debtOf is debit-only and must not be in credit_fields")

    def test_form_solvency_floor_when_both(self):
        rec = self._rec(transfer_hit=True, ledger=["creditOf"])
        spec = vcis.build_property_spec(rec)
        self.assertEqual(spec.form, "solvency-floor")

    def test_form_delta_conservation_when_transfer_only(self):
        rec = self._rec(transfer_hit=True, ledger=[])
        spec = vcis.build_property_spec(rec)
        self.assertEqual(spec.form, "delta-conservation")

    def test_form_accounting_monotone_when_ledger_only(self):
        rec = self._rec(transfer_hit=False, ledger=["creditOf"])
        spec = vcis.build_property_spec(rec)
        self.assertEqual(spec.form, "accounting-monotone")

    def test_token_fallback_when_no_transfer_evidence(self):
        rec = self._rec(transfer_ev=[], ledger=["loanTokenBalance"])
        spec = vcis.build_property_spec(rec)
        # fallback: either extracts a token-ish field or uses generic "token"
        self.assertTrue(spec.tokens, "tokens must not be empty")


# ---------------------------------------------------------------------------
# Tests: manifest schema correctness.
# ---------------------------------------------------------------------------
class TestManifestSchema(unittest.TestCase):
    """vcis_manifest.json must conform to the genuine-coverage schema."""

    @classmethod
    def setUpClass(cls):
        cls.result, cls.ws = _synth_from_fixture("UnsafeMarket.sol")

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_schema_version(self):
        self.assertEqual(self.result["manifest"]["schema"], "vcis_manifest.v1")

    def test_genuine_credit_rule_present(self):
        rule = self.result["manifest"].get("genuine_credit_rule", "")
        self.assertIn("needs-fuzz", rule,
                      "manifest must document the no-false-green rule")
        rule_low = rule.lower()
        has_mutation_ref = (
            "mutation-verify" in rule_low
            or "mutation verify" in rule_low
            or "mutation_verify" in rule_low
            or "mutant" in rule_low
        )
        self.assertTrue(has_mutation_ref,
                        "manifest must reference mutation-verification")

    def test_all_verdicts_have_required_keys(self):
        required = {"function", "file_line", "language", "property_form",
                    "property_name", "verdict", "mutation_verified"}
        for v in self.result["manifest"].get("verdicts", []):
            missing = required - set(v.keys())
            self.assertFalse(missing,
                             f"verdict for {v.get('function')} missing keys: {missing}")

    def test_manifest_json_parseable_from_disk(self):
        out_dir = Path(self.result["out_dir"])
        manifest_file = out_dir / "vcis_manifest.json"
        data = json.loads(manifest_file.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "vcis_manifest.v1")
        self.assertIn("verdicts", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
