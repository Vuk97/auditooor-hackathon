"""Tests for tools/novel-vector-invariant-miner.py (PR9a TRUE-0-day stage)."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "novel-vector-invariant-miner.py"
_spec = importlib.util.spec_from_file_location("novel_vector_invariant_miner", MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
sys.modules["novel_vector_invariant_miner"] = mod
_spec.loader.exec_module(mod)

# The load-bearing contract: assertions this tool derives must pass the
# engine-harness proof gate's notion of REAL when rendered. We assert the
# gate's own real-relation predicate over our derived exprs by loading it.
_GATE_PATH = REPO_ROOT / "tools" / "engine-harness-proof-gate.py"
gate = None
if _GATE_PATH.exists():
    _gspec = importlib.util.spec_from_file_location("engine_harness_proof_gate", _GATE_PATH)
    gate = importlib.util.module_from_spec(_gspec)
    sys.modules["engine_harness_proof_gate"] = gate
    _gspec.loader.exec_module(gate)

VAULT_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    uint256 public totalAssets;
    uint256 public totalShares;
    uint256 public depositCap;
    address public owner;
    mapping(address => uint256) internal balances;
    function deposit(uint256 amount) external returns (uint256) {}
    function withdraw(uint256 shares) public {}
    function redeem(uint256 shares, address to) external {}
    function setOwner(address newOwner) external {}
    function previewRedeem(uint256 shares) external view returns (uint256) {}
    function claim(bytes32 id) external {}
}
"""

# A GENERIC internal-fn fixture: an internal mutating helper that touches real
# state plus an internal validating routine that takes a signature-shaped param.
# Deliberately NOT named after any real-world symbol (no _validateSignature, no
# epoch helper) so the test proves the GENERAL capability "internal functions
# are now enumerated", not a pattern hand-tuned to one symbol.
INTERNAL_FN_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Accumulator {
    uint256 public totalUnits;
    uint256 public unitsCap;
    address public controller;
    mapping(address => uint256) internal ledger;
    // external surface
    function add(uint256 amount) external { _applyDelta(amount); }
    // internal mutating helper - historically skipped, now enumerated
    function _applyDelta(uint256 amount) internal { totalUnits += amount; }
    // internal validating helper taking a signature-shaped param
    function _checkWitness(bytes calldata proof) internal returns (bool) {}
    // private mutating helper
    function _bumpLedger(address who, uint256 v) private { ledger[who] = v; }
    // view internal helper must STILL be excluded (not mutating)
    function _peek(uint256 x) internal view returns (uint256) {}
}
"""

# A GENERIC view-helper fixture: internal/private/public VIEW (pure-read)
# helpers that each carry a derivable READ-class invariant. Deliberately NOT
# named after any real-world protocol symbol (no _calculateEpochTimestampEnd,
# no Intuition symbol) so the test proves the GENERAL capability "internal/
# private/public VIEW functions are enumerated for READ-class families", not a
# pattern hand-tuned to one symbol. Each helper's NAME implies a read role:
#   - _windowBoundaryEnd : a boundary/window read -> epoch_boundary off-by-one
#   - _computeTotalOwed  : an aggregation read     -> read_conservation
#   - _priceForTick      : a price-over-ordered-axis read -> read_monotonicity
#   - currentRate        : a public computed read  -> bounds + determinism
VIEW_HELPER_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract WindowMath {
    uint256 public windowStart;
    uint256 public windowLength;
    uint256 public totalOwed;
    uint256 public rateCap;
    mapping(uint256 => uint256) internal ticks;
    // mutating external surface so the contract is not property-free
    function poke(uint256 v) external { totalOwed += v; }
    // internal VIEW boundary helper - the inclusive-vs-exclusive off-by-one
    function _windowBoundaryEnd(uint256 idx) internal view returns (uint256) {}
    // private VIEW aggregation helper - read-side conservation
    function _computeTotalOwed(uint256 from, uint256 to) private view returns (uint256) {}
    // internal VIEW price-over-ordered-axis helper - read monotonicity
    function _priceForTick(uint256 tick) internal view returns (uint256) {}
    // public VIEW computed read - bounds + determinism
    function currentRate(uint256 util) public view returns (uint256) {}
}
"""

KEEPER_GO = """package keeper
type Keeper struct {
    totalSupply math.Int
    nonce uint64
    owner string
}
func (k Keeper) Deposit(ctx sdk.Context, amount math.Int) error { return nil }
func (k Keeper) Withdraw(ctx sdk.Context, shares math.Int) error { return nil }
// unexported (internal) mutating helper - now enumerated
func (k Keeper) settleInternal(ctx sdk.Context, amount math.Int) error { return nil }
func TestFoo(t *testing.T) {}
"""

# A GENERIC Go distribution-writer fixture (iter13-B / BS-2). A handler that
# rewrites a weight-distribution struct field that must stay normalized
# (sum-to-total, all-positive). Deliberately NOT named after Quicksilver's real
# symbols: the struct field is a synthetic `payoutShares []Share` and the method
# is a generic `SetPayoutShares`, so the test proves the GENERAL conservation/
# normalization capability, not a pattern hand-tuned to one protocol.
DISTRIBUTION_GO = """package keeper
type Distributor struct {
    payoutShares []Share
    totalPool math.Int
}
// SetPayoutShares rewrites the share distribution across recipients.
func (k Distributor) SetPayoutShares(ctx sdk.Context, shares []Share) error { return nil }
func (k Distributor) Rebalance(ctx sdk.Context, weights []Weight) error { return nil }
func TestDist(t *testing.T) {}
"""

# A GENERIC Go staleness-read fixture (iter13-B / BS-3). A pure-read getter that
# returns a stored value carrying a last_update the read must gate on before use
# (the oracle-staleness shape generalized to a read). Deliberately NOT named
# after Synthetify's real symbols: the struct holds a synthetic `feedValue` plus
# `lastUpdate`, and the getter is a generic `GetFeedValue`, so the test proves the
# GENERAL read-class freshness/staleness capability, not a tuned pattern.
STALENESS_READ_GO = """package keeper
type Oracle struct {
    feedValue uint64
    lastUpdate int64
    maxStaleness int64
}
// GetFeedValue returns the stored feed value; it MUST reject a stale lastUpdate.
func (k Oracle) GetFeedValue(ctx sdk.Context, id string) (uint64, error) { return 0, nil }
// SetFeedValue is a mutating writer (must NOT be read-classified).
func (k Oracle) SetFeedValue(ctx sdk.Context, id string, v uint64) error { return nil }
func TestStale(t *testing.T) {}
"""

# A GENERIC Rust staleness-read fixture (iter13-B / BS-3, Synthetify-class). A
# pure-read getter returning a stored value carrying a last_update the read must
# gate on. Deliberately NOT named after Synthetify's real symbols.
STALENESS_READ_RS = """
pub struct AssetState {
    pub spot_value: u64,
    pub last_update: i64,
    pub max_staleness: i64,
}
// pure read getter - reclassified as a view (BS-3 staleness gate)
pub fn get_spot_value(state: &AssetState) -> u64 { state.spot_value }
// mutating writer (takes &mut) - must STAY mutating-state
pub fn set_spot_value(state: &mut AssetState, v: u64) { state.spot_value = v; }
fn test_helper() {}
"""

# A GENERIC validate-distribution fixture (iter13 fix). A fn whose name carries a
# WEAK verb (`validate`) but whose param is a slice-of-STRUCT distribution
# (`intents []WeightEntry`) over a real collection state field (`memberWeights`)
# that must stay normalized. Deliberately NOT named after Quicksilver's real
# symbols (validateIntents / validatorWeights / ValidatorIntent): the fn is a
# generic `validateDistribution`, the param element is a synthetic `WeightEntry`,
# the state field is a synthetic `memberWeights`. The test proves the GENERAL
# class-level capability (a validate-class fn over a slice-of-struct-with-a-weight
# carries a normalization invariant bound to the real collection symbol), NOT a
# pattern hand-tuned to the known target's names.
VALIDATE_DISTRIBUTION_GO = """package keeper
type WeightEntry struct {
    Address string
    Weight  math.LegacyDec
}
type DistKeeper struct {
    memberWeights []WeightEntry
    totalShare    math.LegacyDec
}
// validateDistribution checks the weight distribution across member entries.
func (k DistKeeper) validateDistribution(entries []WeightEntry) error { return nil }
func TestVD(t *testing.T) {}
"""

# A GENERIC epoch-boundary helper fixture (iter13 fix). A pure-read helper that
# computes a window/epoch boundary the protocol must treat as EXCLUSIVE
# (inclusive-vs-exclusive off-by-one). Deliberately generic symbol names.
EPOCH_HELPER_GO = """package keeper
type EpochKeeper struct {
    epochDuration int64
    epochStart    int64
}
// getEpochEnd computes the boundary timestamp for the current epoch window.
func (k EpochKeeper) getEpochEnd(start int64) (int64, error) { return 0, nil }
func TestEH(t *testing.T) {}
"""

PALLET_RS = """
#[pallet::storage]
pub total_issuance: StorageValue<_, u128>;
pub fn mint(origin: OriginFor<T>, amount: u128) -> DispatchResult { Ok(()) }
pub fn burn(origin: OriginFor<T>, amount: u128) -> DispatchResult { Ok(()) }
// bare fn (no pub) is internal - now enumerated
fn apply_delta(amount: u128) -> u128 { amount }
fn test_helper() {}
"""


class _WS:
    def __init__(self, name, src):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        (self.ws / "src").mkdir(parents=True, exist_ok=True)
        self.contract = self.ws / "src" / name
        self.contract.write_text(src, encoding="utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.tmp.cleanup()


def _build(ws: Path, contract: Path, lang="auto", **kw):
    return mod.build(
        workspace=ws,
        contract=contract,
        lang=lang,
        contract_name=kw.get("contract_name"),
        extracted=mod.DEFAULT_EXTRACTED,
        pilot=mod.DEFAULT_PILOT,
        index=mod.DEFAULT_INDEX,
        max_per_fn=kw.get("max_per_fn", 3),
        mimo_refine=False,
        mimo_budget=0,
        render=kw.get("render", False),
        out_dir=kw.get("out_dir"),
    )


class TestDerivation(unittest.TestCase):
    def test_solidity_derives_target_specific_invariants(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            s = _build(w.ws, w.contract)
        self.assertEqual(s["target"], "Vault")
        self.assertEqual(s["target_lang"], "solidity")
        self.assertGreater(s["invariants_derived"], 0)
        names = {r["function"] for r in s["invariants"]}
        self.assertIn("deposit", names)
        # previewRedeem is a VIEW helper: it is NOW enumerated for READ-class
        # families (iter10-A), but ONLY as read-side invariants - never as a
        # mutating-state family (it writes no state).
        preview = [r for r in s["invariants"] if r["function"] == "previewRedeem"]
        self.assertTrue(preview, "previewRedeem view helper not enumerated for read-class")
        for r in preview:
            self.assertEqual(r["invariant_class"], "read-side")
            self.assertNotIn(
                r["family"],
                # mutating-state families must never be derived for a view fn
                {"conservation", "monotonicity", "custody", "authorization",
                 "atomicity", "bounds", "uniqueness", "ordering", "freshness",
                 "determinism", "soundness"},
            )

    def test_invariants_bound_to_real_symbols(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            s = _build(w.ws, w.contract)
        # every derived invariant binds a symbol drawn from the real surface
        real = {"totalAssets", "totalShares", "depositCap", "owner", "balances"}
        bound = {r["bound_symbol"] for r in s["invariants"] if r["bound_symbol"]}
        self.assertTrue(bound.issubset(real), f"unexpected bound symbols: {bound - real}")

    def test_setowner_binds_authorization_to_owner(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            s = _build(w.ws, w.contract)
        auth = [r for r in s["invariants"] if r["function"] == "setOwner" and r["family"] == "authorization"]
        self.assertTrue(auth)
        self.assertEqual(auth[0]["bound_symbol"], "owner")

    def test_true_0day_tagging(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            s = _build(w.ws, w.contract)
        for r in s["invariants"]:
            self.assertEqual(r["detector_match"], "none")
            self.assertEqual(r["discovery_mode"], "spec-violation-counterexample-search")

    def test_grounding_invariant_ids_present(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            s = _build(w.ws, w.contract)
        # at least the high-density families ground in corpus INV-* ids (R58)
        grounded = [r for r in s["invariants"] if r["grounding_invariant_ids"]]
        self.assertTrue(grounded)
        for r in grounded:
            for inv in r["grounding_invariant_ids"]:
                self.assertTrue(inv.startswith("INV-"), inv)

    def test_assertions_are_real_relations(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            s = _build(w.ws, w.contract)
        for r in s["invariants"]:
            self.assertTrue(
                mod._is_real_relation(r["assertion_expr"]),
                f"non-real assertion for {r['function']}/{r['family']}: {r['assertion_expr']}",
            )

    def test_no_tautology_or_neutered_mutation_in_assertions(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            s = _build(w.ws, w.contract)
        for r in s["invariants"]:
            self.assertNotIn("% 1", r["assertion_expr"])

    def test_max_per_fn_respected(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            s = _build(w.ws, w.contract, max_per_fn=1)
        by_fn = {}
        for r in s["invariants"]:
            by_fn[r["function"]] = by_fn.get(r["function"], 0) + 1
        self.assertTrue(all(c <= 1 for c in by_fn.values()))

    def test_confidence_levels(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            s = _build(w.ws, w.contract)
        for r in s["invariants"]:
            self.assertIn(r["confidence"], ("low", "medium", "high"))


class TestLanguages(unittest.TestCase):
    def test_go_target(self):
        with _WS("keeper.go", KEEPER_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        self.assertEqual(s["target_lang"], "go")
        names = {r["function"] for r in s["invariants"]}
        self.assertIn("Deposit", names)
        # Test* helper excluded
        self.assertNotIn("TestFoo", names)

    def test_rust_target(self):
        with _WS("pallet.rs", PALLET_RS) as w:
            s = _build(w.ws, w.contract, lang="rust")
        self.assertEqual(s["target_lang"], "rust")
        names = {r["function"] for r in s["invariants"]}
        self.assertIn("mint", names)
        self.assertNotIn("test_helper", names)

    def test_lang_autodetect(self):
        with _WS("keeper.go", KEEPER_GO) as w:
            self.assertEqual(mod.detect_lang(w.contract, "auto"), "go")

    def test_go_internal_fn_enumerated(self):
        with _WS("keeper.go", KEEPER_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        recs = {r["function"]: r for r in s["invariants"]}
        self.assertIn("settleInternal", recs)
        self.assertEqual(recs["settleInternal"]["callable_surface"], "internal")
        # exported Deposit still external
        self.assertEqual(recs["Deposit"]["callable_surface"], "external")

    def test_rust_internal_fn_enumerated(self):
        with _WS("pallet.rs", PALLET_RS) as w:
            s = _build(w.ws, w.contract, lang="rust")
        recs = {r["function"]: r for r in s["invariants"]}
        self.assertIn("apply_delta", recs)
        self.assertEqual(recs["apply_delta"]["callable_surface"], "internal")
        # pub mint still external
        self.assertEqual(recs["mint"]["callable_surface"], "external")
        # test helper still excluded
        self.assertNotIn("test_helper", recs)


class TestInternalFunctionEnumeration(unittest.TestCase):
    """Regression lock: internal/private mutating functions are enumerated.

    Historically derive_invariants filtered to visibility in
    (public, external, pub), so a bug living in an internal helper (e.g. an
    ERC-4337 _validateSignature override) was never hypothesized. These tests
    assert the GENERAL capability: ANY internal/private mutating function now
    yields target-specific invariants.
    """

    def test_internal_mutating_fn_now_enumerated(self):
        with _WS("Accumulator.sol", INTERNAL_FN_SOL) as w:
            s = _build(w.ws, w.contract)
        names = {r["function"] for r in s["invariants"]}
        # the internal mutating helper now produces invariants
        self.assertIn("_applyDelta", names)
        # so does the private mutating helper
        self.assertIn("_bumpLedger", names)
        # and the internal validating (signature-shaped) helper
        self.assertIn("_checkWitness", names)
        # the external surface still works
        self.assertIn("add", names)

    def test_internal_view_fn_enumerated_read_class_only(self):
        # iter10-A: an internal VIEW helper is NOW enumerated, but ONLY for
        # READ-class families - never as a mutating-state invariant (it writes
        # no state). _peek's name is uninformative, so the uint256-return shape
        # fallback maps it to bounds_on_computed_value / read_determinism.
        with _WS("Accumulator.sol", INTERNAL_FN_SOL) as w:
            s = _build(w.ws, w.contract)
        peek = [r for r in s["invariants"] if r["function"] == "_peek"]
        self.assertTrue(peek, "internal view helper _peek not enumerated for read-class")
        for r in peek:
            self.assertEqual(r["invariant_class"], "read-side")
            self.assertEqual(r["callable_surface"], "internal")
            self.assertIn(
                r["family"],
                {"epoch_boundary", "read_conservation", "read_monotonicity",
                 "bounds_on_computed_value", "read_determinism"},
            )

    def test_internal_fn_carries_visibility_metadata(self):
        with _WS("Accumulator.sol", INTERNAL_FN_SOL) as w:
            s = _build(w.ws, w.contract)
        by_fn = {}
        for r in s["invariants"]:
            by_fn.setdefault(r["function"], r)
        self.assertEqual(by_fn["_applyDelta"]["callable_surface"], "internal")
        self.assertEqual(by_fn["_applyDelta"]["function_visibility"], "internal")
        self.assertEqual(by_fn["_bumpLedger"]["callable_surface"], "internal")
        self.assertEqual(by_fn["_bumpLedger"]["function_visibility"], "private")
        self.assertEqual(by_fn["add"]["callable_surface"], "external")

    def test_internal_validating_fn_derives_soundness_family(self):
        # the signature-shaped internal helper maps to soundness/uniqueness via
        # the shape heuristic (general, not symbol-name-tuned)
        with _WS("Accumulator.sol", INTERNAL_FN_SOL) as w:
            s = _build(w.ws, w.contract)
        fams = {
            r["family"] for r in s["invariants"] if r["function"] == "_checkWitness"
        }
        self.assertTrue(
            fams & {"soundness", "uniqueness"},
            f"_checkWitness derived no soundness/uniqueness family: {fams}",
        )

    def test_derived_internal_invariants_are_real_relations(self):
        with _WS("Accumulator.sol", INTERNAL_FN_SOL) as w:
            s = _build(w.ws, w.contract)
        for r in s["invariants"]:
            self.assertTrue(
                mod._is_real_relation(r["assertion_expr"]),
                f"non-real assertion {r['function']}/{r['family']}: {r['assertion_expr']}",
            )

    def test_internal_invariants_tagged_true_0day(self):
        with _WS("Accumulator.sol", INTERNAL_FN_SOL) as w:
            s = _build(w.ws, w.contract)
        internal_recs = [r for r in s["invariants"] if r["callable_surface"] == "internal"]
        self.assertTrue(internal_recs)
        for r in internal_recs:
            self.assertEqual(r["detector_match"], "none")
            self.assertEqual(r["discovery_mode"], "spec-violation-counterexample-search")


class TestReadClassViewEnumeration(unittest.TestCase):
    """Regression lock (iter10-A): internal/private/public VIEW (pure-read)
    helpers are enumerated for READ-class invariant families.

    Historically derive_invariants filtered to f.mutating == True, so a bug in
    a pure-read helper (the canonical inclusive-vs-exclusive epoch-boundary
    off-by-one, a read-side rounding that creates value, a non-monotone read
    over an ordered axis, a derived-value out-of-bounds) was never hypothesized.
    These tests assert the GENERAL, class-level capability on a generic fixture
    - never tuned to any real-world symbol.
    """

    def test_view_helpers_now_enumerated(self):
        with _WS("WindowMath.sol", VIEW_HELPER_SOL) as w:
            s = _build(w.ws, w.contract)
        names = {r["function"] for r in s["invariants"]}
        # all four view helpers produce read-class invariants
        self.assertIn("_windowBoundaryEnd", names)
        self.assertIn("_computeTotalOwed", names)
        self.assertIn("_priceForTick", names)
        self.assertIn("currentRate", names)
        # the mutating external surface still works
        self.assertIn("poke", names)

    def test_boundary_view_derives_epoch_boundary_invariant(self):
        # the canonical inclusive-vs-exclusive off-by-one read-invariant
        with _WS("WindowMath.sol", VIEW_HELPER_SOL) as w:
            s = _build(w.ws, w.contract)
        fams = {r["family"] for r in s["invariants"] if r["function"] == "_windowBoundaryEnd"}
        self.assertIn("epoch_boundary", fams)
        rec = next(r for r in s["invariants"]
                   if r["function"] == "_windowBoundaryEnd" and r["family"] == "epoch_boundary")
        # statement names the exclusive-upper-bound spec; assertion is strict <
        self.assertIn("EXCLUSIVE", rec["statement"])
        self.assertIn("<", rec["assertion_expr"])
        self.assertEqual(rec["invariant_class"], "read-side")

    def test_aggregation_view_derives_read_conservation(self):
        with _WS("WindowMath.sol", VIEW_HELPER_SOL) as w:
            s = _build(w.ws, w.contract)
        fams = {r["family"] for r in s["invariants"] if r["function"] == "_computeTotalOwed"}
        self.assertIn("read_conservation", fams)

    def test_price_view_derives_read_monotonicity(self):
        with _WS("WindowMath.sol", VIEW_HELPER_SOL) as w:
            s = _build(w.ws, w.contract)
        fams = {r["family"] for r in s["invariants"] if r["function"] == "_priceForTick"}
        self.assertIn("read_monotonicity", fams)

    def test_read_invariants_tagged_read_side_and_true_0day(self):
        with _WS("WindowMath.sol", VIEW_HELPER_SOL) as w:
            s = _build(w.ws, w.contract)
        read_recs = [r for r in s["invariants"] if r["invariant_class"] == "read-side"]
        self.assertTrue(read_recs)
        for r in read_recs:
            # a view fn writes no state -> the source function must be a view
            self.assertEqual(r["detector_match"], "none")
            self.assertEqual(r["discovery_mode"], "spec-violation-counterexample-search")

    def test_read_invariants_are_real_relations(self):
        with _WS("WindowMath.sol", VIEW_HELPER_SOL) as w:
            s = _build(w.ws, w.contract)
        read_recs = [r for r in s["invariants"] if r["invariant_class"] == "read-side"]
        self.assertTrue(read_recs)
        for r in read_recs:
            self.assertTrue(
                mod._is_real_relation(r["assertion_expr"]),
                f"non-real read-assertion {r['function']}/{r['family']}: {r['assertion_expr']}",
            )

    def test_read_invariants_ground_in_corpus_category(self):
        # READ-class families ground in their underlying corpus category so R58
        # grounding resolves to real INV-* ids (epoch_boundary -> bounds, etc.)
        with _WS("WindowMath.sol", VIEW_HELPER_SOL) as w:
            s = _build(w.ws, w.contract)
        read_recs = [r for r in s["invariants"] if r["invariant_class"] == "read-side"]
        grounded = [r for r in read_recs if r["grounding_invariant_ids"]]
        self.assertTrue(grounded, "no read-class invariant grounded in a corpus category")
        for r in grounded:
            # grounding category is a real corpus category, not the read-class name
            # (freshness added iter13-B: the read_staleness read-class family
            # grounds in the freshness corpus category).
            self.assertIn(
                r["grounding_category"],
                {"bounds", "conservation", "monotonicity", "determinism", "freshness"},
            )
            for inv in r["grounding_invariant_ids"]:
                self.assertTrue(inv.startswith("INV-"), inv)

    def test_view_fns_do_not_produce_mutating_state_class(self):
        # a view function must NEVER be tagged mutating-state
        with _WS("WindowMath.sol", VIEW_HELPER_SOL) as w:
            s = _build(w.ws, w.contract)
        view_names = {"_windowBoundaryEnd", "_computeTotalOwed", "_priceForTick", "currentRate"}
        for r in s["invariants"]:
            if r["function"] in view_names:
                self.assertEqual(r["invariant_class"], "read-side")

    def test_read_family_mapping_is_class_level(self):
        # the read-family mapping fires on the ROLE a name implies, not a
        # specific symbol: a synthetic "_epochEndOf" view maps to epoch_boundary
        fn = mod.Fn(name="_epochEndOf", params="uint256 id", visibility="internal", mutating=False)
        fams = mod._read_families_for_fn(fn)
        self.assertIn("epoch_boundary", fams)

    def test_read_shape_fallback_when_name_uninformative(self):
        # an uninformatively-named view returning a numeric still derives a
        # bounds/determinism read-invariant via the shape fallback
        fn = mod.Fn(name="_xform", params="uint256 a", visibility="internal", mutating=False)
        fams = mod._read_families_for_fn(fn)
        self.assertTrue(fams)
        self.assertTrue(set(fams) & {"bounds_on_computed_value", "read_determinism"})


class TestNormalizationAndStaleness(unittest.TestCase):
    """Regression lock (iter13-B): the Go derivation path now expresses

    (BS-2) CONSERVATION / NORMALIZATION invariants with REAL bound symbols for a
    distribution field (sum-to-total, all-positive) instead of collapsing to a
    symbol-less `bounds` placeholder, and

    (BS-3) a read-class FRESHNESS / STALENESS family for a stored last_update
    consumed by a pure-read getter.

    Both are GENERAL, class-level capabilities proved on synthetic fixtures - the
    fixture symbol names are invented, never the Quicksilver/Synthetify ones.
    """

    # ---- BS-2: normalization / conservation with real symbols ----

    def test_distribution_writer_derives_normalization_family(self):
        with _WS("dist.go", DISTRIBUTION_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        fams_by_fn = {}
        for r in s["invariants"]:
            fams_by_fn.setdefault(r["function"], set()).add(r["family"])
        self.assertIn("normalization", fams_by_fn.get("SetPayoutShares", set()))
        self.assertIn("normalization", fams_by_fn.get("Rebalance", set()))

    def test_normalization_binds_real_distribution_symbol(self):
        # the prior bug bound the SDK ctx param / a placeholder; now it must bind
        # the real distribution struct field.
        with _WS("dist.go", DISTRIBUTION_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        norm = [r for r in s["invariants"] if r["family"] == "normalization"]
        self.assertTrue(norm)
        for r in norm:
            self.assertEqual(r["bound_symbol"], "payoutShares")
            # the SDK ctx param must NEVER be the bound symbol
            self.assertNotEqual(r["bound_symbol"], "ctx")
            self.assertNotIn(r["bound_symbol"], (None, "state"))

    def test_normalization_assertion_is_real_relation_with_distinct_fields(self):
        with _WS("dist.go", DISTRIBUTION_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        norm = [r for r in s["invariants"] if r["family"] == "normalization"]
        self.assertTrue(norm)
        for r in norm:
            expr = r["assertion_expr"]
            self.assertTrue(mod._is_real_relation(expr), expr)
            # the assertion compares the components-sum to the denominator and
            # the min-component to a positive floor - distinct fields, no tautology.
            self.assertIn("components_sum", expr)
            self.assertIn("denominator", expr)
            self.assertIn("min_component", expr)
            # When the bare assertion is wrapped as an engine-checkable boolean
            # property (`return <expr>;`, the render convention), the proof gate
            # must NOT consider it a tautology - distinct fields, real operator.
            if gate is not None and hasattr(gate, "_is_tautological_body"):
                self.assertFalse(
                    gate._is_tautological_body(f"return {expr};"),
                    f"proof-gate tautology when rendered: {expr}",
                )

    def test_normalization_grounds_in_conservation_corpus(self):
        with _WS("dist.go", DISTRIBUTION_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        norm = [r for r in s["invariants"] if r["family"] == "normalization"]
        self.assertTrue(norm)
        for r in norm:
            self.assertEqual(r["grounding_category"], "conservation")
            for inv in r["grounding_invariant_ids"]:
                self.assertTrue(inv.startswith("INV-"), inv)

    def test_normalization_is_class_level_via_shape(self):
        # a distribution param shape maps to normalization even with an unknown
        # method name (class-level, not name-tuned).
        fn = mod.Fn(name="frobshuffle", params="weights []Weight", visibility="pub", mutating=True)
        fams = mod._families_for_fn(fn)
        self.assertIn("normalization", fams)

    # ---- BS-3: read-class freshness / staleness ----

    def test_staleness_read_classified_as_view(self):
        with _WS("oracle.go", STALENESS_READ_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        # the getter is read-classified; the writer is not
        self.assertEqual(s["view_functions"], 1)
        recs = {(r["function"], r["invariant_class"]) for r in s["invariants"]}
        self.assertIn(("GetFeedValue", "read-side"), recs)
        # the mutating SetFeedValue must stay mutating-state
        setter = [r for r in s["invariants"] if r["function"] == "SetFeedValue"]
        self.assertTrue(setter)
        for r in setter:
            self.assertEqual(r["invariant_class"], "mutating-state")

    def test_staleness_read_derives_read_staleness_family(self):
        with _WS("oracle.go", STALENESS_READ_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        fams = {r["family"] for r in s["invariants"] if r["function"] == "GetFeedValue"}
        self.assertIn("read_staleness", fams)

    def test_staleness_assertion_gates_on_last_update(self):
        with _WS("oracle.go", STALENESS_READ_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        stale = [r for r in s["invariants"]
                 if r["family"] == "read_staleness" and r["function"] == "GetFeedValue"]
        self.assertTrue(stale)
        for r in stale:
            expr = r["assertion_expr"]
            self.assertTrue(mod._is_real_relation(expr), expr)
            self.assertIn("last_update", expr)
            self.assertIn("max_staleness", expr)
            # the read-now clock placeholder must be substituted, not left raw
            self.assertNotIn("{read_now}", expr)
            self.assertEqual(r["invariant_class"], "read-side")

    def test_staleness_grounds_in_freshness_corpus(self):
        with _WS("oracle.go", STALENESS_READ_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        stale = [r for r in s["invariants"] if r["family"] == "read_staleness"]
        self.assertTrue(stale)
        for r in stale:
            self.assertEqual(r["grounding_category"], "freshness")
            for inv in r["grounding_invariant_ids"]:
                self.assertTrue(inv.startswith("INV-"), inv)

    def test_read_staleness_is_class_level_via_name_role(self):
        # the read-family mapping fires on the read ROLE a name implies, not a
        # specific protocol symbol: a synthetic price/oracle getter -> staleness.
        fn = mod.Fn(name="getOraclePrice", params="bytes32 id", visibility="public", mutating=False)
        fams = mod._read_families_for_fn(fn)
        self.assertIn("read_staleness", fams)

    def test_rust_staleness_read_reaches_read_class(self):
        # BS-3 anchor was Synthetify (Rust): a pure-read getter returning a
        # stored value must reach the read-class staleness family, and the &mut
        # writer must stay mutating-state.
        with _WS("asset.rs", STALENESS_READ_RS) as w:
            s = _build(w.ws, w.contract, lang="rust")
        self.assertEqual(s["view_functions"], 1)
        getter = [r for r in s["invariants"] if r["function"] == "get_spot_value"]
        self.assertTrue(getter)
        fams = {r["family"] for r in getter}
        self.assertIn("read_staleness", fams)
        for r in getter:
            self.assertEqual(r["invariant_class"], "read-side")
        # the &mut writer stays mutating-state
        setter = [r for r in s["invariants"] if r["function"] == "set_spot_value"]
        self.assertTrue(setter)
        for r in setter:
            self.assertEqual(r["invariant_class"], "mutating-state")
        # test helper still excluded
        self.assertNotIn("test_helper", {r["function"] for r in s["invariants"]})

    def test_rust_mut_param_forces_mutating(self):
        # a read-role name with a &mut param must NOT be read-classified
        self.assertTrue(mod._rs_is_mutating("get_and_bump", "state: &mut S", "u64"))
        # a read-role getter with no &mut and a value return is a view
        self.assertFalse(mod._rs_is_mutating("get_value", "state: &S", "u64"))
        # a unit/ProgramResult return is conservatively mutating
        self.assertTrue(mod._rs_is_mutating("get_thing", "state: &S", "ProgramResult"))
        self.assertTrue(mod._rs_is_mutating("get_thing", "state: &S", "Result<(), E>"))

    def test_go_mutate_verb_anchoring_no_substring_trap(self):
        # "Asset" contains "set" and "Address" contains "add"; neither must be
        # mis-classified as a mutating verb (anchored-prefix match).
        self.assertFalse(mod._go_is_mutating("GetAssetPrice", "(uint64, error)"))
        self.assertFalse(mod._go_is_mutating("GetAddressBalance", "(uint64, error)"))
        # a genuine setter is still mutating
        self.assertTrue(mod._go_is_mutating("SetAssetPrice", "error"))
        # a read-role name that returns only an error is conservatively mutating
        self.assertTrue(mod._go_is_mutating("GetFoo", "error"))


class TestValidateClassDistributionTrigger(unittest.TestCase):
    """Regression lock (iter13): a fn whose name carries a WEAK verb but whose
    param is a slice-of-STRUCT distribution must derive a NORMALIZATION invariant
    bound to the REAL collection state symbol, not collapse to a symbol-less /
    scalar `bounds` placeholder. Proven on a GENERIC fixture - the fixture symbol
    names (validateDistribution / memberWeights / WeightEntry) are invented, never
    the known target's (validateIntents / validatorWeights / ValidatorIntent), so
    this asserts the CLASS-level trigger broadening, not a symbol-tuned hack.
    """

    def test_validate_distribution_derives_normalization(self):
        with _WS("vd.go", VALIDATE_DISTRIBUTION_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        fams = {r["family"] for r in s["invariants"] if r["function"] == "validateDistribution"}
        self.assertIn("normalization", fams)

    def test_validate_distribution_binds_real_collection_symbol(self):
        with _WS("vd.go", VALIDATE_DISTRIBUTION_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        norm = [r for r in s["invariants"]
                if r["function"] == "validateDistribution" and r["family"] == "normalization"]
        self.assertTrue(norm, "validateDistribution derived no normalization invariant")
        for r in norm:
            # MUST bind the real collection distribution field, not a None
            # placeholder, not a bare per-element scalar (`Weight`), not the SDK
            # ctx param.
            self.assertEqual(r["bound_symbol"], "memberWeights")
            self.assertNotIn(r["bound_symbol"], (None, "state", "ctx", "Weight"))

    def test_validate_distribution_assertion_is_real_relation(self):
        with _WS("vd.go", VALIDATE_DISTRIBUTION_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        norm = [r for r in s["invariants"]
                if r["function"] == "validateDistribution" and r["family"] == "normalization"]
        self.assertTrue(norm)
        for r in norm:
            expr = r["assertion_expr"]
            self.assertTrue(mod._is_real_relation(expr), expr)
            self.assertIn("components_sum", expr)
            self.assertIn("denominator", expr)

    def test_weak_verb_without_dist_shape_not_normalization(self):
        # the discipline guard: a WEAK verb (`validate`) WITHOUT a distribution
        # param shape must NOT be mis-mapped to normalization.
        fn = mod.Fn(name="validateSignature", params="bytes sig, address signer",
                    visibility="internal", mutating=True)
        fams = mod._families_for_fn(fn)
        self.assertNotIn("normalization", fams)

    def test_slice_of_struct_param_detected_as_distribution(self):
        # class-level shape detector: a slice-of-struct element type carrying a
        # dist token is recognized regardless of element type name.
        self.assertTrue(mod._params_carry_distribution("intents []ValidatorIntent"))
        self.assertTrue(mod._params_carry_distribution("vals []*WeightAlloc"))
        self.assertTrue(mod._params_carry_distribution("shares Vec<ShareEntry>"))
        self.assertTrue(mod._params_carry_distribution("weights []uint256"))
        # a non-distribution param must NOT be flagged
        self.assertFalse(mod._params_carry_distribution("bytes sig, address signer"))
        self.assertFalse(mod._params_carry_distribution("uint256 amount"))

    def test_strong_dist_name_fires_without_params(self):
        # a STRONG distribution-role name binds normalization on the name alone.
        for nm in ("reweightValidators", "distributeRewards", "apportionShares"):
            fn = mod.Fn(name=nm, params="", visibility="external", mutating=True)
            self.assertIn("normalization", mod._families_for_fn(fn), nm)

    def test_epoch_helper_derives_epoch_boundary(self):
        # a pure-read epoch/window boundary helper must derive the inclusive-vs-
        # exclusive epoch_boundary read-class invariant (the second half of the
        # iter13 class signal: an epoch helper is reached and bound, not dropped).
        with _WS("eh.go", EPOCH_HELPER_GO) as w:
            s = _build(w.ws, w.contract, lang="go")
        rec = [r for r in s["invariants"] if r["function"] == "getEpochEnd"]
        self.assertTrue(rec, "getEpochEnd derived no invariant")
        fams = {r["family"] for r in rec}
        self.assertIn("epoch_boundary", fams)
        for r in rec:
            if r["family"] == "epoch_boundary":
                self.assertIsNotNone(r["bound_symbol"])
                self.assertNotIn(r["bound_symbol"], (None, "state"))
                self.assertEqual(r["invariant_class"], "read-side")


class TestFamilyMapping(unittest.TestCase):
    def test_known_name_maps_to_families(self):
        fn = mod.Fn(name="deposit", params="uint256 amount", visibility="external", mutating=True)
        fams = mod._families_for_fn(fn)
        self.assertIn("conservation", fams)

    def test_unknown_name_falls_back_to_shape(self):
        fn = mod.Fn(name="frobnicate", params="address to, uint256 v", visibility="external", mutating=True)
        fams = mod._families_for_fn(fn)
        self.assertTrue(fams)  # never empty

    def test_symbol_binding_prefers_aggregate(self):
        fn = mod.Fn(name="deposit", params="uint256 amount", visibility="external", mutating=True)
        sym = mod._pick_symbol("conservation", ["owner", "totalAssets", "foo"], fn)
        self.assertEqual(sym, "totalAssets")

    def test_freshness_returns_none_without_time_var(self):
        fn = mod.Fn(name="resolve", params="", visibility="external", mutating=True)
        sym = mod._pick_symbol("freshness", ["owner", "totalAssets"], fn)
        self.assertIsNone(sym)


class TestRealRelationPredicate(unittest.TestCase):
    def test_rejects_self_equality(self):
        self.assertFalse(mod._is_real_relation("x == x"))

    def test_rejects_neutered_mod(self):
        self.assertFalse(mod._is_real_relation("y == x % 1"))

    def test_accepts_genuine_relation(self):
        self.assertTrue(mod._is_real_relation("a_post <= b_pre"))

    def test_rejects_no_relation(self):
        self.assertFalse(mod._is_real_relation("totalAssets"))


class TestJSONExtraction(unittest.TestCase):
    def test_extract_plain_json(self):
        self.assertEqual(mod._extract_json_obj('{"a":1}'), {"a": 1})

    def test_extract_fenced_json(self):
        self.assertEqual(mod._extract_json_obj('```json\n{"a":2}\n```'), {"a": 2})

    def test_extract_embedded_json(self):
        self.assertEqual(mod._extract_json_obj('prefix {"a":3} suffix'), {"a": 3})

    def test_extract_garbage_returns_none(self):
        self.assertIsNone(mod._extract_json_obj("no json here"))


class TestSchemaAndSummary(unittest.TestCase):
    def test_summary_schema(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            s = _build(w.ws, w.contract)
        self.assertEqual(s["schema_version"], mod.SUMMARY_SCHEMA)
        for r in s["invariants"]:
            self.assertEqual(r["schema_version"], mod.SCHEMA)

    def test_per_family_counts_consistent(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            s = _build(w.ws, w.contract)
        self.assertEqual(sum(s["per_family"].values()), s["invariants_derived"])


class TestRenderDelegation(unittest.TestCase):
    def test_render_produces_proof_gate_passing_harness(self):
        if gate is None:
            self.skipTest("engine-harness-proof-gate.py not present")
        with _WS("Vault.sol", VAULT_SOL) as w:
            out_dir = w.ws / ".auditooor" / "nh"
            s = _build(w.ws, w.contract, render=True, out_dir=out_dir)
            self.assertIsNotNone(s["render"])
            if not s["render"].get("rendered"):
                self.skipTest(f"render unavailable: {s['render'].get('reason')}")
            # render must emit the engine-checkable Solidity property files that
            # the existing engines (halmos/medusa/echidna/forge) run as the
            # counterexample search; must run before the tempdir is cleaned up.
            sol_props = list(out_dir.rglob("*.sol"))
            self.assertTrue(sol_props, "render emitted no Solidity property files")


class TestCLI(unittest.TestCase):
    def test_cli_json_and_jsonl_output(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            out = w.ws / "novel.jsonl"
            rc = mod.main(
                [
                    "--workspace", str(w.ws),
                    "--contract", str(w.contract),
                    "--output", str(out),
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())
            lines = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertTrue(lines)
            for r in lines:
                self.assertEqual(r["schema_version"], mod.SCHEMA)

    def test_cli_missing_contract_exits_2(self):
        with _WS("Vault.sol", VAULT_SOL) as w:
            rc = mod.main(["--workspace", str(w.ws), "--contract", "src/Nope.sol"])
            self.assertEqual(rc, 2)


# r36-rebuttal: bugfix-inventory-claude-20260610
# Minimal Cairo 1.0-ish source with `fn` patterns (Noir syntax is identical at
# this level; the _RS_FN regex finds `fn` keywords and handles both).
NOIR_FN_SRC = """
pub fn add_liquidity(amount: Field) {}
pub fn remove_liquidity(shares: Field) {}
fn _settle(val: Field) {}
"""

# Cairo 1.0 uses `fn` for free functions too (subset also caught by _RS_FN).
CAIRO_FN_SRC = """
fn deposit(amount: u256) {}
fn withdraw(shares: u256) {}
"""


class TestUnsupportedLangGracefulHandling(unittest.TestCase):
    """Regression lock: detect_lang must NOT fall through to 'solidity' for
    .cairo / .nr / .vy / .ts extensions (bug: line 748 fallback was 'solidity',
    which caused the EVM parser to be invoked on non-EVM source, producing a hard
    ValueError / exit-2 instead of a graceful empty Surface or move-fallback parse).

    The fix adds explicit branches for .cairo -> 'cairo', .nr -> 'noir',
    .vy -> 'vyper', and routes any remaining unknown extension to its raw name
    so parse_surface's unsupported-lang guard can handle it gracefully.
    """

    def test_detect_lang_cairo_does_not_fall_through_to_solidity(self):
        # THE primary regression guard: .cairo must NOT map to 'solidity'.
        p = Path("ERC20.cairo")
        result = mod.detect_lang(p, "auto")
        self.assertNotEqual(
            result, "solidity",
            ".cairo file must not be detected as 'solidity' - it would invoke the EVM parser "
            "which raises ValueError on non-EVM source, causing a hard exit-2.",
        )
        self.assertEqual(result, "cairo")

    def test_detect_lang_noir_does_not_fall_through_to_solidity(self):
        p = Path("token.nr")
        result = mod.detect_lang(p, "auto")
        self.assertNotEqual(result, "solidity", ".nr must not map to 'solidity'")
        self.assertEqual(result, "noir")

    def test_detect_lang_vyper_does_not_fall_through_to_solidity(self):
        p = Path("vault.vy")
        result = mod.detect_lang(p, "auto")
        self.assertNotEqual(result, "solidity", ".vy must not map to 'solidity'")
        self.assertEqual(result, "vyper")

    def test_detect_lang_unknown_ext_not_solidity(self):
        # A .ts file should not be silently treated as Solidity.
        p = Path("token.ts")
        result = mod.detect_lang(p, "auto")
        self.assertNotEqual(
            result, "solidity",
            ".ts must not map to 'solidity' - TypeScript source would cause the EVM parser "
            "to raise ValueError.",
        )

    def test_cairo_build_does_not_raise_value_error(self):
        # A .cairo file passed with lang='auto' must NOT raise ValueError and must
        # NOT exit with code 2. The EVM parser must never be invoked on Cairo source.
        with _WS("ERC20.cairo", CAIRO_FN_SRC) as w:
            # This call would crash (ValueError from EVM parser) before the fix.
            try:
                s = _build(w.ws, w.contract, lang="auto")
            except ValueError as e:
                self.fail(
                    f"build() raised ValueError for a .cairo file: {e}. "
                    "The EVM parser should not be called on non-EVM source."
                )
            # The surface lang must reflect 'cairo', not 'solidity'.
            self.assertEqual(s["target_lang"], "cairo")

    def test_noir_build_does_not_raise_value_error(self):
        # A .nr file must parse without ValueError; Noir uses 'fn' syntax so
        # _RS_FN finds functions via the move/fallback branch.
        with _WS("token.nr", NOIR_FN_SRC) as w:
            try:
                s = _build(w.ws, w.contract, lang="auto")
            except ValueError as e:
                self.fail(f"build() raised ValueError for a .nr file: {e}")
            self.assertEqual(s["target_lang"], "noir")

    def test_unknown_ext_build_returns_graceful_empty_surface(self):
        # A .ts file must return an empty Surface (no functions, no crash), not raise.
        # The unsupported-lang guard in parse_surface handles this.
        with _WS("token.ts", "const x = 1;") as w:
            try:
                s = _build(w.ws, w.contract, lang="auto")
            except ValueError as e:
                self.fail(f"build() raised ValueError for a .ts file: {e}")
            # An empty surface is acceptable; 0 invariants is correct for an unknown lang.
            self.assertEqual(s["functions_parsed"], 0)
            self.assertEqual(s["invariants_derived"], 0)

    def test_known_langs_unaffected_by_fix(self):
        # The fix must not disturb known language detection.
        self.assertEqual(mod.detect_lang(Path("Vault.sol"), "auto"), "solidity")
        self.assertEqual(mod.detect_lang(Path("keeper.go"), "auto"), "go")
        self.assertEqual(mod.detect_lang(Path("pallet.rs"), "auto"), "rust")
        self.assertEqual(mod.detect_lang(Path("module.move"), "auto"), "move")

    def test_explicit_lang_override_unaffected(self):
        # An explicit lang= override must always win, regardless of extension.
        self.assertEqual(mod.detect_lang(Path("ERC20.cairo"), "solidity"), "solidity")
        self.assertEqual(mod.detect_lang(Path("token.ts"), "rust"), "rust")


if __name__ == "__main__":
    unittest.main()
