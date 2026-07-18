"""Guard tests for the fail-closed vacuity gate.

A sentinel-only harness (whose ONLY assertion is assert(true)/assert!(true)/
assert True/...) must be REJECTED everywhere it could be credited as coverage:

  1. The shared predicate tools/lib/harness_vacuity.is_sentinel_only_harness
     flags every sentinel form the generator emits, and PASSES a real predicate.
  2. tools/per-function-invariant-gen.py stamps each manifest row `is_sentinel`
     and reports a manifest-level `sentinel_count` (its emitted scaffolds are
     all sentinel, so sentinel_count == function_count > 0).
  3. tools/mutation-verify-coverage.py.verify() short-circuits a sentinel-only
     harness to verdict `no-property-discovered` (NEVER non-vacuous, with
     genuine_coverage False) BEFORE the mutation loop, while a real-predicate
     harness is NOT short-circuited (it proceeds into the loop).

These are genuine fail-before / pass-after guards: each "real predicate passes"
assertion would FAIL against a sentinel body, and each "sentinel rejected"
assertion would FAIL if the gate were a no-op.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEN_TOOL = ROOT / "tools" / "per-function-invariant-gen.py"
MVC_TOOL = ROOT / "tools" / "mutation-verify-coverage.py"
VAC_LIB = ROOT / "tools" / "lib" / "harness_vacuity.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class HarnessVacuityPredicateTest(unittest.TestCase):
    """Layer 1: the shared predicate."""

    def setUp(self):
        self.vac = _load(VAC_LIB, "harness_vacuity_t")

    def test_solidity_assert_true_is_sentinel(self):
        body = (
            "contract Halmos_X_f {\n"
            "  function check_f_does_not_break_core_invariant() public {\n"
            "    assert(true);\n  }\n}\n"
        )
        self.assertTrue(self.vac.is_sentinel_only_harness(body))

    def test_rust_assert_bang_true_is_sentinel(self):
        body = "#[test]\nfn prop_f() {\n    assert!(true);\n}\n"
        self.assertTrue(self.vac.is_sentinel_only_harness(body))

    def test_move_assert_true_arg_is_sentinel(self):
        body = "#[test]\nfun test_f() {\n    assert!(true, 0);\n}\n"
        self.assertTrue(self.vac.is_sentinel_only_harness(body))

    def test_cairo_assert_true_msg_is_sentinel(self):
        body = "#[test]\nfn test_f() {\n    assert(true, 'invariant placeholder');\n}\n"
        self.assertTrue(self.vac.is_sentinel_only_harness(body))

    def test_vyper_bare_assert_true_is_sentinel(self):
        body = "def test_f_invariant():\n    assert True  # placeholder\n"
        self.assertTrue(self.vac.is_sentinel_only_harness(body))

    def test_cadence_test_assert_true_is_sentinel(self):
        body = "access(all) fun test_f() {\n    Test.assert(true)\n}\n"
        self.assertTrue(self.vac.is_sentinel_only_harness(body))

    def test_go_stub_body_is_sentinel(self):
        body = (
            "func TestXInvariant(t *testing.T) {\n"
            "    // SENTINEL: replace with a real property.\n    _ = t\n}\n"
        )
        self.assertTrue(self.vac.is_sentinel_only_harness(body))

    def test_no_assertion_at_all_is_sentinel(self):
        self.assertTrue(self.vac.is_sentinel_only_harness("contract X { function f() public {} }"))

    def test_empty_is_sentinel(self):
        self.assertTrue(self.vac.is_sentinel_only_harness(""))

    def test_comment_only_assert_true_in_preamble_is_sentinel(self):
        # The example proptest form lives in comments; must be stripped, not
        # mistaken for a real property. Body is still a sentinel.
        body = (
            "// Suggested form:\n//   prop_assert!(out == expected);\n"
            "#[test]\nfn prop_f() {\n    assert!(true);\n}\n"
        )
        self.assertTrue(self.vac.is_sentinel_only_harness(body))

    # ---- PASS-AFTER: a real source-grounded property is NOT a sentinel. ----

    def test_solidity_real_relation_passes(self):
        body = (
            "contract H { function check_f() public {\n"
            "    uint256 b = t.balance();\n    t.f(10);\n"
            "    assert(t.balance() == b + 10);\n  }\n}\n"
        )
        self.assertFalse(self.vac.is_sentinel_only_harness(body))

    def test_rust_real_assert_eq_passes(self):
        body = "#[test]\nfn prop_f() {\n    let out = f(3);\n    assert_eq!(out, 6);\n}\n"
        self.assertFalse(self.vac.is_sentinel_only_harness(body))

    def test_return_bool_relation_passes(self):
        body = "function echidna_sum() public returns (bool) {\n    return total <= cap;\n}\n"
        self.assertFalse(self.vac.is_sentinel_only_harness(body))

    def test_return_self_eq_is_sentinel(self):
        body = "function echidna_x() public returns (bool) {\n    return total == total;\n}\n"
        self.assertTrue(self.vac.is_sentinel_only_harness(body))

    def test_go_real_fatal_passes(self):
        body = (
            "func TestX(t *testing.T) {\n    out := f(1)\n"
            '    if out != 2 { t.Fatalf("bad: %v", out) }\n}\n'
        )
        self.assertFalse(self.vac.is_sentinel_only_harness(body))

    def test_vyper_real_assert_passes(self):
        body = "def test_f():\n    out = c.f(5)\n    assert out == 10\n"
        self.assertFalse(self.vac.is_sentinel_only_harness(body))

    def test_negative_control_passes(self):
        body = (
            "contract H { function check_revert() public {\n"
            "    vm.expectRevert();\n    t.f(0);\n  }\n}\n"
        )
        self.assertFalse(self.vac.is_sentinel_only_harness(body))


class DeepVacuityModeTest(unittest.TestCase):
    """Layer 1b: deep-mode static detectors (modes 1, 4, 4b, 5-subterm,
    5-skeleton, 6). Each fixture uses a REAL body shape from the taxonomy and
    asserts the mode FIRES; a genuine paired fixture (morpho VaultV2
    invariant_cap style) asserts CLEAN. These are fail-before / pass-after
    guards: each "fires" assertion would FAIL if the detector were a no-op, and
    the genuine fixture would FAIL if the detector over-fired."""

    def setUp(self):
        self.vac = _load(VAC_LIB, "harness_vacuity_deep_t")

    # ---- mode 1: setUp-max-bound (type(uint256).max cap). ----
    def test_setup_max_bound_fires(self):
        body = (
            "contract H {\n"
            "  uint256 absoluteCap;\n"
            "  function setUp() public {\n"
            "    absoluteCap = type(uint256).max;\n  }\n"
            "  function invariant_cap() public {\n"
            "    require(allocation <= absoluteCap);\n  }\n}\n"
        )
        self.assertTrue(self.vac.is_setup_max_bound(body))
        self.assertIn(self.vac.MODE_SETUP_MAX_BOUND, self.vac.deep_vacuity_modes(body))

    def test_setup_max_bound_pow_form_fires(self):
        body = (
            "contract H {\n"
            "  function setUp() public { uint256 supplyLimit = 2**256-1; "
            "  }\n"
            "  function invariant_x() public { assert(total <= supplyLimit); }\n}\n"
        )
        self.assertTrue(self.vac.is_setup_max_bound(body))

    def test_finite_cap_is_clean_mode1(self):
        # morpho EconInvariant_MetaMorpho FINITE binding caps defeat mode 1.
        body = (
            "contract H {\n"
            "  uint256 CAP_A;\n"
            "  function setUp() public { CAP_A = 1e20; }\n"
            "  function invariant_cap() public { require(allocation <= CAP_A); }\n}\n"
        )
        self.assertFalse(self.vac.is_setup_max_bound(body))

    # ---- mode 4b: dead-CUT-guard (target==address(0) guard). ----
    def test_dead_cut_guard_fires(self):
        body = (
            "contract H {\n"
            "  Target target;\n"
            "  function bindTarget(address a) public { target = Target(a); }\n"
            "  function setUp() public { /* never binds target */ uint x = 1; }\n"
            "  function invariant_a() public {\n"
            "    if (address(target) != address(0)) { target.poke(); }\n"
            "    assert(ghostTotalIn == ghostTotalOut);\n  }\n}\n"
        )
        self.assertTrue(self.vac.is_dead_cut_guard(body))
        self.assertIn(self.vac.MODE_DEAD_CUT_GUARD, self.vac.deep_vacuity_modes(body))

    def test_bound_target_in_setup_is_clean_mode4b(self):
        body = (
            "contract H {\n"
            "  Target target;\n"
            "  function bindTarget(address a) public { target = Target(a); }\n"
            "  function setUp() public { bindTarget(address(real)); }\n"
            "  function invariant_a() public {\n"
            "    if (address(target) != address(0)) { target.poke(); }\n  }\n}\n"
        )
        self.assertFalse(self.vac.is_dead_cut_guard(body))

    # ---- mode 4: model-counter invariant (ghost totalIn==totalOut+fees). ----
    def test_model_counter_invariant_fires(self):
        body = (
            "contract H {\n"
            "  uint256 totalIn; uint256 totalOut; uint256 feesAccrued;\n"
            "  function mutate_deposit(uint256 a) public {\n"
            "    totalIn += a; feesAccrued += a / 100;\n  }\n"
            "  function mutate_withdraw(uint256 a) public { totalOut += a; }\n"
            "  function invariant_conservation() public {\n"
            "    assert(totalIn == totalOut + feesAccrued);\n  }\n}\n"
        )
        self.assertTrue(self.vac.is_model_counter_invariant(body))
        self.assertIn(
            self.vac.MODE_MODEL_COUNTER_INVARIANT, self.vac.deep_vacuity_modes(body)
        )

    def test_real_view_read_is_clean_mode4(self):
        # ssv property_operator_index_monotone style: reads REAL storage.
        body = (
            "contract H {\n"
            "  uint256 totalIn;\n"
            "  function mutate_deposit(uint256 a) public { totalIn += a; }\n"
            "  function invariant_real() public {\n"
            "    assert(target.totalSupply() >= totalIn);\n  }\n}\n"
        )
        self.assertFalse(self.vac.is_model_counter_invariant(body))

    # ---- mode 5 (subterm): controlCase && real. ----
    def test_tautological_subterm_and_fires(self):
        # etherfi CashModuleCore_FuzzProps: controlCase=(after>=before||before>=after).
        body = (
            "contract H {\n"
            "  function check_props() public {\n"
            "    assertTrue((after >= before || before >= after) && realInvariant);\n  }\n}\n"
        )
        self.assertTrue(self.vac.is_tautological_subterm_and(body))
        self.assertIn(
            self.vac.MODE_TAUTOLOGICAL_SUBTERM_AND, self.vac.deep_vacuity_modes(body)
        )

    def test_reflexive_eq_and_fires(self):
        body = (
            "contract H { function check_x() public {\n"
            "    assert((x == x) && total <= cap);\n  }\n}\n"
        )
        self.assertTrue(self.vac.is_tautological_subterm_and(body))

    def test_genuine_and_is_clean_subterm(self):
        # A real AND of two genuine relations is NOT a tautological subterm.
        body = (
            "contract H { function check_x() public {\n"
            "    assert((a <= b) && (c <= d));\n  }\n}\n"
        )
        self.assertFalse(self.vac.is_tautological_subterm_and(body))

    # ---- mode 5 (skeleton): assertTrue(false, "...materialized-skeleton..."). ----
    def test_sentinel_skeleton_fires(self):
        body = (
            "contract Invariant_EQ_001 {\n"
            "  function test_eq() public {\n"
            "    assertTrue(false, \"materialized-skeleton: TODO body, not yet proven\");\n  }\n}\n"
        )
        self.assertTrue(self.vac.is_sentinel_skeleton(body))
        self.assertIn(
            self.vac.MODE_SENTINEL_SKELETON, self.vac.deep_vacuity_modes(body)
        )

    def test_assert_false_without_skeleton_marker_is_clean_mode5(self):
        # assertTrue(false, "real revert reason") is a real negative assertion,
        # not a skeleton placeholder.
        body = (
            "contract H { function check() public {\n"
            "    assertTrue(false, \"deposit must revert when paused\");\n  }\n}\n"
        )
        self.assertFalse(self.vac.is_sentinel_skeleton(body))

    # ---- mode 6: mock-callpath-vacuity (.call without receive, witness==0). ----
    def test_mock_callpath_vacuity_fires(self):
        body = (
            "contract LiquidityControllerMock is LiquidityController {\n"
            "  uint256 wPayout;\n"
            "  function h_payout(uint256 a) public {\n"
            "    (bool ok,) = recipient.call{value: a}(\"\");\n"
            "    if (ok) { wPayout += 1; }\n  }\n"
            "  function invariant_x() public { assert(total <= cap); }\n}\n"
        )
        self.assertTrue(self.vac.is_mock_callpath_vacuity(body))
        self.assertIn(
            self.vac.MODE_MOCK_CALLPATH_VACUITY, self.vac.deep_vacuity_modes(body)
        )

    def test_mock_force_send_no_receive_fires(self):
        body = (
            "contract VaultMock is Vault {\n"
            "  uint256 wMove;\n"
            "  function h_move(uint256 a) public { selfdestruct(payable(sink)); }\n"
            "  function invariant_x() public { assert(true); }\n}\n"
        )
        self.assertTrue(self.vac.is_mock_callpath_vacuity(body))

    def test_mock_with_receive_and_witness_is_clean_mode6(self):
        # etherfi CashSolvency genuine harness: receive() present + witness >0.
        body = (
            "contract CashSolvencyHarness is CashModule {\n"
            "  uint256 wBorrow;\n"
            "  receive() external payable {}\n"
            "  function h_borrow(uint256 a) public {\n"
            "    (bool ok,) = recipient.call{value: a}(\"\");\n"
            "    if (ok) { wBorrow += 1; }\n  }\n"
            "  function invariant_reach() public { assertGt(wBorrow, 0); }\n}\n"
        )
        self.assertFalse(self.vac.is_mock_callpath_vacuity(body))

    # ---- GENUINE paired fixture: morpho VaultV2 invariant_cap. CLEAN on ALL. ----
    def test_morpho_vaultv2_invariant_cap_is_clean_on_all_deep_modes(self):
        body = (
            "contract VaultV2InvariantHandler is VaultV2 {\n"
            "  uint256 internal CAP_A = 1e20;\n"
            "  uint256 wDeposit;\n"
            "  VaultV2 vault;\n"
            "  receive() external payable {}\n"
            "  function setUp() public {\n"
            "    vault = VaultV2(factory.create());\n"
            "    bindTarget(address(vault));\n  }\n"
            "  function h_deposit(uint256 a) public {\n"
            "    a = bound(a, 1, token.balanceOf(address(this)));\n"
            "    try vault.deposit(a) { wDeposit += 1; } catch {}\n  }\n"
            "  function invariant_cap() public {\n"
            "    assertLe(vault.allocation(), vault.absoluteCap());\n"
            "    assertGt(wDeposit, 0);\n  }\n}\n"
        )
        self.assertEqual(self.vac.deep_vacuity_modes(body), [], self.vac.deep_vacuity_modes(body))
        # And it is not sentinel-only (a real relational invariant).
        self.assertFalse(self.vac.is_sentinel_only_harness(body))

    def test_deep_reasons_cover_every_mode(self):
        # Every mode deep_vacuity_modes can emit has a reason string.
        for mode in (
            self.vac.MODE_SETUP_MAX_BOUND,
            self.vac.MODE_DEAD_CUT_GUARD,
            self.vac.MODE_MODEL_COUNTER_INVARIANT,
            self.vac.MODE_TAUTOLOGICAL_SUBTERM_AND,
            self.vac.MODE_SENTINEL_SKELETON,
            self.vac.MODE_MOCK_CALLPATH_VACUITY,
        ):
            self.assertIn(mode, self.vac.deep_vacuity_reasons)
            self.assertTrue(self.vac.deep_vacuity_reasons[mode].strip())


class GeneratorStampsSentinelTest(unittest.TestCase):
    """Layer 2: per-function-invariant-gen.py stamps is_sentinel."""

    def test_emitted_solidity_scaffolds_are_all_sentinel(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Vault {\n"
                "  uint256 public total;\n"
                "  function deposit(uint256 a) external { total += a; }\n"
                "}\n",
                encoding="utf-8",
            )
            out = subprocess.run(
                [sys.executable, str(GEN_TOOL), "--workspace", str(ws), "--json"],
                capture_output=True, text=True,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            manifest = json.loads(out.stdout)
            self.assertGreaterEqual(manifest["function_count"], 1)
            # Every emitted scaffold is sentinel-only at emit time.
            self.assertEqual(manifest["sentinel_count"], manifest["function_count"])
            self.assertEqual(manifest["non_sentinel_count"], 0)
            for row in manifest["functions"]:
                self.assertTrue(row["is_sentinel"], row)

    def test_emitted_rust_scaffolds_are_all_sentinel(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "lib.rs").write_text(
                "pub fn deposit(a: u64) -> u64 { a + 1 }\n", encoding="utf-8"
            )
            out = subprocess.run(
                [sys.executable, str(GEN_TOOL), "--workspace", str(ws),
                 "--lang", "rust", "--json"],
                capture_output=True, text=True,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            manifest = json.loads(out.stdout)
            self.assertGreaterEqual(manifest["function_count"], 1)
            self.assertEqual(manifest["sentinel_count"], manifest["function_count"])
            for row in manifest["functions"]:
                self.assertTrue(row["is_sentinel"], row)


class MutationVerifyRejectsSentinelTest(unittest.TestCase):
    """Layer 3: mutation-verify-coverage.verify() short-circuits a sentinel."""

    def setUp(self):
        self.mvc = _load(MVC_TOOL, "mutation_verify_coverage_t")

    def test_sentinel_harness_short_circuits_to_no_property_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "Vault.sol"
            src.write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Vault {\n  uint256 public total;\n"
                "  function deposit(uint256 a) public { total += a; }\n}\n",
                encoding="utf-8",
            )
            harness = ws / "Halmos_Vault_deposit.t.sol"
            harness.write_text(
                "pragma solidity ^0.8.13;\n"
                "contract Halmos_Vault_deposit {\n"
                "  function check_deposit_does_not_break_core_invariant() public {\n"
                "    assert(true);\n  }\n}\n",
                encoding="utf-8",
            )
            rec = self.mvc.verify(
                workspace=ws, source_file=src, function="deposit",
                harness=str(harness), language="solidity",
            )
            # FAIL-CLOSED: a sentinel can never reach non-vacuous / genuine.
            self.assertEqual(rec["verdict"], "no-property-discovered", rec)
            self.assertNotEqual(rec["verdict"], "non-vacuous")
            self.assertFalse(rec.get("genuine_coverage", False))
            self.assertEqual(rec.get("vacuity_gate"), "sentinel-only-harness")

    def test_real_predicate_harness_is_not_short_circuited(self):
        # A real-predicate harness must NOT be rejected by the static gate; it
        # falls through to the (downstream) mutation loop. We assert only that
        # the static gate did NOT fire (verdict is whatever the loop decides,
        # but it carries no vacuity_gate marker and is not the sentinel verdict
        # produced by the static pre-filter).
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "Vault.sol"
            src.write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Vault {\n  uint256 public total;\n"
                "  function deposit(uint256 a) public { total += a; }\n}\n",
                encoding="utf-8",
            )
            harness = ws / "Halmos_Vault_deposit.t.sol"
            harness.write_text(
                "pragma solidity ^0.8.13;\n"
                "contract Halmos_Vault_deposit {\n"
                "  Vault v;\n"
                "  function check_deposit() public {\n"
                "    uint256 b = v.total();\n    v.deposit(7);\n"
                "    assert(v.total() == b + 7);\n  }\n}\n",
                encoding="utf-8",
            )
            rec = self.mvc.verify(
                workspace=ws, source_file=src, function="deposit",
                harness=str(harness), language="solidity",
                max_mutants=1, timeout=30,
            )
            # The STATIC sentinel pre-filter must not have fired.
            self.assertNotEqual(rec.get("vacuity_gate"), "sentinel-only-harness", rec)
            # And it is not the static sentinel verdict shape (it entered the
            # loop / runner; halmos may be absent in CI, that is fine - the point
            # is the gate let it through).


if __name__ == "__main__":
    unittest.main()
