"""Unit tests for engine-harness-proof-gate.py (PR4a).

Anchors:
  - morpho-midnight `assert(true)` halmos stub  -> fail-stub-or-ghost
  - real MidnightBundles_FuzzProps medusa harness -> pass-real-property-executed
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "engine_harness_proof_gate",
    ROOT / "tools" / "engine-harness-proof-gate.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _tmpfile(body: str, suffix: str) -> Path:
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    f.write(body)
    f.close()
    return Path(f.name)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# morpho-midnight assert(true) halmos stub (the FAIL anchor).
HALMOS_STUB = """
pragma solidity ^0.8.0;

contract MidnightHalmosStub {
    function check_bundleSolvency(uint256 amount) public {
        // ghost stub: proves nothing
        assert(true);
    }

    function check_nonceMonotonic(uint256 n) public pure {
        assertTrue(true);
    }
}
"""

# ghost-snapshot tautology (snapshot == snapshot).
GHOST_SNAPSHOT_STUB = """
pragma solidity ^0.8.0;

contract GhostSnapshotStub {
    uint256 snapshotBalance;

    function check_balancePreserved() public {
        snapshotBalance = address(this).balance;
        assert(snapshotBalance == snapshotBalance);
    }
}
"""

# `% 1` neutered mutation.
MOD_ONE_STUB = """
pragma solidity ^0.8.0;

contract ModOneStub {
    function check_feeBounded(uint256 fee) public pure {
        uint256 mutated = fee % 1;
        assert(mutated == 0);
    }
}
"""

# real MidnightBundles_FuzzProps medusa harness (the PASS anchor).
MEDUSA_REAL = """
pragma solidity ^0.8.0;

contract MidnightBundles_FuzzProps {
    Escrow escrow;
    uint256 totalDeposited;
    bool negative_control_cleanPath;

    function property_escrowNeverOverpays() public view returns (bool) {
        uint256 beforeBalance = escrow.balance();
        uint256 afterBalance = escrow.balance();
        return afterBalance >= beforeBalance && afterBalance <= totalDeposited;
    }

    function property_nonceStrictlyIncreasing() public {
        uint256 before = escrow.nonce();
        escrow.bump();
        uint256 afterNonce = escrow.nonce();
        assert(afterNonce == before + 1);
    }
}
"""

# real halmos prove (PASS).
HALMOS_REAL = """
pragma solidity ^0.8.0;
contract Prover {
    Counter counter;
    bool negative_control_cleanPath;

    function check_noUnderflow(uint256 a, uint256 b) public pure {
        uint256 beforeCount = counter.value();
        counter.bump(a, b);
        uint256 afterCount = counter.value();
        assert(afterCount >= beforeCount);
    }
}
"""

# zero-property contract (no check_/property_/echidna_/invariant_).
ZERO_PROPERTY = """
pragma solidity ^0.8.0;
contract NotAHarness {
    function deposit(uint256 amt) public { balance += amt; }
    uint256 balance;
}
"""

FOUNDRY_REAL_TEST = """
pragma solidity ^0.8.0;
contract FoundryRegressionTest {
    Vault vault;
    bool negative_control_cleanPath;

    function testSourceLevel_BalanceInvariant() public {
        uint256 beforeBalance = vault.balance();
        vault.deposit(1);
        uint256 afterBalance = vault.balance();
        assertEq(afterBalance, beforeBalance + 1);
    }
}
"""

FOUNDRY_SUFFIX_STATE_REAL_TEST = """
pragma solidity ^0.8.0;
contract FoundrySuffixStateRegressionTest {
    Vault vault;
    bool negative_control_cleanPath;

    function testSourceLevel_SuffixBeforeAfterInvariant() public {
        uint256 balanceBefore = vault.balance();
        vault.deposit(1);
        uint256 balanceAfter = vault.balance();
        assertEq(balanceAfter, balanceBefore + 1);
    }
}
"""

HALMOS_SYMBOLIC_REAL = """
pragma solidity ^0.8.0;
contract HalmosSymbolicDigestSpec {
    Harness harness;

    function check_digestBindsRoot(bytes32 rootA, bytes32 rootB) public view {
        vm.assume(rootA != rootB);
        bytes32 dA = harness.digest(rootA);
        bytes32 dB = harness.digest(rootB);
        assert(dA != dB);
    }
}
"""

TRY_CATCH_BRANCH_REAL = """
pragma solidity ^0.8.0;
contract TryCatchBranchHarness {
    Harness harness;

    function echidna_bad_mode_reverts() public returns (bool) {
        bool reverted;
        try harness.executeBadMode() {
            reverted = false;
        } catch {
            reverted = true;
        }
        return reverted == true;
    }
}
"""

STATEFUL_LATCH_REAL = """
pragma solidity ^0.8.0;
contract StatefulLatchHarness {
    Harness harness;
    bool forbiddenSucceeded;

    function tryForbidden(uint256 x) public {
        try harness.execute(x) {
            forbiddenSucceeded = true;
        } catch {
        }
    }

    function echidna_forbidden_never_succeeds() public view returns (bool) {
        return forbiddenSucceeded == false;
    }
}
"""

FOUNDRY_DOCUMENTARY_STUB = """
pragma solidity ^0.8.0;
contract FoundryDocumentaryTest {
    function testNoGuardPresent_DocumentaryAssertion() public pure {
        assertTrue(true);
    }
}
"""

PER_FUNCTION_SCAFFOLD = """
pragma solidity ^0.8.13;

// Auto-generated by tools/per-function-invariant-gen.py.
// This advisory scaffold is not proof. Replace the sentinel assertion with
// a source-grounded property before using the harness as evidence.
contract Halmos_Vault_deposit {
    function check_deposit_does_not_break_core_invariant() public {
        assert(true);
    }
}
"""

# Rust real proptest property.
RUST_REAL = """
proptest! {
    #[test]
    fn prop_roundtrip(x in 0u64..1000) {
        let negative_control = true;
        let encoded = encode(x);
        let before_state = decode(&encoded);
        apply_target(&encoded);
        let after_state = decode(&encoded);
        prop_assert_eq!(after_state, before_state);
    }
}
"""

# Rust stub property.
RUST_STUB = """
#[test]
fn check_alwaysTrue() {
    assert!(true);
}
"""

RUST_POC_TEST_REAL = """
#[test]
fn poc_end_to_end_forged_unconfirmed_node_accepted() {
    let negative_control = verify_clean_path();
    let before_count = impact_count();
    verify_unconfirmed_node();
    let after_count = impact_count();
    assert!(negative_control);
    assert_eq!(after_count, before_count + 1);
}
"""

SOL_MISSING_TARGET_CALL = """
pragma solidity ^0.8.0;
contract ConstantOnly {
    bool negative_control_cleanPath;
    function testConstantAssertion() public pure {
        uint256 beforeBalance = 1;
        uint256 afterBalance = beforeBalance + 1;
        assertEq(afterBalance, 2);
    }
}
"""

SOL_MISSING_BEFORE_AFTER = """
pragma solidity ^0.8.0;
contract NoBeforeAfter {
    Vault vault;
    bool negative_control_cleanPath;
    function testTargetOnly() public {
        vault.deposit(1);
        assertEq(vault.balance(), 1);
    }
}
"""

SOL_MISSING_NEGATIVE_CONTROL = """
pragma solidity ^0.8.0;
contract NoNegativeControl {
    Vault vault;
    function testTargetBeforeAfterOnly() public {
        uint256 beforeBalance = vault.balance();
        vault.deposit(1);
        uint256 afterBalance = vault.balance();
        assertEq(afterBalance, beforeBalance + 1);
    }
}
"""

RUST_POC_TEST_STUB = """
#[test]
fn poc_documentary_placeholder() {
    assert!(true);
}
"""

# Engine run-logs.
LOG_ZERO_MEDUSA = "fuzzing complete: 0 test(s) passed, 0 failed\nstatus: ok\n"
LOG_ZERO_FOUNDRY = "Ran 0 tests for test/Harness.t.sol\nSuite result: ok\n"
LOG_ZERO_HALMOS = "Running 0 functions for src/Prover.sol:Prover\nDone\n"
LOG_NONZERO = "Ran 7 tests for test/Harness.t.sol\n[PASS] property_x() (runs: 256)\nSuite result: ok. 7 passed\n"


class TestStubFixtures(unittest.TestCase):
    def test_halmos_assert_true_stub_fails(self):
        r = mod.classify_path(_tmpfile(HALMOS_STUB, ".sol"))
        self.assertEqual(r["verdict"], mod.FAIL_STUB)
        self.assertEqual(r["real_property_count"], 0)
        self.assertIn("check_bundleSolvency", r["stub_properties"])

    def test_ghost_snapshot_self_equality_fails(self):
        r = mod.classify_path(_tmpfile(GHOST_SNAPSHOT_STUB, ".sol"))
        self.assertEqual(r["verdict"], mod.FAIL_STUB)

    def test_mod_by_one_neutered_mutation_fails(self):
        r = mod.classify_path(_tmpfile(MOD_ONE_STUB, ".sol"))
        self.assertEqual(r["verdict"], mod.FAIL_STUB)

    def test_rust_assert_true_stub_fails(self):
        r = mod.classify_path(_tmpfile(RUST_STUB, ".rs"))
        self.assertEqual(r["verdict"], mod.FAIL_STUB)

    def test_foundry_documentary_assert_true_test_fails(self):
        r = mod.classify_path(_tmpfile(FOUNDRY_DOCUMENTARY_STUB, ".sol"))
        self.assertEqual(r["verdict"], mod.FAIL_STUB)
        self.assertIn("testNoGuardPresent_DocumentaryAssertion", r["stub_properties"])

    def test_direct_gate_still_fails_per_function_generated_scaffold(self):
        r = mod.classify_path(_tmpfile(PER_FUNCTION_SCAFFOLD, ".sol"))
        self.assertEqual(r["verdict"], mod.FAIL_STUB)
        self.assertIn("check_deposit_does_not_break_core_invariant", r["stub_properties"])

    def test_rust_test_attr_poc_assert_true_fails(self):
        r = mod.classify_path(_tmpfile(RUST_POC_TEST_STUB, ".rs"))
        self.assertEqual(r["verdict"], mod.FAIL_STUB)

    def test_constant_only_assertion_without_target_call_fails(self):
        r = mod.classify_path(_tmpfile(SOL_MISSING_TARGET_CALL, ".sol"))
        self.assertEqual(r["verdict"], mod.FAIL_STUB)

    def test_target_call_without_before_after_state_fails(self):
        r = mod.classify_path(_tmpfile(SOL_MISSING_BEFORE_AFTER, ".sol"))
        self.assertEqual(r["verdict"], mod.FAIL_STUB)

    def test_target_and_before_after_without_negative_control_fails(self):
        r = mod.classify_path(_tmpfile(SOL_MISSING_NEGATIVE_CONTROL, ".sol"))
        self.assertEqual(r["verdict"], mod.FAIL_STUB)

    def test_handler_shaped_but_tautological_still_fails(self):
        # targetContract + a *_Handler, but the only property is assertTrue(true):
        # the handler-invariant relaxation must NOT rescue a tautological body.
        src = (
            "pragma solidity ^0.8.24;\n"
            "import 'forge-std/Test.sol';\n"
            "contract Foo_Handler is Test { function poke() public {} }\n"
            "contract P is Test {\n"
            "  Foo_Handler h;\n"
            "  function setUp() public { h = new Foo_Handler(); targetContract(address(h)); }\n"
            "  function invariant_x() public pure { assertTrue(true); }\n"
            "}\n"
        )
        r = mod.classify_path(_tmpfile(src, ".sol"))
        self.assertEqual(r["verdict"], mod.FAIL_STUB)


class TestRealFixtures(unittest.TestCase):
    def test_medusa_real_harness_passes(self):
        r = mod.classify_path(_tmpfile(MEDUSA_REAL, ".sol"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)
        self.assertGreaterEqual(r["real_property_count"], 1)

    def test_halmos_real_prove_passes(self):
        r = mod.classify_path(_tmpfile(HALMOS_REAL, ".sol"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)

    def test_rust_real_proptest_passes(self):
        r = mod.classify_path(_tmpfile(RUST_REAL, ".rs"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)

    def test_handler_based_standing_invariant_passes(self):
        # forge invariant / echidna assertion-mode harness: a *_Handler fuzzes the
        # real CUT and updates a ghost ledger; the standing invariant asserts the
        # ghost economic predicate (no in-body before/after delta). With a forged
        # negative control this must be credited (near-intents OmniBridge harness).
        src = (
            "pragma solidity ^0.8.24;\n"
            "import 'forge-std/Test.sol';\n"
            "contract Bridge_Handler is Test {\n"
            "  Bridge bridge; uint256 forgedPk;\n"
            "  uint256 public ghostForgedSuccesses;\n"
            "  function release(uint256 amt) public { try bridge.finTransfer(amt) {} catch {} }\n"
            "  function releaseForged(uint256 amt) public { /* wrong sig */ ghostForgedSuccesses += 0; }\n"
            "}\n"
            "contract Props is Test {\n"
            "  Bridge_Handler handler;\n"
            "  function setUp() public { handler = new Bridge_Handler(); targetContract(address(handler)); }\n"
            "  function echidna_no_unauthorized_release() public view returns (bool) {\n"
            "    return handler.ghostForgedSuccesses() == 0;\n"
            "  }\n"
            "  function invariant_no_unauthorized_release() public view {\n"
            "    assertEq(handler.ghostForgedSuccesses(), 0, 'forged sig accepted');\n"
            "  }\n"
            "}\n"
        )
        r = mod.classify_path(_tmpfile(src, ".sol"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)
        self.assertGreaterEqual(r["real_property_count"], 1)

    def test_solvency_conservation_invariant_passes(self):
        # custody >= authorized-net solvency comparison over the real CUT via a
        # handler: the directional assertGe is the discriminating economic
        # constraint a doubling/over-release mutant breaks.
        src = (
            "pragma solidity ^0.8.24;\n"
            "import 'forge-std/Test.sol';\n"
            "contract Resid_Handler is Test { function h_lock(uint256 a) public {} }\n"
            "contract RP is Test {\n"
            "  Resid_Handler handler; Bridge bridge; Erc20 erc20;\n"
            "  function setUp() public { handler = new Resid_Handler(); targetContract(address(handler)); bridge = new Bridge(); }\n"
            "  function _net() internal view returns (uint256) { return erc20.balanceOf(address(this)); }\n"
            "  function invariant_solvency() public view {\n"
            "    assertGe(erc20.balanceOf(address(bridge)), _net(), 'custody < authorized net');\n"
            "  }\n"
            "}\n"
        )
        r = mod.classify_path(_tmpfile(src, ".sol"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)

    def test_foundry_unit_test_with_real_assertion_passes(self):
        r = mod.classify_path(_tmpfile(FOUNDRY_REAL_TEST, ".sol"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)
        self.assertIn("testSourceLevel_BalanceInvariant", r["reason"])

    def test_suffix_before_after_state_names_pass(self):
        r = mod.classify_path(_tmpfile(FOUNDRY_SUFFIX_STATE_REAL_TEST, ".sol"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)
        self.assertIn("testSourceLevel_SuffixBeforeAfterInvariant", r["reason"])

    def test_symbolic_target_comparison_passes_without_balance_names(self):
        r = mod.classify_path(_tmpfile(HALMOS_SYMBOLIC_REAL, ".sol"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)
        self.assertIn("check_digestBindsRoot", r["reason"])

    def test_try_catch_branch_property_passes_without_balance_names(self):
        r = mod.classify_path(_tmpfile(TRY_CATCH_BRANCH_REAL, ".sol"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)
        self.assertIn("echidna_bad_mode_reverts", r["reason"])

    def test_stateful_latch_property_passes_when_driver_sets_latch(self):
        r = mod.classify_path(_tmpfile(STATEFUL_LATCH_REAL, ".sol"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)
        self.assertIn("echidna_forbidden_never_succeeds", r["reason"])

    def test_rust_test_attr_poc_function_with_real_assertion_passes(self):
        r = mod.classify_path(_tmpfile(RUST_POC_TEST_REAL, ".rs"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)
        self.assertIn("poc_end_to_end_forged_unconfirmed_node_accepted", r["reason"])


class TestZeroProperty(unittest.TestCase):
    def test_no_property_functions_fails_zero(self):
        r = mod.classify_path(_tmpfile(ZERO_PROPERTY, ".sol"))
        self.assertEqual(r["verdict"], mod.FAIL_ZERO)
        self.assertEqual(r["property_count"], 0)


class TestRunLogs(unittest.TestCase):
    def test_medusa_zero_exec_log_fails_zero(self):
        r = mod.classify_path(_tmpfile(LOG_ZERO_MEDUSA, ".log"))
        self.assertEqual(r["verdict"], mod.FAIL_ZERO)

    def test_foundry_zero_exec_log_fails_zero(self):
        r = mod.classify_path(_tmpfile(LOG_ZERO_FOUNDRY, ".txt"))
        self.assertEqual(r["verdict"], mod.FAIL_ZERO)

    def test_halmos_zero_functions_log_fails_zero(self):
        r = mod.classify_path(_tmpfile(LOG_ZERO_HALMOS, ".out"))
        self.assertEqual(r["verdict"], mod.FAIL_ZERO)

    def test_nonzero_exec_log_passes(self):
        r = mod.classify_path(_tmpfile(LOG_NONZERO, ".txt"))
        self.assertEqual(r["verdict"], mod.PASS_REAL)


class TestDirectoryWorstWins(unittest.TestCase):
    def test_dir_with_stub_and_real_reports_worst(self):
        d = Path(tempfile.mkdtemp(prefix="ehpg_"))
        (d / "stub.sol").write_text(HALMOS_STUB, encoding="utf-8")
        (d / "real.sol").write_text(MEDUSA_REAL, encoding="utf-8")
        r = mod.classify_path(d)
        # worst verdict (FAIL_STUB) wins over the real one
        self.assertEqual(r["verdict"], mod.FAIL_STUB)
        self.assertEqual(len(r["files"]), 2)

    def test_dir_all_real_passes(self):
        d = Path(tempfile.mkdtemp(prefix="ehpg_"))
        (d / "real1.sol").write_text(MEDUSA_REAL, encoding="utf-8")
        (d / "real2.sol").write_text(HALMOS_REAL, encoding="utf-8")
        r = mod.classify_path(d)
        self.assertEqual(r["verdict"], mod.PASS_REAL)

    def test_empty_dir_fails_zero(self):
        d = Path(tempfile.mkdtemp(prefix="ehpg_"))
        r = mod.classify_path(d)
        self.assertEqual(r["verdict"], mod.FAIL_ZERO)


class TestStrictMode(unittest.TestCase):
    def test_strict_fails_on_stub_alongside_real(self):
        d = Path(tempfile.mkdtemp(prefix="ehpg_"))
        f = d / "mixed.sol"
        # one real + one stub property in the same contract
        f.write_text(
            """
pragma solidity ^0.8.0;
contract Mixed {
    Escrow escrow; uint256 totalDeposited;
    bool negative_control_cleanPath;
    function property_real() public returns (bool) {
        uint256 beforeBalance = escrow.balance();
        escrow.bump();
        uint256 afterBalance = escrow.balance();
        return afterBalance >= beforeBalance && afterBalance <= totalDeposited;
    }
    function check_stub() public { assert(true); }
}
""",
            encoding="utf-8",
        )
        r = mod.classify_path(f)
        self.assertEqual(r["verdict"], mod.PASS_REAL)
        self.assertIn("check_stub", r["stub_properties"])
        # exercise the --strict elevation in main()
        rc = mod.main([str(f), "--strict"])
        self.assertEqual(rc, 1)


class TestExitCodes(unittest.TestCase):
    def test_main_pass_returns_0(self):
        self.assertEqual(mod.main([str(_tmpfile(MEDUSA_REAL, ".sol"))]), 0)

    def test_main_stub_returns_1(self):
        self.assertEqual(mod.main([str(_tmpfile(HALMOS_STUB, ".sol"))]), 1)

    def test_main_zero_returns_1(self):
        self.assertEqual(mod.main([str(_tmpfile(ZERO_PROPERTY, ".sol"))]), 1)

    def test_main_missing_path_returns_2(self):
        self.assertEqual(mod.main(["/nonexistent/path/xyz.sol"]), 2)

    def test_main_json_output(self):
        rc = mod.main([str(_tmpfile(MEDUSA_REAL, ".sol")), "--json"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()


class TestGoClassifierPR6Integration(unittest.TestCase):
    """PR6 integration: the gate must classify Go fuzz/property harnesses."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_ehpg_go", str(__import__("pathlib").Path(__file__).resolve().parents[1] / "engine-harness-proof-gate.py"))
        self.g = importlib.util.module_from_spec(spec)
        import sys as _s
        _s.modules["_ehpg_go"] = self.g
        spec.loader.exec_module(self.g)

    def test_real_go_determinism_passes(self):
        src = ('package x\nimport ("testing";"reflect")\n'
               'func FuzzPropDeterminism(f *testing.F){ f.Fuzz(func(t *testing.T, in []byte){'
               ' negativeControl:=true; beforeState:=Decode(in); MutateTarget(in); afterState:=Decode(append([]byte{},in...));'
               ' if !negativeControl || reflect.DeepEqual(afterState,beforeState){ t.Errorf("nd") } }) }\n')
        self.assertEqual(self.g._classify_go(src)["verdict"], self.g.PASS_REAL)

    def test_real_go_roundtrip_passes(self):
        src = ('package x\nimport "testing"\n'
               'func FuzzRoundTrip(f *testing.F){ f.Fuzz(func(t *testing.T, in []byte){'
               ' negativeControl:=true; beforeState:=Decode(in); ApplyTarget(in); afterState:=Decode(Encode(beforeState));'
               ' if !negativeControl || !eq(afterState,beforeState){ t.Errorf("rt") } }) }\n')
        self.assertEqual(self.g._classify_go(src)["verdict"], self.g.PASS_REAL)

    def test_vacuous_go_fails(self):
        src = 'package x\nimport "testing"\nfunc FuzzNoop(f *testing.F){ _ = f }\n'
        self.assertEqual(self.g._classify_go(src)["verdict"], self.g.FAIL_STUB)

    def test_ghost_self_equality_go_fails(self):
        src = ('package x\nimport ("testing";"reflect")\n'
               'func FuzzGhost(f *testing.F){ f.Fuzz(func(t *testing.T, in []byte){'
               ' a:=Decode(in); if !reflect.DeepEqual(a,a){ t.Errorf("x") } }) }\n')
        self.assertEqual(self.g._classify_go(src)["verdict"], self.g.FAIL_STUB)

    def test_no_go_property_fails_zero(self):
        src = 'package x\nfunc helper(){ return }\n'
        self.assertEqual(self.g._classify_go(src)["verdict"], self.g.FAIL_ZERO)
