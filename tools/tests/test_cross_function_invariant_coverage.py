#!/usr/bin/env python3
"""Unit tests for tools/cross-function-invariant-coverage.py.

Covers:
  - requirement enumeration: L30 sibling pairs + multi-function state-machine
    sequences (generic, language-aware: Solidity + Rust + Go)
  - the anti-stub / mutation-verified coverage check (a referencing test with NO
    mutation kill = uncovered; a kill = covered)
  - verdict vocabulary (pass-cross-function-covered / pass-no-requirements /
    pass-no-source / fail-cross-function-uncovered / ok-rebuttal / error)
  - the reusable check(ws) entrypoint + report write
  - env extensibility hooks (naming pairs, sequence threshold)
  - ZERO workspace hardcoding (works on an arbitrary tmp dir)
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "cross-function-invariant-coverage.py"


def _load():
    spec = importlib.util.spec_from_file_location("xfi_cov", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so dataclass field() introspection (Python 3.14) can
    # resolve the module dict for the @dataclass default_factory fields.
    sys.modules["xfi_cov"] = mod
    spec.loader.exec_module(mod)
    return mod


xfi = _load()


class _WS:
    """Scratch workspace builder."""

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "src").mkdir()
        (self.dir / ".auditooor").mkdir()

    def src(self, name, body):
        p = self.dir / "src" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p

    def test(self, name, body):
        p = self.dir / "test" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p

    def mutation(self, records):
        (self.dir / ".auditooor" / "mutation_verify_coverage.json").write_text(
            json.dumps({"results": records}), encoding="utf-8"
        )

    def rebuttal(self, reason):
        (self.dir / ".auditooor"
         / "cross_function_invariant_coverage_rebuttal.txt").write_text(
            f"xfi-rebuttal: {reason}\n", encoding="utf-8"
        )


_VAULT_SOL = """contract Vault {
  mapping(address=>uint) bal;
  uint totalAssets;
  function deposit(uint amt) external { bal[msg.sender] += amt; totalAssets = totalAssets + amt; }
  function withdraw(uint amt) external { require(bal[msg.sender]>=amt); bal[msg.sender] -= amt; totalAssets = totalAssets - amt; }
  function accrue() external { totalAssets = totalAssets + 1; }
}"""


class EnumerationTest(unittest.TestCase):
    def test_sibling_pair_requirement_detected(self):
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        self.assertIn("deposit|withdraw", labels, res)

    def test_state_machine_requirement_detected(self):
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        res = xfi.evaluate(ws.dir)
        sm = [r for r in res["requirements"] if r["kind"] == "state-machine"]
        self.assertTrue(any(r["label"] == "state:totalAssets" for r in sm), res)
        for r in sm:
            if r["label"] == "state:totalAssets":
                names = sorted(f["name"] for f in r["functions"])
                self.assertEqual(names, ["accrue", "deposit", "withdraw"])

    def test_no_requirements_when_no_pairs_or_sequences(self):
        ws = _WS()
        # a single isolated function, no sibling pair, no shared state field
        ws.src("Solo.sol", "contract S { function ping() external { uint x = 1; } }")
        res = xfi.evaluate(ws.dir)
        self.assertEqual(res["verdict"], "pass-no-requirements", res)

    def test_no_source(self):
        ws = _WS()
        # no source files at all (empty src)
        res = xfi.evaluate(ws.dir)
        self.assertEqual(res["verdict"], "pass-no-source", res)

    def test_rust_state_machine(self):
        ws = _WS()
        ws.src("pallet.rs", """
impl Pallet {
  fn open(o: Origin) { self.total = self.total + 1; }
  fn fund(o: Origin) { self.total = self.total + 2; }
  fn close(o: Origin) { self.total = self.total - 1; }
}
""")
        res = xfi.evaluate(ws.dir)
        sm = [r for r in res["requirements"] if r["kind"] == "state-machine"]
        self.assertTrue(any("total" in r["label"] for r in sm), res)

    def test_go_sibling_pair(self):
        ws = _WS()
        ws.src("keeper.go", """
package keeper
func (k Keeper) MintTokens(ctx Context) { k.SetSupply(ctx, 1) }
func (k Keeper) BurnTokens(ctx Context) { k.SetSupply(ctx, 0) }
""")
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        self.assertIn("mint|burn", labels, res)

    def test_oos_vendored_and_interchaintest_excluded_from_requirements(self):
        # A vendored @openzeppelin copy (report-to-vendor OOS) and the Cosmos
        # ``interchaintest`` integration-test harness (test infra) must NOT seed
        # cross-function requirements - the gate would otherwise demand an
        # in-scope mutation test for explicitly out-of-scope code (false-red).
        ws = _WS()
        ws.src("peggo/solidity/contracts/@openzeppelin/contracts/ERC20.sol",
               "contract ERC20 { uint supply;\n"
               "  function mint(uint a) external { supply = supply + a; }\n"
               "  function burn(uint a) external { supply = supply - a; } }")
        ws.src("interchaintest/helpers/bank.go",
               "package helpers\n"
               "func Deposit(ctx Context) { SetBal(ctx, 1) }\n"
               "func Withdraw(ctx Context) { SetBal(ctx, 0) }\n")
        # in-scope module sibling pair - MUST still seed the requirement
        ws.src("modules/exchange/keeper.go",
               "package keeper\n"
               "func (k Keeper) Deposit(ctx Context) { k.SetBal(ctx, 1) }\n"
               "func (k Keeper) Withdraw(ctx Context) { k.SetBal(ctx, 0) }\n")
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        # the in-scope deposit|withdraw survives...
        self.assertIn("deposit|withdraw", labels, res)
        # ...mint|burn existed ONLY in the vendored OZ file, so it is gone...
        self.assertNotIn("mint|burn", labels, res)
        # ...and no requirement references an OOS file.
        for r in res["requirements"]:
            for f in r.get("functions", []):
                fp = str(f.get("file", ""))
                self.assertNotIn("@openzeppelin", fp, r)
                self.assertNotIn("interchaintest", fp, r)

    def test_substring_token_does_not_create_add_requirement(self):
        ws = _WS()
        ws.src("Padded.rs", """
fn padded_size() -> usize { 0 }
fn memory_address() -> usize { 1 }
fn remove_comments(input: &str) -> String { input.to_string() }
""")
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        self.assertFalse(any(l.startswith("add|remove") for l in labels), res)

    def test_sibling_pair_requires_same_module(self):
        ws = _WS()
        ws.src("crates/a/src/claim.rs", "fn claim_leaf() {}")
        ws.src("crates/b/src/finalize.rs", "fn finalize_round() {}")
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        self.assertFalse(any(l.startswith("claim|finalize") for l in labels), res)

    def test_broad_pair_requires_shared_noun(self):
        ws = _WS()
        ws.src("crates/parser/src/program.rs", """
fn add_constant() {}
fn remove_comments() {}
""")
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        self.assertFalse(any(l.startswith("add|remove") for l in labels), res)

    def test_rust_std_mem_take_not_state_write(self):
        ws = _WS()
        ws.src("pallet.rs", """
fn a() { let _x = std::mem::take(&mut foo); }
fn b() { let _x = std::mem::take(&mut bar); }
fn c() { let _x = std::mem::take(&mut baz); }
""")
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        self.assertNotIn("state:mem", labels, res)


class SharedScopeExclusionWiringTest(unittest.TestCase):
    """Guard for the migration of the ad-hoc interchaintest/@openzeppelin
    _SKIP_DIRS literals to the shared tools/lib/scope_exclusion helper.

    Proves the two load-bearing properties the wiring must preserve:
      (1) an OOS (vendored) surface is EXCLUDED from requirements AND from the
          test-ref scan - covering the migrated literals (interchaintest,
          @openzeppelin) AND the wider vendored universe the shared helper now
          owns (cosmos-sdk, solmate) so a regression that drops the helper would
          be caught, and
      (2) an in-scope protocol surface is STILL present (no false-green / no
          over-suppression - the #1 sin).
    """

    def test_shared_helper_loaded(self):
        # The by-path loader must resolve the shared helper; if it silently
        # returns None the vendored prune degrades to the _SKIP_DIRS pass alone.
        self.assertIsNotNone(
            xfi._SCOPE_EXCL,
            "scope_exclusion helper failed to load by path; vendored OOS prune "
            "would degrade to _SKIP_DIRS only",
        )
        # the migrated literals must classify as vendored via the shared helper
        self.assertTrue(xfi._is_vendored_oos("interchaintest/helpers/bank.go"))
        self.assertTrue(
            xfi._is_vendored_oos("contracts/@openzeppelin/contracts/ERC20.sol"))
        # an in-scope protocol path must NOT be flagged (fail-safe direction)
        self.assertFalse(xfi._is_vendored_oos("modules/exchange/keeper.go"))
        self.assertFalse(xfi._is_vendored_oos("crates/pallet-foo/src/lib.rs"))

    def test_oos_vendored_surface_excluded_inscope_present_via_shared_helper(self):
        ws = _WS()
        # OOS-1: the migrated @openzeppelin literal (vendored OZ copy).
        ws.src("contracts/@openzeppelin/contracts/token/ERC20.sol",
               "contract ERC20 { uint supply;\n"
               "  function mint(uint a) external { supply = supply + a; }\n"
               "  function burn(uint a) external { supply = supply - a; } }")
        # OOS-2: the migrated interchaintest literal (Cosmos integration harness).
        ws.src("interchaintest/helpers/bank.go",
               "package helpers\n"
               "func StakeFoo(ctx Context) { SetBal(ctx, 1) }\n"
               "func UnstakeFoo(ctx Context) { SetBal(ctx, 0) }\n")
        # OOS-3: a vendored dep the OLD literal set did NOT have but the shared
        # helper DOES (proves the wiring is the shared table, not the 2 literals).
        ws.src("vendor/github.com/cosmos/cosmos-sdk/x/bank/keeper.go",
               "package keeper\n"
               "func (k Keeper) Lock(ctx Context) { k.SetBal(ctx, 1) }\n"
               "func (k Keeper) Unlock(ctx Context) { k.SetBal(ctx, 0) }\n")
        # IN-SCOPE: a real protocol module sibling pair - MUST survive.
        ws.src("modules/exchange/keeper.go",
               "package keeper\n"
               "func (k Keeper) Stake(ctx Context) { k.SetBal(ctx, 1) }\n"
               "func (k Keeper) Unstake(ctx Context) { k.SetBal(ctx, 0) }\n")
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        # the in-scope stake|unstake survives ...
        self.assertIn("stake|unstake", labels, res)
        # ... mint|burn existed ONLY in the vendored OZ file, so it is gone ...
        self.assertNotIn("mint|burn", labels, res)
        # ... and NO requirement references any vendored OOS file.
        for r in res["requirements"]:
            for f in r.get("functions", []):
                fp = str(f.get("file", ""))
                self.assertNotIn("@openzeppelin", fp, r)
                self.assertNotIn("interchaintest", fp, r)
                self.assertNotIn("cosmos-sdk", fp, r)
                self.assertNotIn("/vendor/", "/" + fp, r)

    def test_vendored_test_harness_not_mined_for_refs(self):
        # A test/harness file living UNDER a vendored dep tree is OOS test infra:
        # it must NOT be scanned for in-scope cross-function references (the scan
        # uses is_vendored so an in-scope test/poc IS still found - see the
        # existing test_test_outside_src_root_is_found).
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        # vendored harness that references the arms but is OOS -> must be ignored
        vend = ws.dir / "interchaintest" / "Roundtrip.t.sol"
        vend.parent.mkdir(parents=True, exist_ok=True)
        vend.write_text(
            "contract RT { function t() public { v.deposit(1); v.withdraw(1); } }",
            encoding="utf-8")
        refs = xfi._scan_test_function_refs(ws.dir)
        files = {r["file"] for r in refs}
        self.assertFalse(any("interchaintest" in f for f in files),
                         f"vendored harness leaked into test-ref scan: {files}")


class CoverageCheckTest(unittest.TestCase):
    def test_referencing_test_without_mutation_is_uncovered(self):
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        ws.test("RT.t.sol", "contract RT { function t() public { v.deposit(1); v.withdraw(1); } }")
        # NO mutation record on disk
        res = xfi.evaluate(ws.dir)
        self.assertEqual(res["verdict"], "fail-cross-function-uncovered", res)

    def test_mutation_verified_sibling_pair_is_covered(self):
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        ws.test("RT.t.sol",
                "contract RT { function t() public { v.deposit(1); v.withdraw(1); v.accrue(); } }")
        ws.mutation([
            {"function": "Vault.sol::deposit", "verdict": "non-vacuous", "killed_count": 2},
            {"function": "Vault.sol::accrue", "verdict": "non-vacuous", "killed_count": 1},
        ])
        res = xfi.evaluate(ws.dir)
        self.assertEqual(res["verdict"], "pass-cross-function-covered", res)
        self.assertEqual(res["uncovered_count"], 0, res)

    def test_vacuous_mutation_is_uncovered(self):
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        ws.test("RT.t.sol", "contract RT { function t() public { v.deposit(1); v.withdraw(1); } }")
        # mutation backend ran but every harness was vacuous -> no kill -> uncovered
        ws.mutation([
            {"function": "Vault.sol::deposit", "verdict": "vacuous"},
            {"function": "Vault.sol::withdraw", "verdict": "vacuous"},
            {"function": "Vault.sol::accrue", "verdict": "vacuous"},
        ])
        res = xfi.evaluate(ws.dir)
        self.assertEqual(res["verdict"], "fail-cross-function-uncovered", res)

    def test_test_outside_src_root_is_found(self):
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        # test lives in a sibling test/ dir OUTSIDE src/
        ws.test("Roundtrip.t.sol",
                "contract RT { function t() public { v.deposit(1); v.withdraw(1); v.accrue(); } }")
        ws.mutation([{"function": "Vault.sol::deposit", "verdict": "killed"}])
        res = xfi.evaluate(ws.dir)
        sib = [r for r in res["covered"] if r["label"] == "deposit|withdraw"]
        self.assertTrue(sib, res)

    def test_no_referencing_test_is_uncovered(self):
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        # mutation exists but no test references both arms
        ws.mutation([{"function": "Vault.sol::deposit", "verdict": "killed"}])
        res = xfi.evaluate(ws.dir)
        self.assertEqual(res["verdict"], "fail-cross-function-uncovered", res)
        sib = [r for r in res["uncovered"] if r["label"] == "deposit|withdraw"]
        self.assertTrue(sib, res)
        self.assertIn("no test unit references", sib[0]["evidence"]["reason"])

    def test_killed_runtime_trace_can_cover_internal_cross_function_requirement(self):
        ws = _WS()
        ws.src("lib.rs", """
impl P {
  fn first(&mut self) { self.sum += 1; }
  fn second(&mut self) { self.sum += 2; }
  fn third(&mut self) { self.sum += 3; }
}
""")
        sidecar = ws.dir / ".auditooor" / "cross-function-coverage"
        sidecar.mkdir(parents=True)
        (sidecar / "mutation_first.json").write_text(json.dumps({
            "function": "first",
            "verdict": "non-vacuous",
            "baseline": {"output_tail": "trace first second"},
            "mutant_results": [{"killed": True, "output_tail": "trace first second"}],
        }), encoding="utf-8")
        res = xfi.evaluate(ws.dir)
        self.assertEqual(res["verdict"], "pass-cross-function-covered", res)

    def test_fork_etch_record_covered_by_requirement_label(self):
        """A fork-etch cross-function record is keyed by the EXACT requirement
        label and stores the FACET name in `function` (not the arm names). The
        killed_fns/killed_tests joins can never match it, so the gate must credit
        the requirement via a direct requirement-label join. Regression
        2026-06-14: the entire fork-etch mechanism (the canonical cross-function
        mutation-verify producer) was invisible to this gate - a genuine kill
        scored 0/N covered."""
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        # NO referencing test; record's `function` is the facet, requirement is
        # the exact enumerated label, and it is a non-vacuous mutation_verified
        # kill.
        ws.mutation([{
            "function": "Vault",            # facet name, NOT an arm
            "requirement": "deposit|withdraw",
            "verdict": "killed",
            "mutation_verified": True,
            "mode": "fork-etch",
        }])
        res = xfi.evaluate(ws.dir)
        # assert on the SPECIFIC requirement row (the source also yields a
        # state:totalAssets requirement this single record does not cover, so the
        # overall verdict is not the contract under test here).
        sib = [r for r in res["covered"] if r["label"] == "deposit|withdraw"]
        self.assertTrue(sib, f"deposit|withdraw must be covered by label join: {res}")
        self.assertIn("requirement-label match", sib[0]["evidence"]["reason"])

    def test_label_match_requires_mutation_verified_true(self):
        """False-green guard: a record carrying the requirement label but NOT
        flagged mutation_verified=True must NOT credit the requirement via the
        label join (a bare verdict token can never silently pass)."""
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        ws.mutation([{
            "function": "Vault",
            "requirement": "deposit|withdraw",
            "verdict": "killed",
            "mutation_verified": False,   # <- not non-vacuous
            "mode": "fork-etch",
        }])
        res = xfi.evaluate(ws.dir)
        self.assertEqual(res["verdict"], "fail-cross-function-uncovered", res)


class RebuttalTest(unittest.TestCase):
    def test_rebuttal_flips_fail_to_ok(self):
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        ws.rebuttal("single-function target; cross-function proven out of band in audit/report.md")
        res = xfi.evaluate(ws.dir)
        self.assertEqual(res["verdict"], "ok-rebuttal", res)

    def test_oversized_rebuttal_ignored(self):
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        ws.rebuttal("x" * 250)
        res = xfi.evaluate(ws.dir)
        self.assertEqual(res["verdict"], "fail-cross-function-uncovered", res)


class EntrypointTest(unittest.TestCase):
    def test_check_writes_report_and_returns_dict(self):
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        res = xfi.check(ws.dir)
        self.assertIn(res["verdict"], {
            "fail-cross-function-uncovered", "pass-cross-function-covered"})
        report = ws.dir / ".auditooor" / "cross_function_invariant_coverage.json"
        self.assertTrue(report.is_file(), "report not written")
        self.assertIn("report_path", res)
        loaded = json.loads(report.read_text())
        self.assertEqual(loaded["schema"], xfi.SCHEMA)

    def test_check_error_on_bad_workspace(self):
        res = xfi.check("/nonexistent/path/xyz123")
        self.assertEqual(res["verdict"], "error", res)

    def test_schema_string_present(self):
        self.assertEqual(xfi.SCHEMA, "auditooor.cross_function_invariant_coverage.v1")


class EnvHookTest(unittest.TestCase):
    def test_env_naming_pair_extension(self):
        ws = _WS()
        ws.src("Custom.sol",
               "contract C { function settle() external { } function rollback() external { } }")
        os.environ["AUDITOOOR_XFI_NAMING_PAIRS"] = "settle|rollback|settle/rollback must be atomic"
        try:
            res = xfi.evaluate(ws.dir)
            labels = {r["label"] for r in res["requirements"]}
            self.assertIn("settle|rollback", labels, res)
        finally:
            del os.environ["AUDITOOOR_XFI_NAMING_PAIRS"]

    def test_env_sequence_threshold_floor(self):
        # threshold can be raised but never below 3
        os.environ["AUDITOOOR_XFI_SEQUENCE_THRESHOLD"] = "2"
        try:
            self.assertGreaterEqual(xfi._sequence_threshold(), 3)
        finally:
            del os.environ["AUDITOOOR_XFI_SEQUENCE_THRESHOLD"]

    def test_env_sequence_threshold_raise(self):
        os.environ["AUDITOOOR_XFI_SEQUENCE_THRESHOLD"] = "5"
        try:
            self.assertEqual(xfi._sequence_threshold(), 5)
        finally:
            del os.environ["AUDITOOOR_XFI_SEQUENCE_THRESHOLD"]


class WorklistTest(unittest.TestCase):
    def test_worklist_lists_uncovered(self):
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        res = xfi.check(ws.dir)
        work = xfi._emit_worklist(res)
        self.assertTrue(work, "worklist empty despite uncovered requirements")
        self.assertTrue(all("functions" in w and "invariant_hint" in w for w in work))




class LocalVarFalsePositiveTest(unittest.TestCase):
    """Bug: state-write regex fired on local variable declarations such as
    `uint256 name = IWell(well).name();`, fabricating bogus state-machine
    requirements for tokens like name/symbol/msb/shift/exponent/downcasted.
    Fix: _is_local_var_decl() + extended _FIELD_STOPWORDS (wave3).

    Each test:
    - builds a fixture where a bogus token would previously generate a
      state-machine requirement,
    - asserts the requirement is NOT emitted (false-positive eliminated), and
    - asserts a legitimate real-storage requirement IS still emitted when
      present (fix does not over-suppress).
    """

    def test_solidity_local_var_name_token_not_state_field(self):
        """uint256 name = IWell(well).name() is a local declaration; 3 such
        functions must NOT produce a state:name requirement."""
        ws = _WS()
        ws.src("Well.sol", """
contract Well {
    function getName() external view returns (string memory) {
        string memory name = IERC20(token).name();
        return name;
    }
    function getSymbol() external view returns (string memory) {
        string memory symbol = IERC20(token).symbol();
        return symbol;
    }
    function encodeInitCall() external view returns (bytes memory) {
        string memory name = IERC20(token0).name();
        string memory symbol = IERC20(token0).symbol();
        return abi.encode(name, symbol);
    }
}
""")
        res = xfi.evaluate(ws.dir)
        sm_labels = {r["label"] for r in res["requirements"] if r["kind"] == "state-machine"}
        self.assertNotIn("state:name", sm_labels,
            f"state:name is a local-var false positive; must not appear. got: {sm_labels}")
        self.assertNotIn("state:symbol", sm_labels,
            f"state:symbol is a local-var false positive; must not appear. got: {sm_labels}")

    def test_solidity_typed_local_math_temps_not_state_fields(self):
        """uint256 msb / shift are local math temporaries appearing in the
        same library across 3+ functions; they must NOT produce state-machine
        requirements."""
        ws = _WS()
        ws.src("Math.sol", """
library ABDKMath {
    function fromUInt(uint256 x) internal pure returns (int128) {
        uint256 msb = 0;
        msb = x >> 128;
        return int128(x << (127 - msb));
    }
    function fromUIntToLog2(uint256 x) internal pure returns (int128) {
        uint256 msb = 127;
        uint256 shift = 0;
        shift = msb >> 1;
        return int128(msb);
    }
    function add(int128 x, int128 y) internal pure returns (int128) {
        uint256 msb = uint256(int256(x));
        int256 result = int256(x) + y;
        return int128(result);
    }
}
""")
        res = xfi.evaluate(ws.dir)
        sm_labels = {r["label"] for r in res["requirements"] if r["kind"] == "state-machine"}
        self.assertNotIn("state:msb", sm_labels,
            f"state:msb is a local math temp; must not appear. got: {sm_labels}")
        self.assertNotIn("state:shift", sm_labels,
            f"state:shift is a local math temp; must not appear. got: {sm_labels}")

    def test_solidity_storage_struct_local_not_state_field(self):
        """AppStorage storage ds = LibAppStorage.diamondStorage() is a
        storage-pointer local, NOT a persistent field named 'ds'."""
        ws = _WS()
        ws.src("Diamond.sol", """
contract Diamond {
    function facets() external view returns (Facet[] memory) {
        AppStorage storage ds = LibAppStorage.diamondStorage();
        return ds.facets;
    }
    function facetAddresses() external view returns (address[] memory) {
        AppStorage storage ds = LibAppStorage.diamondStorage();
        return ds.facetAddresses;
    }
    function facetAddress(bytes4 sel) external view returns (address) {
        AppStorage storage ds = LibAppStorage.diamondStorage();
        return ds.facetToAddress[sel];
    }
}
""")
        res = xfi.evaluate(ws.dir)
        sm_labels = {r["label"] for r in res["requirements"] if r["kind"] == "state-machine"}
        self.assertNotIn("state:ds", sm_labels,
            f"state:ds is a local storage-pointer alias; must not appear. got: {sm_labels}")

    def test_solidity_mapping_type_param_not_state_field(self):
        """mapping(uint256 => mapping(address => Balance)) - the type params
        uint256 and address inside the mapping declaration must NOT produce
        state-machine requirements."""
        ws = _WS()
        ws.src("Internalizer.sol", """
contract Internalizer {
    mapping(uint256 => mapping(address => uint256)) internal _balances;

    function beansPerFertilizer() external view returns (uint256) {
        uint256 id = _balances[1][msg.sender];
        return id;
    }
    function getEndBpf() external view returns (uint256) {
        uint256 id = _balances[2][msg.sender];
        return id;
    }
    function remainingRecapitalization() external view returns (uint256) {
        uint256 id = _balances[3][msg.sender];
        return id;
    }
}
""")
        res = xfi.evaluate(ws.dir)
        sm_labels = {r["label"] for r in res["requirements"] if r["kind"] == "state-machine"}
        self.assertNotIn("state:uint256", sm_labels,
            f"state:uint256 is a mapping type parameter; must not appear. got: {sm_labels}")

    def test_solidity_downcasted_local_not_state_field(self):
        """uint256 downcasted = ... appears across SafeCast helpers as a
        local; must NOT produce a state-machine requirement."""
        ws = _WS()
        ws.src("SafeCast.sol", """
library SafeCast {
    function toInt248(int256 value) internal pure returns (int248) {
        int248 downcasted = int248(value);
        require(downcasted == value);
        return downcasted;
    }
    function toInt240(int256 value) internal pure returns (int240) {
        int240 downcasted = int240(value);
        require(downcasted == value);
        return downcasted;
    }
    function toInt232(int256 value) internal pure returns (int232) {
        int232 downcasted = int232(value);
        require(downcasted == value);
        return downcasted;
    }
}
""")
        res = xfi.evaluate(ws.dir)
        sm_labels = {r["label"] for r in res["requirements"] if r["kind"] == "state-machine"}
        self.assertNotIn("state:downcasted", sm_labels,
            f"state:downcasted is a local SafeCast temp; must not appear. got: {sm_labels}")

    def test_real_storage_write_still_detected_after_fix(self):
        """Ensure the fix does NOT suppress legitimate storage state writes.
        deposit/withdraw round-trip AND state:totalAssets must still appear."""
        ws = _WS()
        ws.src("Vault.sol", _VAULT_SOL)
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        self.assertIn("deposit|withdraw", labels,
            "deposit/withdraw sibling pair must still be detected after stopword fix")
        sm_labels = {r["label"] for r in res["requirements"] if r["kind"] == "state-machine"}
        self.assertTrue(any("totalAssets" in lab for lab in sm_labels),
            f"state:totalAssets must still be detected as a genuine state write. got: {sm_labels}")

    def test_mixed_local_and_storage_writes_only_storage_counted(self):
        """A function body with BOTH local declarations and real storage writes
        must only count the storage write, not the local var name."""
        ws = _WS()
        ws.src("Mixed.sol", """
contract Mixed {
    uint256 public totalValue;
    function update(address token) external {
        string memory name = IERC20(token).name();
        uint256 exponent = 18;
        totalValue = totalValue + 1;
    }
    function reset(address token) external {
        string memory name = IERC20(token).name();
        totalValue = 0;
    }
    function increment(uint256 amt) external {
        uint256 msb = amt >> 1;
        totalValue = totalValue + msb;
    }
}
""")
        res = xfi.evaluate(ws.dir)
        sm_labels = {r["label"] for r in res["requirements"] if r["kind"] == "state-machine"}
        self.assertNotIn("state:name", sm_labels,
            "state:name is a local; must not appear even when mixed with real storage writes")
        self.assertNotIn("state:exponent", sm_labels,
            "state:exponent is a local math temp; must not appear")
        self.assertNotIn("state:msb", sm_labels,
            "state:msb is a local math temp; must not appear")
        self.assertTrue(any("totalValue" in lab for lab in sm_labels),
            f"state:totalValue must still be detected as genuine. got: {sm_labels}")

    def test_rust_let_decl_not_state_field(self):
        """In Rust, `let foo = ...` / `let mut foo = ...` is a local var;
        must not produce a state-machine requirement on 'foo'."""
        ws = _WS()
        ws.src("math.rs", """
impl Converter {
    fn to_u64(x: i128) -> u64 {
        let exponent = x as u64;
        exponent
    }
    fn to_i64(x: u128) -> i64 {
        let exponent = x as i64;
        exponent
    }
    fn to_u32(x: u64) -> u32 {
        let exponent = x as u32;
        exponent
    }
}
""")
        res = xfi.evaluate(ws.dir)
        sm_labels = {r["label"] for r in res["requirements"] if r["kind"] == "state-machine"}
        self.assertNotIn("state:exponent", sm_labels,
            "state:exponent is a local Rust let-binding; must not appear")


class GoStateMachineOverDetectionTest(unittest.TestCase):
    """Regression for the axelar-dlt Go state-machine over-detection (confirmed
    2026-07-12): the Go writer scan flagged phantom `state:X` cross-function
    requirements from (a) read-only `GetX`/`getX` getters that only append into
    a local/named-return slice and (b) function-local `:=` short-var-decls
    later reassigned with a bare `=`/`+=`. Neither is a mutated KVStore/keeper
    field. A genuine 2-writer... actually >=3-writer (the tool's sequence
    threshold) coupled `k.SetFoo(...)` field must still be detected."""

    _READONLY_GETTER_FIXTURE = """
package keeper

// getTransfers is a read-only iterator: builds and returns a LOCAL
// (named-return) slice, never mutates keeper state.
func (k Keeper) getTransfers(ctx Context) (transfers []Transfer) {
	iter := k.getStore(ctx).Iterator(transferPrefix)
	for iter.Valid() {
		transfers = append(transfers, iter.Value())
		iter.Next()
	}
	return transfers
}

// GetTransfersForChain: same shape, capitalized Get-getter.
func (k Keeper) GetTransfersForChain(ctx Context, chain string) (transfers []Transfer) {
	iter := k.getStore(ctx).Iterator(transferPrefix)
	for iter.Valid() {
		transfers = append(transfers, iter.Value())
		iter.Next()
	}
	return transfers
}

// GetTransfersForChainPaginated: third getter, same local-slice pattern.
func (k Keeper) GetTransfersForChainPaginated(ctx Context, chain string) (transfers []Transfer) {
	var transfers []Transfer
	transfers = append(transfers, Transfer{})
	return transfers
}
"""

    _LOCAL_SHORTDECL_FIXTURE = """
package types

// ABIInflationGuard: `total` is a function-local declared via `:=` and later
// reassigned with `+=` - not a persistent field.
func ABIInflationGuard(payload []byte, maxCost int) error {
	total, index, virtualArgs := 0, 0, 0
	total += index + virtualArgs
	if total > maxCost {
		return errTooLarge
	}
	return nil
}

func walkTuple(payload []byte, maxCost int) error {
	total, index, virtualArgs := 0, 0, 0
	total += index + virtualArgs
	return nil
}

func walkElements(payload []byte, maxCost int) error {
	total, index, virtualArgs := 0, 0, 0
	total += index + virtualArgs
	return nil
}
"""

    _REAL_KEEPER_FIXTURE = """
package keeper

// A genuine coupled mutable field: 3 distinct functions call k.SetParams,
// a domain-specific keeper setter (NOT a getter, NOT a local, NOT a generic
// math/big or raw-KVStore accessor) - this MUST still be detected.
func (k Keeper) InitGenesis(ctx Context, params Params) {
	k.SetParams(ctx, params)
}

func Migrate7to8(k Keeper) func(ctx Context) error {
	return func(ctx Context) error {
		params := k.GetParams(ctx)
		k.SetParams(ctx, params)
		return nil
	}
}

func (s msgServer) UpdateParams(ctx Context, params Params) error {
	s.SetParams(ctx, params)
	return nil
}
"""

    def test_readonly_go_getter_not_state_machine(self):
        ws = _WS()
        ws.src("transfer.go", self._READONLY_GETTER_FIXTURE)
        res = xfi.evaluate(ws.dir)
        sm_labels = {r["label"] for r in res["requirements"] if r["kind"] == "state-machine"}
        self.assertFalse(any(lab.startswith("state:transfers") for lab in sm_labels),
            f"state:transfers is a read-only getter's local slice; must not appear. got: {sm_labels}")

    def test_go_shortdecl_local_not_state_machine(self):
        ws = _WS()
        ws.src("abi_inflation_guard.go", self._LOCAL_SHORTDECL_FIXTURE)
        res = xfi.evaluate(ws.dir)
        sm_labels = {r["label"] for r in res["requirements"] if r["kind"] == "state-machine"}
        self.assertFalse(any(lab.startswith("state:total") for lab in sm_labels),
            f"state:total is a `:=` local later reassigned with `+=`; must not appear. got: {sm_labels}")

    def test_go_setraw_and_setuint64_not_state_machine(self):
        ws = _WS()
        ws.src("queuer.go", """
package utils

func (q *Queue) incrSize() {
	q.size++
	q.store.SetRaw(sizeKey, encode(q.size))
}

func (q *Queue) decrSize() {
	q.size--
	q.store.SetRaw(sizeKey, encode(q.size))
}

func (q *Queue) ImportState(state QueueState) {
	q.store.SetRaw(sizeKey, encode(0))
}
""")
        ws.src("command.go", """
package types

func createApproveContractCallParams(idx uint64) []byte {
	return pack(new(big.Int).SetUint64(idx))
}
func createApproveContractCallParamsGeneric(idx uint64) []byte {
	return pack(new(big.Int).SetUint64(idx))
}
func createApproveContractCallWithMintParams(idx uint64) []byte {
	return pack(new(big.Int).SetUint64(idx))
}
""")
        res = xfi.evaluate(ws.dir)
        sm_labels = {r["label"] for r in res["requirements"] if r["kind"] == "state-machine"}
        self.assertFalse(any(lab.startswith("state:Raw") for lab in sm_labels),
            f"state:Raw is the generic KVStore raw accessor, not a domain field. got: {sm_labels}")
        self.assertFalse(any(lab.startswith("state:Uint64") for lab in sm_labels),
            f"state:Uint64 is big.Int.SetUint64, not a keeper setter. got: {sm_labels}")

    def test_real_go_keeper_setter_still_detected(self):
        """The fix must NOT weaken detection of a genuine >=3-writer coupled
        KVStore/keeper field (k.SetParams called from InitGenesis, the
        Migrate7to8 closure, and UpdateParams)."""
        ws = _WS()
        ws.src("genesis.go", self._REAL_KEEPER_FIXTURE)
        res = xfi.evaluate(ws.dir)
        sm = [r for r in res["requirements"] if r["kind"] == "state-machine"]
        sm_labels = {r["label"] for r in sm}
        self.assertTrue(any(lab.startswith("state:Params") for lab in sm_labels),
            f"state:Params is a genuine 3-writer k.SetParams(...) field; must still be detected. got: {sm_labels}")
        for r in sm:
            if r["label"].startswith("state:Params"):
                names = sorted(f["name"] for f in r["functions"])
                self.assertEqual(names, ["InitGenesis", "Migrate7to8", "UpdateParams"])


# ---------------------------------------------------------------------------
# Guard tests for xfn-interface-skip fix
# ---------------------------------------------------------------------------

_INTERFACE_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVault {
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
    function balanceOf(address user) external view returns (uint256);
}
"""

_CONTRACT_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;
    uint256 public totalAssets;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalAssets += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        totalAssets -= amount;
    }
}
"""


class IsInterfaceLikeTest(unittest.TestCase):
    """Unit tests for the _is_interface_like predicate (xfn-interface-skip)."""

    def _p(self, path_str: str) -> Path:
        return Path(path_str)

    # interface-by-path-convention

    def test_interfaces_dir_detected(self):
        self.assertTrue(xfi._is_interface_like(self._p("src/interfaces/IVault.sol")))

    def test_interface_singular_dir_detected(self):
        self.assertTrue(xfi._is_interface_like(self._p("contracts/interface/IFoo.sol")))

    def test_interfaces_dir_case_insensitive(self):
        self.assertTrue(xfi._is_interface_like(self._p("src/Interfaces/IBar.sol")))

    # interface-by-I<Upper>-stem-convention

    def test_IUpper_stem_detected(self):
        self.assertTrue(xfi._is_interface_like(self._p("src/IVault.sol")))

    def test_IERC20_stem_detected(self):
        self.assertTrue(xfi._is_interface_like(self._p("tokens/IERC20.sol")))

    # NOT interface: regular contract files

    def test_regular_contract_not_interface(self):
        self.assertFalse(xfi._is_interface_like(self._p("src/Vault.sol")))

    def test_single_char_stem_not_interface(self):
        # stem must be at least 2 chars (I + Upper)
        self.assertFalse(xfi._is_interface_like(self._p("I.sol")))

    def test_I_lower_second_char_not_interface(self):
        # stem[1] must be uppercase
        self.assertFalse(xfi._is_interface_like(self._p("Ib.sol")))

    # only fires for .sol, not other languages

    def test_non_sol_interface_dir_not_flagged(self):
        self.assertFalse(xfi._is_interface_like(self._p("src/interfaces/traits.rs")))

    def test_non_sol_IUpper_stem_not_flagged(self):
        self.assertFalse(xfi._is_interface_like(self._p("IFoo.go")))


class IterSourceFilesInterfaceSkipTest(unittest.TestCase):
    """Integration tests: _iter_source_files skips interface-like files and
    yields real contract files (xfn-interface-skip guard)."""

    def _collect(self, root: Path, include_tests: bool = False) -> list:
        return [(p, lang, rel) for p, lang, rel, _is_test in
                xfi._iter_source_files(root, include_tests)]

    def test_interface_file_in_interfaces_dir_is_skipped(self):
        ws = _WS()
        iface = ws.dir / "src" / "interfaces" / "IVault.sol"
        iface.parent.mkdir(parents=True, exist_ok=True)
        iface.write_text(_INTERFACE_SOL, encoding="utf-8")

        results = self._collect(ws.dir)
        paths = [p for p, _lang, _rel in results]
        self.assertNotIn(iface, paths,
                         "interface file under /interfaces/ must be skipped")

    def test_IUpper_stem_file_is_skipped(self):
        ws = _WS()
        iface = ws.dir / "src" / "IVault.sol"
        iface.write_text(_INTERFACE_SOL, encoding="utf-8")

        results = self._collect(ws.dir)
        paths = [p for p, _lang, _rel in results]
        self.assertNotIn(iface, paths,
                         "I<Upper>.sol stem must be skipped")

    def test_real_contract_is_kept(self):
        ws = _WS()
        contract = ws.dir / "src" / "Vault.sol"
        contract.write_text(_CONTRACT_SOL, encoding="utf-8")

        results = self._collect(ws.dir)
        paths = [p for p, _lang, _rel in results]
        self.assertIn(contract, paths,
                      "real contract with function bodies must be kept")

    def test_interface_skipped_real_kept_together(self):
        """When both an interface and a real contract exist, only the contract
        is yielded - the interface generates zero requirements."""
        ws = _WS()
        (ws.dir / "src" / "interfaces").mkdir(parents=True, exist_ok=True)

        iface = ws.dir / "src" / "interfaces" / "IVault.sol"
        iface.write_text(_INTERFACE_SOL, encoding="utf-8")

        contract = ws.dir / "src" / "Vault.sol"
        contract.write_text(_CONTRACT_SOL, encoding="utf-8")

        results = self._collect(ws.dir)
        paths = [p for p, _lang, _rel in results]

        self.assertIn(contract, paths,
                      "Vault.sol (real contract) must be yielded")
        self.assertNotIn(iface, paths,
                         "IVault.sol (interface) must not be yielded")

    def test_interface_in_interfaces_dir_generates_no_requirements(self):
        """End-to-end: an interface-only .sol under /interfaces/ must not
        contribute any cross-function requirements to evaluate()."""
        ws = _WS()
        iface_dir = ws.dir / "src" / "interfaces"
        iface_dir.mkdir(parents=True, exist_ok=True)
        (iface_dir / "IVault.sol").write_text(_INTERFACE_SOL, encoding="utf-8")

        res = xfi.evaluate(ws.dir)
        self.assertEqual(res["verdict"], "pass-no-source",
                         "interface-only workspace must yield pass-no-source "
                         "(no mutable source to enumerate requirements from). "
                         f"Got: {res['verdict']}")

    def test_IUpper_stem_generates_no_requirements(self):
        """End-to-end: an interface-only .sol with I<Upper> stem must not
        contribute any cross-function requirements."""
        ws = _WS()
        (ws.dir / "src" / "IVault.sol").write_text(_INTERFACE_SOL, encoding="utf-8")

        res = xfi.evaluate(ws.dir)
        self.assertIn(res["verdict"], ("pass-no-source", "pass-no-requirements"),
                      "interface-only workspace must yield pass-no-source or "
                      "pass-no-requirements (no mutable surface). "
                      f"Got: {res['verdict']}")

    def test_real_contract_alongside_interface_still_generates_requirements(self):
        """The skip must be surgical: interfaces are excluded but a real
        sibling contract still seeds cross-function requirements."""
        ws = _WS()
        iface_dir = ws.dir / "src" / "interfaces"
        iface_dir.mkdir(parents=True, exist_ok=True)
        (iface_dir / "IVault.sol").write_text(_INTERFACE_SOL, encoding="utf-8")
        ws.src("Vault.sol", _VAULT_SOL)

        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        self.assertIn("deposit|withdraw", labels,
                      "deposit|withdraw requirement must survive even when an "
                      f"interface file is present. requirements: {labels}")


if __name__ == "__main__":
    unittest.main()


class TestPremadeMutantKillCredit(unittest.TestCase):
    """A mutation-verify-coverage record whose `function` is path-qualified
    ("src/L1/ETHLockbox.sol:unlockETH") must credit the requirement's BARE
    function name ("unlockETH"). Before the fix the path-qualified string went
    into killed_fns verbatim and never matched - silently dropping genuine
    premade-mutant kills (cross-fn 5/108 should have been 9/108)."""

    def test_path_qualified_kill_credits_bare_name(self):
        import tempfile, json
        from pathlib import Path
        ws = Path(tempfile.mkdtemp()); (ws / ".auditooor").mkdir(parents=True)
        (ws / ".auditooor" / "mutation_verify_coverage.json").write_text(json.dumps({
            "results": [{"source_file": "src/L1/ETHLockbox.sol",
                         "function": "src/L1/ETHLockbox.sol:unlockETH",
                         "verdict": "non-vacuous", "mutation_verified": True}]}))
        r = xfi._load_mutation_state(ws)
        self.assertIn("unlocketh", r["killed_fns"], "bare function name not credited")

    def test_mvc_sidecar_dir_is_read(self):
        import tempfile, json
        from pathlib import Path
        ws = Path(tempfile.mkdtemp()); (ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
        (ws / ".auditooor" / "mvc_sidecar" / "ethlockbox_premade.json").write_text(json.dumps({
            "function": "src/L1/ETHLockbox.sol:lockETH", "verdict": "non-vacuous",
            "mutation_verified": True}))
        r = xfi._load_mutation_state(ws)
        self.assertIn("locketh", r["killed_fns"], "mvc_sidecar premade record not read")


class LocalAndPrivilegedFilterTest(unittest.TestCase):
    """Generic fixes: writes inside view/pure functions, assignments to per-
    function locals/params (declare-then-reassign, mapping keys), and all-
    privileged requirements are NOT real unprivileged cross-function state and
    must not produce phantom `state:<local>` / owner-only requirements. A genuine
    unprivileged co-mutated STORAGE field must still be detected (no over-filter)."""

    def test_view_pure_locals_not_state_fields(self):
        ws = _WS()
        # `digest`/`verify` are view; `_digest` is a LOCAL recomputed in each -
        # not co-mutated storage. Must NOT emit state:_digest.
        ws.src("MultisigIsm.sol", """contract M {
  function digest(bytes calldata m) public view returns (bytes32) { bytes32 _digest = keccak256(m); return _digest; }
  function verify(bytes calldata m) public view returns (bool) { bytes32 _digest = keccak256(m); return _digest != 0; }
  function check(bytes calldata m) public view returns (bool) { bytes32 _digest = keccak256(m); return _digest != bytes32(0); }
}""")
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        self.assertNotIn("state:_digest", labels, res)

    def test_memory_local_declared_then_used_not_state(self):
        ws = _WS()
        # `bytes memory payload = ...` is a local in each non-view function.
        ws.src("Hooks.sol", """contract H {
  function a() external { bytes memory payload = abi.encode(1); emit X(payload); }
  function b() external { bytes memory payload = abi.encode(2); emit X(payload); }
  function c() external { bytes memory payload = abi.encode(3); emit X(payload); }
  event X(bytes);
}""")
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        self.assertNotIn("state:payload", labels, res)

    def test_all_privileged_pair_excluded_but_unprivileged_detected(self):
        ws = _WS()
        # owner-only add/remove pair -> excluded; public add/remove pair -> kept.
        ws.src("IGP.sol", """contract G {
  mapping(address=>bool) signers;
  function addQuoteSigner(address s) external onlyOwner { signers[s] = true; }
  function removeQuoteSigner(address s) external onlyOwner { signers[s] = false; }
}""")
        ws.src("Reg.sol", """contract R {
  mapping(address=>bool) members;
  function addMember(address s) external { members[s] = true; }
  function removeMember(address s) external { members[s] = false; }
}""")
        res = xfi.evaluate(ws.dir)
        labels = {r["label"] for r in res["requirements"]}
        # owner-only IGP pair filtered (privileged-only = OOS)
        self.assertFalse(any(l.startswith("add|remove") and "igp" in l.lower() for l in labels), res)
        # the unprivileged member add/remove pair is still required (no over-filter)
        self.assertTrue(any(l.startswith("add|remove") for l in labels), res)


if __name__ == "__main__":
    unittest.main()


class TestMvcSidecarCrossFnCredit(unittest.TestCase):
    """NUVA 2026-06-30 serving-join: a mutation-verified mvc_sidecar chimera handler
    whose SOURCE exercises >=2 of a requirement's functions credits that requirement
    (the standard join misses it - the kill is keyed to the handler name, not the arms).
    NEVER-FALSE-PASS: a vacuous sidecar must NOT credit; the CUT source must NOT be read
    (it defines every fn); the harness must really exercise >= need functions."""

    def _ws_with_sidecar(self, rec: dict, handler_src: str):
        d = Path(tempfile.mkdtemp(prefix="xfi_mvc_"))
        sc = d / ".auditooor" / "mvc_sidecar"
        sc.mkdir(parents=True)
        h = d / "chimera_harnesses" / "X" / "test" / "XHandler.sol"
        h.parent.mkdir(parents=True)
        h.write_text(handler_src, encoding="utf-8")
        rec = dict(rec)
        rec["harness_path"] = "chimera_harnesses/X/test/XHandler.sol"
        (sc / "x.json").write_text(json.dumps(rec), encoding="utf-8")
        return d

    def test_nonvacuous_harness_exercising_two_arms_is_collected(self):
        ws = self._ws_with_sidecar(
            {"schema": "mvc_sidecar_v1", "mutation_verified": True},
            "contract XHandler { function h() public { v.deposit(x); v.withdraw(y); } }")
        refs = xfi._mvc_sidecar_verified_harness_refs(ws)
        self.assertEqual(len(refs), 1)
        self.assertTrue({"deposit", "withdraw"} <= {r.lower() for r in refs[0]["referenced"]})

    def test_vacuous_sidecar_is_rejected(self):
        ws = self._ws_with_sidecar(
            {"schema": "mvc_sidecar_v1", "mutation_verified": False, "verdict": "vacuous"},
            "contract XHandler { function h() public { v.deposit(x); v.withdraw(y); } }")
        self.assertEqual(xfi._mvc_sidecar_verified_harness_refs(ws), [])

    def test_no_baseline_sidecar_is_rejected(self):
        ws = self._ws_with_sidecar(
            {"schema": "auditooor.mutation_verify_coverage.v1",
             "mutation_verified": False, "verdict": "no-baseline"},
            "contract XHandler { function h() public { v.deposit(x); v.withdraw(y); } }")
        self.assertEqual(xfi._mvc_sidecar_verified_harness_refs(ws), [])

    def test_credit_requires_need_arms(self):
        refs = [{"file": "h.sol", "referenced": {"deposit"}, "sidecar": "x.json"}]

        class _R:
            kind = "sibling-pair"
            function_names = ["deposit", "withdraw"]
        ok, _ = xfi._requirement_covered_by_mvc_harness(_R(), refs, 2)
        self.assertFalse(ok, "1 arm must NOT cover a 2-arm requirement")
        refs2 = [{"file": "h.sol", "referenced": {"deposit", "withdraw"}, "sidecar": "x.json"}]
        ok2, ev2 = xfi._requirement_covered_by_mvc_harness(_R(), refs2, 2)
        self.assertTrue(ok2)
        self.assertEqual(sorted(ev2["matched_functions"]), ["deposit", "withdraw"])


class TestV1SchemaCommandHarnessRefs(unittest.TestCase):
    """Strata 2026-07-01 serving-join fix (same class as engine-harness-proof
    _resolve_sidecar_harness_file): the flat mutation_verify_coverage.v1 mvc_sidecar
    schema has NO harness_path/test_path key - it stores the harness as a runner
    COMMAND `cd <DIR> && forge test --match-path '<REL>'`. _mvc_sidecar_verified_
    harness_refs read only the *_path keys, so a genuinely non-vacuous v1 harness was
    never read and its cross-function refs were invisible (mint|burn read 'no test unit
    references the set' despite a real harness). _harness_files_from_command resolves
    the match-path file (+ campaign-dir siblings) from the command."""

    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp()).resolve()
        camp = self.ws / "chimera_harnesses" / "TrancheMintBurnConservation"
        camp.mkdir(parents=True)
        (camp / "Sanity.t.sol").write_text(
            "contract T { function t() public { h.mint(1); h.burnSharesAsFee(1); } }")
        (camp / "TrancheMintBurnConservation.sol").write_text(
            "contract H { function mint(uint x) public {} function burnSharesAsFee(uint x) public {} }")
        (self.ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)

    def _cmd(self, rel):
        return (f"cd {self.ws / 'chimera_harnesses'} && "
                f"/usr/bin/forge test --match-path '{rel}'")

    def test_harness_files_from_command_resolves_match_path_and_siblings(self):
        files = self.m._harness_files_from_command(
            self._cmd("TrancheMintBurnConservation/Sanity.t.sol"), self.ws)
        names = {Path(f).name for f in files}
        self.assertIn("Sanity.t.sol", names)
        self.assertIn("TrancheMintBurnConservation.sol", names)

    def test_harness_files_from_command_empty_when_no_match_path(self):
        self.assertEqual(self.m._harness_files_from_command("echo hi", self.ws), [])

    def test_v1_sidecar_refs_credited_without_harness_path(self):
        (self.ws / ".auditooor" / "mvc_sidecar" / "mvc-TrancheMintBurnConservation.json").write_text(
            json.dumps({
                "schema": "auditooor.mutation_verify_coverage.v1",
                "verdict": "non-vacuous", "killed_count": 2,
                "source_file": str(self.ws / "src" / "Tranche.sol"),
                "harness": self._cmd("TrancheMintBurnConservation/Sanity.t.sol"),
            }))
        rows = self.m._mvc_sidecar_verified_harness_refs(self.ws)
        self.assertTrue(rows, "a non-vacuous v1 sidecar must yield a refs row")
        refs = set()
        for r in rows:
            refs |= r["referenced"]
        self.assertIn("mint", refs)
        self.assertIn("burnSharesAsFee", refs)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestModuleScopedMvcCredit(unittest.TestCase):
    """False-green fix (axelar-sc 2026-07-12): _requirement_covered_by_mvc_harness
    must not credit a requirement with a harness from an ADJACENT module that merely
    shares the requirement's function-name tokens. The harness must also name one of
    the requirement's contracts (file stem)."""

    def _req(self, names, files):
        return xfi.Requirement(
            kind="sibling-pair", label="mint|burn@axelar-cgp-solidity",
            invariant_hint="supply-conservation",
            functions=[{"name": n, "file": f, "line": 1} for n, f in zip(names, files)],
            function_names=set(names),
        )

    def test_adjacent_module_harness_does_not_credit(self):
        # Requirement is AxelarGateway.mintToken/burnToken (axelar-cgp module).
        req = self._req(
            ["mintToken", "burnToken"],
            ["axelar-cgp-solidity/contracts/AxelarGateway.sol"] * 2,
        )
        # Harness references the same function tokens but only the ITS TokenManager
        # contract - it must NOT credit the axelar-cgp Gateway requirement.
        mvc_refs = [{
            "file": "chimera_harnesses/ITSMintConservation/test/H.t.sol",
            "referenced": {"mintToken", "burnToken", "TokenManager", "InterchainToken"},
            "sidecar": "mvc-ITSMintConservation.json",
        }]
        covered, _ = xfi._requirement_covered_by_mvc_harness(req, mvc_refs, need=2)
        self.assertFalse(covered, "adjacent-module harness must not credit the req")

    def test_same_contract_harness_credits(self):
        req = self._req(
            ["mintToken", "burnToken"],
            ["axelar-cgp-solidity/contracts/AxelarGateway.sol"] * 2,
        )
        mvc_refs = [{
            "file": "chimera_harnesses/GatewayMintBurn/test/H.t.sol",
            "referenced": {"mintToken", "burnToken", "AxelarGateway", "AxelarAuthWeighted"},
            "sidecar": "mvc-GatewayMintBurn.json",
        }]
        covered, ev = xfi._requirement_covered_by_mvc_harness(req, mvc_refs, need=2)
        self.assertTrue(covered, "harness naming the req contract must credit")
        self.assertIn("axelargateway", [c.lower() for c in ev.get("matched_contracts", [])])

    def test_legacy_behaviour_when_no_file_info(self):
        # Requirement carries NO file info -> legacy name-only credit preserved.
        req = xfi.Requirement(
            kind="sibling-pair", label="mint|burn", invariant_hint="x",
            functions=[{"name": "mintToken"}, {"name": "burnToken"}],
            function_names={"mintToken", "burnToken"},
        )
        mvc_refs = [{
            "file": "t/H.t.sol",
            "referenced": {"mintToken", "burnToken", "Whatever"},
            "sidecar": "s.json",
        }]
        covered, _ = xfi._requirement_covered_by_mvc_harness(req, mvc_refs, need=2)
        self.assertTrue(covered, "no-file-info req must keep legacy name-only credit")


if __name__ == "__main__":
    unittest.main()
