#!/usr/bin/env python3
"""Unit tests for tools/value-moving-functions.py.

Covers:
  - Solidity fixture: take/flashLoan/accrueInterest detected; getter + setOwner NOT flagged
  - Go fixture: Transfer/Mint detected; pure readers + IncrementNonce NOT flagged
  - morpho-midnight smoke: Midnight.sol::take + ::flashLoan present in output
  - pure-getter negative control in both languages
  - ZERO workspace literals (tmp dirs used throughout)
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
# Load the tool.
# ---------------------------------------------------------------------------
_TOOL = Path(__file__).resolve().parent.parent / "value-moving-functions.py"

# Replace hyphens in the module name so Python can import it as an attribute.
_MOD_NAME = "value_moving_functions"


def _load():
    spec = importlib.util.spec_from_file_location(_MOD_NAME, _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


vmf = _load()

# ---------------------------------------------------------------------------
# Path to the bundled fixtures.
# ---------------------------------------------------------------------------
_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "value_moving_functions"


class _WS:
    """Minimal scratch workspace builder used for isolated unit tests."""

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
# Helper: build an indexed set of (file_basename, function_name) pairs.
# ---------------------------------------------------------------------------
def _fn_set(records):
    out = set()
    for r in records:
        base = Path(r["file"]).name
        out.add((base, r["function"]))
    return out


# ---------------------------------------------------------------------------
# Solidity fixture tests.
# ---------------------------------------------------------------------------
class SolidityFixtureTest(unittest.TestCase):
    """Run the tool against the bundled Solidity fixture and assert detection."""

    @classmethod
    def setUpClass(cls):
        """Create a temp workspace that contains only the Solidity fixture."""
        cls.ws = _WS()
        src = _FIXTURE_DIR / "sol" / "MarketCore.sol"
        cls.ws.add("src/MarketCore.sol", src.read_text(encoding="utf-8"))
        cls.records = vmf.enumerate_value_moving(cls.ws.root)
        cls.fn_set = _fn_set(cls.records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_take_detected(self):
        """take() has safeTransferFrom + creditOf/debtOf writes - must be flagged."""
        self.assertIn(("MarketCore.sol", "take"), self.fn_set,
                      f"take not detected; got: {self.fn_set}")

    def test_flashloan_detected(self):
        """flashLoan() has safeTransfer - must be flagged (transfer hit alone suffices)."""
        self.assertIn(("MarketCore.sol", "flashLoan"), self.fn_set,
                      f"flashLoan not detected; got: {self.fn_set}")

    def test_accrue_interest_detected(self):
        """accrueInterest() writes balances - must be flagged (ledger write alone suffices)."""
        self.assertIn(("MarketCore.sol", "accrueInterest"), self.fn_set,
                      f"accrueInterest not detected; got: {self.fn_set}")

    def test_pure_getter_not_flagged(self):
        """getCreditOf() is a pure view getter - must NOT appear in output."""
        self.assertNotIn(("MarketCore.sol", "getCreditOf"), self.fn_set,
                         "pure getter getCreditOf incorrectly flagged as value-moving")

    def test_set_owner_not_flagged(self):
        """setOwner() writes no value field - must NOT appear in output."""
        self.assertNotIn(("MarketCore.sol", "setOwner"), self.fn_set,
                         "setOwner incorrectly flagged as value-moving")

    def test_take_has_transfer_and_ledger(self):
        """take() should fire BOTH transfer_hit and ledger_write_hit."""
        rec = next(
            (r for r in self.records
             if Path(r["file"]).name == "MarketCore.sol" and r["function"] == "take"),
            None,
        )
        self.assertIsNotNone(rec, "take record missing")
        self.assertTrue(rec["transfer_hit"], "take: expected transfer_hit=True")
        self.assertTrue(rec["ledger_write_hit"], "take: expected ledger_write_hit=True")

    def test_flashloan_has_transfer_hit(self):
        """flashLoan() fires via transfer_hit only."""
        rec = next(
            (r for r in self.records
             if Path(r["file"]).name == "MarketCore.sol" and r["function"] == "flashLoan"),
            None,
        )
        self.assertIsNotNone(rec, "flashLoan record missing")
        self.assertTrue(rec["transfer_hit"], "flashLoan: expected transfer_hit=True")


# ---------------------------------------------------------------------------
# Go fixture tests.
# ---------------------------------------------------------------------------
class GoFixtureTest(unittest.TestCase):
    """Run the tool against the bundled Go fixture and assert detection."""

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        src = _FIXTURE_DIR / "go" / "bank_keeper.go"
        cls.ws.add("src/bank_keeper.go", src.read_text(encoding="utf-8"))
        cls.records = vmf.enumerate_value_moving(cls.ws.root)
        cls.fn_set = _fn_set(cls.records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_transfer_detected(self):
        """Transfer() calls bankKeeper.SendCoins - must be flagged."""
        self.assertIn(("bank_keeper.go", "Transfer"), self.fn_set,
                      f"Transfer not detected; got: {self.fn_set}")

    def test_mint_detected(self):
        """Mint() calls MintCoins - must be flagged."""
        self.assertIn(("bank_keeper.go", "Mint"), self.fn_set,
                      f"Mint not detected; got: {self.fn_set}")

    def test_pure_getter_not_flagged(self):
        """GetCreditBalance / GetDebtBalance are reads - must NOT appear."""
        for fn in ("GetCreditBalance", "GetDebtBalance"):
            self.assertNotIn(("bank_keeper.go", fn), self.fn_set,
                             f"pure getter {fn} incorrectly flagged")

    def test_increment_nonce_not_flagged(self):
        """IncrementNonce writes 'nonce' which is not a value field - must NOT appear."""
        self.assertNotIn(("bank_keeper.go", "IncrementNonce"), self.fn_set,
                         "IncrementNonce incorrectly flagged as value-moving")


# ---------------------------------------------------------------------------
# OOS filtering: test files and vendored dirs are excluded.
# ---------------------------------------------------------------------------
class OOSFilterTest(unittest.TestCase):
    """Files under test/ or lib/ must be excluded even if they contain transfers."""

    def setUp(self):
        self.ws = _WS()
        # A test file with a transfer - must be excluded
        self.ws.add(
            "test/VaultTest.sol",
            "contract T { function testTransfer() external {"
            " SafeTransferLib.safeTransfer(tok, alice, 100); } }",
        )
        # A vendored lib file with a transfer - must be excluded
        self.ws.add(
            "lib/vendor/ERC20.sol",
            "contract E { function transfer(address to, uint v) external {"
            " balances[to] += v; } }",
        )
        # In-scope file with a transfer - must be included
        self.ws.add(
            "src/Core.sol",
            "contract C { mapping(address=>uint) shareOf; "
            "function distribute(address u, uint v) external {"
            " shareOf[u] += v; } }",
        )

    def tearDown(self):
        self.ws.cleanup()

    def test_test_file_excluded(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        names = {r["function"] for r in records}
        self.assertNotIn("testTransfer", names,
                         "test file function leaked into value-moving output")

    def test_vendor_file_excluded(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        files = {Path(r["file"]).name for r in records}
        self.assertNotIn("ERC20.sol", files,
                         "vendored ERC20.sol leaked into value-moving output")

    def test_inscope_file_included(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        names = {r["function"] for r in records}
        self.assertIn("distribute", names,
                      "in-scope Core.sol::distribute missing from output")


class SolidityViewPureExclusionTest(unittest.TestCase):
    """A Solidity view/pure fn cannot write storage or transfer - never value-moving.

    Regression for the WellPrice.decimals() class of false-positive: a getter
    that READS value-field names (totalSupply/balances) was mis-credited as a
    ledger write, flooding every VMF-gated lane. A non-view fn writing the same
    field must still be flagged (no over-exclusion).
    """

    def setUp(self):
        self.ws = _WS()
        self.ws.add(
            "src/Price.sol",
            "contract P {\n"
            " mapping(address=>uint) balances; uint totalSupply;\n"
            # view getter that references value fields -> must NOT be flagged
            " function assetPrice(address u) external view returns (uint) {\n"
            "   return balances[u] * totalSupply; }\n"
            # pure helper referencing a value-ish name -> must NOT be flagged
            " function calcShare(uint balance, uint supply) public pure returns (uint) {\n"
            "   return balance * supply; }\n"
            # non-view writer of the same field -> MUST be flagged
            " function credit(address u, uint v) external { balances[u] += v; }\n"
            "}",
        )

    def tearDown(self):
        self.ws.cleanup()

    def test_view_getter_not_flagged(self):
        names = {r["function"] for r in vmf.enumerate_value_moving(self.ws.root)}
        self.assertNotIn("assetPrice", names,
                         "view getter assetPrice mis-flagged as value-moving")

    def test_pure_helper_not_flagged(self):
        names = {r["function"] for r in vmf.enumerate_value_moving(self.ws.root)}
        self.assertNotIn("calcShare", names,
                         "pure helper calcShare mis-flagged as value-moving")

    def test_nonview_writer_still_flagged(self):
        names = {r["function"] for r in vmf.enumerate_value_moving(self.ws.root)}
        self.assertIn("credit", names,
                      "non-view writer credit() must remain value-moving")


class ManifestAuthoritativeScopeTest(unittest.TestCase):
    """value-moving enumeration must be MANIFEST-AUTHORITATIVE when a workspace's
    inscope_units.jsonl is present: only manifest rows count as in-scope, even
    though the file is a real source file with a value-moving write.

    Regression for the optimism core-coverage pollution: enumerate_value_moving
    filtered with is_oos() alone, which is blind to the curated per-workspace
    scope. OOS-but-not-vendored modules (op-e2e / op-chain-ops / op-batcher /
    cannon) leaked into value_moving_functions.json, so the core-coverage gate
    enumerated them as "uncovered core" contracts. With the manifest present,
    only the in-scope module survives.
    """

    def setUp(self):
        self.ws = _WS()
        # Two real, non-vendored, non-test source files each with a ledger write.
        self.ws.add(
            "src/in_scope/Core.sol",
            "contract C { mapping(address=>uint) balances;"
            " function credit(address u, uint v) external { balances[u] += v; } }",
        )
        self.ws.add(
            "src/out_of_scope/Periphery.sol",
            "contract P { mapping(address=>uint) balances;"
            " function topup(address u, uint v) external { balances[u] += v; } }",
        )

    def tearDown(self):
        self.ws.cleanup()

    def _write_manifest(self, rows):
        man = self.ws.root / ".auditooor" / "inscope_units.jsonl"
        man.write_text(
            "\n".join(json.dumps({"file": r}) for r in rows) + "\n",
            encoding="utf-8",
        )

    def test_manifest_excludes_oos_module(self):
        # Manifest names ONLY the in-scope file.
        self._write_manifest(["src/in_scope/Core.sol"])
        names = {r["function"] for r in vmf.enumerate_value_moving(self.ws.root)}
        self.assertIn("credit", names,
                      "manifest in-scope Core.credit must be enumerated")
        self.assertNotIn(
            "topup", names,
            "OOS Periphery.topup leaked despite an authoritative manifest "
            "that does not list it",
        )

    def test_no_manifest_falls_back_to_is_oos(self):
        # No manifest -> fail-safe: both non-OOS source files are in-scope.
        man = self.ws.root / ".auditooor" / "inscope_units.jsonl"
        if man.exists():
            man.unlink()
        names = {r["function"] for r in vmf.enumerate_value_moving(self.ws.root)}
        self.assertIn("credit", names)
        self.assertIn(
            "topup", names,
            "without a manifest, a non-OOS source file must stay in-scope "
            "(fail-safe = more coverage)",
        )


class SolidityInterfaceExclusionTest(unittest.TestCase):
    """Interface-declared / bodiless Solidity fns must NOT be enumerated.

    Root-cause: a bodiless `function f() external;` has no '{' in its own
    declaration.  _extract_body() scans forward and finds the next '{' in the
    file (e.g. the body of the following contract), returning it as the body.
    If that body contains call{value:} or a ledger write, the interface method
    is mis-flagged as a value-mover.

    Regression for the BEAN hunt: IWETH.withdraw and IWETH.balanceOf were
    flagged because they absorbed UnwrapAndSendETH's body.

    Guard tests:
      - interface-declared withdraw / balanceOf -> NOT flagged
      - bodiless external abstract declaration -> NOT flagged
      - real contract function with body -> IS flagged
    """

    def setUp(self):
        self.ws = _WS()
        # Interface with two bodiless declarations followed immediately by a
        # real contract whose body contains call{value:}.  This is the exact
        # shape of the BEAN FP.
        self.ws.add(
            "src/UnwrapAndSendETH.sol",
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.17;\n"
            "\n"
            "interface IWETH {\n"
            "    function withdraw(uint256) external;\n"
            "    function balanceOf(address) external returns (uint256);\n"
            "}\n"
            "\n"
            "contract UnwrapAndSendETH {\n"
            "    address public immutable WETH;\n"
            "    constructor(address w) { WETH = w; }\n"
            "    receive() external payable {}\n"
            "    function unwrapAndSend(address to) external {\n"
            "        uint256 bal = IWETH(WETH).balanceOf(address(this));\n"
            "        IWETH(WETH).withdraw(bal);\n"
            "        (bool ok, ) = to.call{value: address(this).balance}(\"\");\n"
            "        require(ok);\n"
            "    }\n"
            "}\n",
        )
        # Separate file: abstract contract with a bodiless virtual function.
        self.ws.add(
            "src/AbstractBase.sol",
            "abstract contract Base {\n"
            "    function doTransfer(address to, uint v) external virtual;\n"
            "    function realWork(address to, uint v) external {\n"
            "        payable(to).transfer(v);\n"
            "    }\n"
            "}\n",
        )

    def tearDown(self):
        self.ws.cleanup()

    def test_interface_withdraw_not_flagged(self):
        """IWETH.withdraw is a bodiless interface declaration - must NOT appear."""
        records = vmf.enumerate_value_moving(self.ws.root)
        # filter to interface-declared fns (only withdraw + balanceOf from IWETH)
        iweth_fns = [
            r for r in records
            if r["function"] in ("withdraw", "balanceOf")
            and Path(r["file"]).name == "UnwrapAndSendETH.sol"
        ]
        self.assertEqual(
            iweth_fns, [],
            f"Interface methods leaked into VMF output: {iweth_fns}",
        )

    def test_interface_balanceof_not_flagged(self):
        """IWETH.balanceOf is a bodiless interface declaration - must NOT appear."""
        records = vmf.enumerate_value_moving(self.ws.root)
        names = {r["function"] for r in records
                 if Path(r["file"]).name == "UnwrapAndSendETH.sol"}
        self.assertNotIn(
            "balanceOf", names,
            "IWETH.balanceOf (interface decl) incorrectly flagged as value-moving",
        )

    def test_abstract_bodiless_fn_not_flagged(self):
        """Abstract virtual function with no body must NOT appear."""
        records = vmf.enumerate_value_moving(self.ws.root)
        names = {r["function"] for r in records
                 if Path(r["file"]).name == "AbstractBase.sol"}
        self.assertNotIn(
            "doTransfer", names,
            "Abstract bodiless doTransfer incorrectly flagged as value-moving",
        )

    def test_real_contract_fn_still_flagged(self):
        """unwrapAndSend has a real body with call{value:} - must remain flagged."""
        records = vmf.enumerate_value_moving(self.ws.root)
        names = {r["function"] for r in records
                 if Path(r["file"]).name == "UnwrapAndSendETH.sol"}
        self.assertIn(
            "unwrapAndSend", names,
            "unwrapAndSend (real body with call{value:}) must be value-moving",
        )

    def test_abstract_real_fn_still_flagged(self):
        """Base.realWork has a body with .transfer() - must remain flagged."""
        records = vmf.enumerate_value_moving(self.ws.root)
        names = {r["function"] for r in records
                 if Path(r["file"]).name == "AbstractBase.sol"}
        self.assertIn(
            "realWork", names,
            "Base.realWork (real body with .transfer()) must be value-moving",
        )


class ToolArtifactExclusionTest(unittest.TestCase):
    """Generated harnesses under <ws>/.auditooor/ are never the code-under-test."""

    def setUp(self):
        self.ws = _WS()
        # A generated VCIS harness scaffold with a clear value-mover.
        self.ws.add(
            ".auditooor/vcis-harness/src/SolvencyFuzz.sol",
            "contract H { mapping(address=>uint) balances;"
            " function action_repay(address u, uint v) external { balances[u] += v; } }",
        )
        # In-scope source with the same shape must still be detected.
        self.ws.add(
            "src/Real.sol",
            "contract R { mapping(address=>uint) balances;"
            " function repay(address u, uint v) external { balances[u] += v; } }",
        )

    def tearDown(self):
        self.ws.cleanup()

    def test_artifact_harness_excluded(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        for r in records:
            self.assertNotIn(".auditooor", r["file"],
                             f"tool-artifact file leaked into VMF: {r['file']}")

    def test_real_source_still_detected(self):
        names = {r["function"] for r in vmf.enumerate_value_moving(self.ws.root)}
        self.assertIn("repay", names,
                      "in-scope Real.sol::repay missing after artifact exclusion")


# ---------------------------------------------------------------------------
# JSON output structure.
# ---------------------------------------------------------------------------
class GeneratedCodeExclusionTest(unittest.TestCase):
    """abigen/protoc generated bindings carry a 'Code generated ... DO NOT EDIT.'
    header but no generated FILENAME suffix, so is_in_scope admits them and
    is_oos(rel) (no head text) misses them. They are auto-generated ABI wrappers,
    never an auditable value-moving CORE contract - they must be dropped so they do
    not pollute the core-coverage denominator (3 of optimism's 63 were such)."""

    def setUp(self):
        self.ws = _WS()
        # Generated abigen Go binding (real optimism shape: op-node/bindings/*.go).
        # Body uses a recognized value-mover so the exclusion is NON-VACUOUS: if the
        # filter were absent this WOULD be flagged value-moving.
        self.ws.add(
            "op-node/bindings/optimismportal.go",
            "// Code generated - DO NOT EDIT.\n"
            "// This file is a generated binding and any manual changes will be lost.\n"
            "package bindings\n"
            "func (p *OptimismPortal) DepositTransaction(ctx Context, amt Coins) error {\n"
            "    return p.bankKeeper.SendCoinsFromModuleToAccount(ctx, mod, to, amt)\n}\n",
        )
        # A real (non-generated) Go source with the SAME value-moving body - only the
        # generated header differs, so it must still be detected (no over-exclusion).
        self.ws.add(
            "op-node/rollup/real.go",
            "package rollup\n"
            "func (k Keeper) DepositTransaction(ctx Context, amt Coins) error {\n"
            "    return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, mod, to, amt)\n}\n",
        )

    def tearDown(self):
        self.ws.cleanup()

    def test_generated_binding_excluded(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        for r in records:
            self.assertNotIn("bindings/optimismportal.go", r["file"],
                             f"generated abigen binding leaked into VMF: {r['file']}")

    def test_real_go_source_still_detected(self):
        files = {r["file"] for r in vmf.enumerate_value_moving(self.ws.root)}
        self.assertTrue(any("rollup/real.go" in f for f in files),
                        "non-generated Go source wrongly dropped by generated filter")


class OutputStructureTest(unittest.TestCase):
    """run() must write valid JSON with the documented schema."""

    def setUp(self):
        self.ws = _WS()
        self.ws.add(
            "src/Token.sol",
            "contract T { mapping(address=>uint) balances;"
            " function transfer(address to, uint amt) external {"
            " balances[to] += amt; } }",
        )

    def tearDown(self):
        self.ws.cleanup()

    def test_output_file_created(self):
        out = vmf.run(self.ws.root)
        self.assertTrue(out.exists(), f"output file not created: {out}")

    def test_output_schema(self):
        out = vmf.run(self.ws.root)
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertIn("workspace", payload)
        self.assertIn("generated_at", payload)
        self.assertIn("function_count", payload)
        self.assertIn("functions", payload)
        self.assertIsInstance(payload["functions"], list)
        for rec in payload["functions"]:
            for key in ("file", "function", "language",
                        "transfer_hit", "ledger_write_hit",
                        "transfer_evidence", "ledger_write_evidence"):
                self.assertIn(key, rec, f"missing key '{key}' in record: {rec}")


# ---------------------------------------------------------------------------
# morpho-midnight smoke test: Midnight.sol::take + ::flashLoan must appear.
# ---------------------------------------------------------------------------
MORPHO_MIDNIGHT_WS = Path("/Users/wolf/audits/morpho-midnight")


@unittest.skipUnless(
    MORPHO_MIDNIGHT_WS.is_dir(),
    "morpho-midnight workspace not present - skipping smoke test",
)
class MorphoMidnightSmokeTest(unittest.TestCase):
    """Verify that Midnight.sol::take and ::flashLoan are detected in the real workspace."""

    @classmethod
    def setUpClass(cls):
        cls.records = vmf.enumerate_value_moving(MORPHO_MIDNIGHT_WS)
        cls.fn_set = _fn_set(cls.records)

    def test_take_detected_in_midnight(self):
        """Midnight.sol::take is the primary value-moving function under audit."""
        self.assertIn(("Midnight.sol", "take"), self.fn_set,
                      f"Midnight.sol::take not detected; sample: "
                      f"{list(self.fn_set)[:10]}")

    def test_flashloan_detected_in_midnight(self):
        """Midnight.sol::flashLoan is a known value-moving function."""
        self.assertIn(("Midnight.sol", "flashLoan"), self.fn_set,
                      f"Midnight.sol::flashLoan not detected; sample: "
                      f"{list(self.fn_set)[:10]}")


# ---------------------------------------------------------------------------
# Rust fixture tests - inline #[test] fns excluded, real value-movers included.
# ---------------------------------------------------------------------------
_RS_FIXTURE_DIR = _FIXTURE_DIR / "rs"


class RustFixtureTest(unittest.TestCase):
    """Run the tool against the bundled Rust fixture and assert correct detection."""

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        src = _RS_FIXTURE_DIR / "vault.rs"
        cls.ws.add("src/vault.rs", src.read_text(encoding="utf-8"))
        cls.records = vmf.enumerate_value_moving(cls.ws.root)
        cls.fn_set = _fn_set(cls.records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_deposit_detected(self):
        """deposit() has *bal += amount (compound indexed write) - must be flagged."""
        self.assertIn(("vault.rs", "deposit"), self.fn_set,
                      f"deposit not detected; got: {self.fn_set}")

    def test_withdraw_detected(self):
        """withdraw() has *bal -= amount - must be flagged."""
        self.assertIn(("vault.rs", "withdraw"), self.fn_set,
                      f"withdraw not detected; got: {self.fn_set}")

    def test_push_amount_detected(self):
        """push_amount() pushes to an amounts Vec - must be flagged."""
        self.assertIn(("vault.rs", "push_amount"), self.fn_set,
                      f"push_amount not detected; got: {self.fn_set}")

    def test_cosmwasm_send_detected(self):
        """cosmwasm_send() uses BankMsg::Send - must be flagged."""
        self.assertIn(("vault.rs", "cosmwasm_send"), self.fn_set,
                      f"cosmwasm_send not detected; got: {self.fn_set}")

    def test_test_attr_fn_excluded(self):
        """#[test] fn test_deposit_noop must NOT appear - it is a test fn."""
        self.assertNotIn(("vault.rs", "test_deposit_noop"), self.fn_set,
                         "#[test] fn test_deposit_noop incorrectly flagged as value-moving")

    def test_tokio_test_attr_fn_excluded(self):
        """#[tokio::test] fn test_withdraw_async must NOT appear."""
        self.assertNotIn(("vault.rs", "test_withdraw_async"), self.fn_set,
                         "#[tokio::test] fn test_withdraw_async incorrectly flagged")

    def test_pure_getter_not_flagged(self):
        """get_balance() is a pure read - must NOT appear."""
        self.assertNotIn(("vault.rs", "get_balance"), self.fn_set,
                         "pure getter get_balance incorrectly flagged as value-moving")


# ---------------------------------------------------------------------------
# OOS path filter: benches/, e2e-test/, e2e-tests/, _test_util files excluded.
# ---------------------------------------------------------------------------
class OOSPathExtendedTest(unittest.TestCase):
    """Verify the extended OOS markers for benches, e2e-test, _test_util."""

    def setUp(self):
        self.ws = _WS()
        # benches/ dir - must be excluded
        self.ws.add(
            "benches/benchmark.rs",
            "fn bench_transfer() { let mut balance: u64 = 0; balance += 100; }",
        )
        # e2e-test hyphenated dir - must be excluded
        self.ws.add(
            "crates/e2e-test/src/helpers.rs",
            "fn setup_transfer() { let mut balance: u64 = 0; balance += 100; }",
        )
        # e2e-tests variant - must be excluded
        self.ws.add(
            "crates/e2e-tests/src/runner.rs",
            "fn run_transfer() { let mut balance: u64 = 0; balance += 100; }",
        )
        # _test_util.go file - must be excluded
        self.ws.add(
            "x/clob/memclob/memclob_test_util.go",
            "package memclob\n"
            "func setupOrderBook() {\n"
            "    var expectedOrderIdToFilledAmount = make(map[string]int)\n"
            "    expectedOrderIdToFilledAmount[\"order1\"] = 100\n"
            "}\n",
        )
        # In-scope file - must be included
        self.ws.add(
            "src/ledger.rs",
            "pub fn credit(mut balance: u64, amount: u64) -> u64 { balance += amount; balance }",
        )

    def tearDown(self):
        self.ws.cleanup()

    def test_benches_dir_excluded(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        files = {Path(r["file"]).name for r in records}
        self.assertNotIn("benchmark.rs", files,
                         "benches/benchmark.rs leaked into value-moving output")

    def test_e2e_test_dir_excluded(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        files = {Path(r["file"]).name for r in records}
        self.assertNotIn("helpers.rs", files,
                         "e2e-test/helpers.rs leaked into value-moving output")

    def test_e2e_tests_dir_excluded(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        files = {Path(r["file"]).name for r in records}
        self.assertNotIn("runner.rs", files,
                         "e2e-tests/runner.rs leaked into value-moving output")

    def test_test_util_go_excluded(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        files = {Path(r["file"]).name for r in records}
        self.assertNotIn("memclob_test_util.go", files,
                         "memclob_test_util.go (test util) leaked into value-moving output")

    def test_inscope_rust_included(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        # ledger.rs::credit should be detected because `balance += amount` fires
        # the generic compound-assignment rule (if the field name hits _VALUE_ROOTS)
        # OR the transfer-call pattern for .transfer - here it relies on ledger-write.
        # The name 'balance' IS a value root, so this should fire.
        names = {r["function"] for r in records}
        self.assertIn("credit", names,
                      "in-scope ledger.rs::credit missing from output")


if __name__ == "__main__":
    unittest.main(verbosity=2)
