"""Tests for tools/lib/scope_exclusion.py - the single-source-of-truth
scope-exclusion / in-scope-membership module.

These prove (mechanically, generically, language-agnostically):
  1. Each marker class fires (vendored / test / generated, incl. header regex).
  2. In-scope protocol source across Go/Cosmos, Solidity, Rust is NOT excluded.
  3. Leading-slash normalisation (top-level test/Foo.sol -> /test/ matches).
  4. Whole-segment matching: "interchaintest" excluded, "latest_state.go" KEPT;
     "contracts/@openzeppelin/..." excluded, project "contracts/MyToken.sol" KEPT.
  5. Manifest-authoritative mode (membership = manifest rows verbatim).
  6. Env-hook extension (append, never replace).
  7. is_auditable_source suffix gating + OOS gating.
  8. is_oos = generated OR test OR vendored.

NOTE: workspace names appearing below are SMOKE fixtures only (the union was
mined across them); none drives module logic.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from tools.lib import scope_exclusion as se


# ---------------------------------------------------------------------------
# Vendored class.
# ---------------------------------------------------------------------------
class VendoredTest(unittest.TestCase):
    def test_dependency_dirs_fire(self):
        for p in [
            "node_modules/foo/index.js",
            "lib/forge-std/src/Test.sol",
            "lib/openzeppelin-contracts/contracts/token/ERC20.sol",
            "contracts/vendor/SomeDep.sol",
            "third_party/grpc/foo.go",
            "out/MyContract.sol/MyContract.json",
            "cache/solidity-files-cache.json",
            "target/debug/build/x.rs",
            "broadcast/Deploy.s.sol/1/run-latest.json",
            "src/reference/OldImpl.sol",
            "artifacts/Contract.json",
        ]:
            self.assertTrue(se.is_vendored(p), f"expected vendored: {p}")

    def test_solidity_dep_namespaces_fire(self):
        for p in [
            "contracts/@openzeppelin/contracts/access/Ownable.sol",
            "node_modules/@openzeppelin/contracts-upgradeable/proxy/Initializable.sol",
            "src/@uniswap/v3-core/contracts/UniswapV3Pool.sol",
            "deps/@chainlink/contracts/AggregatorV3Interface.sol",
            "lib/solmate/src/tokens/ERC20.sol",
            "lib/solady/src/utils/SafeTransferLib.sol",
        ]:
            self.assertTrue(se.is_vendored(p), f"expected vendored: {p}")

    def test_well_known_lib_files_fire(self):
        for p in [
            "src/utils/SafeERC20.sol",
            "contracts/libraries/Address.sol",
            "src/math/Math.sol",
            "src/cryptography/ECDSA.sol",
            "src/Strings.sol",
        ]:
            self.assertTrue(se.is_vendored(p), f"expected vendored lib file: {p}")

    def test_cosmos_go_deps_fire(self):
        for p in [
            "x/foo/cosmos-sdk/types/coin.go",
            "vendor/github.com/cometbft/cometbft/abci/types.go",
            "tests/interchaintest/setup.go",
            "x/wasm/wasmd/keeper.go",
        ]:
            self.assertTrue(se.is_vendored(p), f"expected vendored: {p}")

    def test_interchaintest_segment_vs_substring(self):
        # whole segment "interchaintest" must drop ...
        self.assertTrue(se.is_vendored("tests/interchaintest/foo.go"))
        # ... but "latest" containing the substring "test" must NOT be vendored
        self.assertFalse(se.is_vendored("modules/exchange/keeper/latest_state.go"))

    def test_tendermint_component_dir_is_in_scope_not_vendored(self):
        # A bare "tendermint" segment is an in-scope component-interface dir on a
        # Cosmos chain (the orchestrator interfaces TO tendermint), NOT a
        # vendored copy. Dropping it would be a false-green. A genuinely vendored
        # CometBFT/Tendermint copy lives under vendor/ and is still dropped.
        self.assertFalse(se.is_vendored(
            "src/injective-core/peggo/orchestrator/cosmos/tendermint/client.go"))
        self.assertFalse(se.is_oos(
            "src/injective-core/peggo/orchestrator/cosmos/tendermint/client.go"))
        # genuinely vendored copy under vendor/ still caught (by the vendor marker)
        self.assertTrue(se.is_vendored(
            "vendor/github.com/cometbft/cometbft/abci/types.go"))


# ---------------------------------------------------------------------------
# Test class.
# ---------------------------------------------------------------------------
class TestMarkerTest(unittest.TestCase):
    def test_test_dirs_and_suffixes_fire(self):
        for p in [
            "test/Foo.sol",                      # top-level, no leading slash (false-red guard)
            "src/test/Bar.t.sol",
            "contracts/test/Baz.sol",
            "tests/integration/main.rs",
            "x/keeper/keeper_test.go",
            "src/lib/foo_test.rs",
            "crates/foo/src/tests.rs",
            "test/invariants/Handler.t.sol",
            "script/Deploy.s.sol",
            "scripts/deploy.go",
            "src/MyContract.t.sol",
            "spec/behaviour_spec.rb",
            "testdata/sample.json",
        ]:
            self.assertTrue(se.is_test(p), f"expected test: {p}")

    def test_top_level_test_dir_leading_slash_normalisation(self):
        # THE morpho-midnight false-red: top-level test/ with no leading slash.
        self.assertTrue(se.is_test("test/Foo.sol"))
        self.assertTrue(se.is_test("./test/Foo.sol"))
        self.assertTrue(se.is_test("test\\Foo.sol"))  # backslash variant

    def test_mocks_fixtures_harness_fire(self):
        for p in [
            "src/mocks/MockToken.sol",
            "contracts/mock/MockOracle.sol",
            "test/fixtures/data.go",
            "src/harness/InvariantHarness.sol",
            "test/echidna/EchidnaTest.sol",
            "test/halmos/SymbolicTest.sol",
            "test/medusa/config.yaml",
            "certora/specs/Foo.spec",
            # NOTE: "src/interfaces/IERC20.sol" was REMOVED here - interfaces/ is a
            # normal PRODUCTION Solidity layout, not test/mock infra. The over-broad
            # "/interface" / "/interfaces/" markers were dropped from
            # _TEST_MARKERS_DEFAULT (strata expected-19-got-17 false-green); see
            # test_scope_exclusion_interfaces_inscope.py for the regression pin.
        ]:
            self.assertTrue(se.is_test(p), f"expected test/infra: {p}")

    def test_basename_regexes_fire(self):
        self.assertTrue(se.is_test("cmd/test_main.go"))          # ^test_*.go basename
        self.assertTrue(se.is_test("contracts/MyContractTest.sol"))  # ...Test.sol basename
        self.assertTrue(se.is_test("contracts/FooTest.sol"))

    def test_dirname_regexes_fire(self):
        self.assertTrue(se.is_test("x/keeper/testutil/helpers.go"))
        self.assertTrue(se.is_test("internal/testing/server.go"))

    def test_poc_dirs_fire(self):
        self.assertTrue(se.is_test("poc/Exploit.sol"))
        self.assertTrue(se.is_test("test/poc-tests/Repro.t.sol"))

    def test_benches_dir_fires(self):
        """benches/ is a benchmark (non-protocol) dir and must be OOS."""
        self.assertTrue(se.is_test("benches/benchmark.rs"),
                        "benches/benchmark.rs should be test/infra OOS")
        self.assertTrue(se.is_test("crates/foo/benches/bench_hash.rs"),
                        "crates/foo/benches/bench_hash.rs should be test/infra OOS")

    def test_e2e_hyphenated_dirs_fire(self):
        """Hyphenated e2e-test / e2e-tests / something-tests dirs must be OOS."""
        self.assertTrue(se.is_test("crates/e2e-test/src/helper.rs"),
                        "e2e-test dir should be OOS")
        self.assertTrue(se.is_test("crates/e2e-tests/src/runner.rs"),
                        "e2e-tests dir should be OOS")
        self.assertTrue(se.is_test("crates/integration-tests/src/main.rs"),
                        "integration-tests dir should be OOS")
        self.assertTrue(se.is_test("crates/integration-test/src/setup.rs"),
                        "integration-test dir should be OOS")

    def test_test_util_file_suffix_fires(self):
        """Files named *_test_util.go / *_test_utils.go must be OOS."""
        self.assertTrue(se.is_test("x/clob/memclob/memclob_test_util.go"),
                        "memclob_test_util.go should be OOS")
        self.assertTrue(se.is_test("module/keeper/keeper_test_utils.go"),
                        "keeper_test_utils.go should be OOS")
        self.assertTrue(se.is_test("src/util/sign_test_utils.go"),
                        "sign_test_utils.go should be OOS")
        # Rust variant
        self.assertTrue(se.is_test("crates/core/src/actions_test_utils.rs"),
                        "actions_test_utils.rs should be OOS")

    def test_benches_segment_vs_substring(self):
        """'benches' must be a whole-segment match, not a bare substring."""
        # A file under a 'benches' directory is OOS ...
        self.assertTrue(se.is_test("crates/foo/benches/bench_hash.rs"))
        # ... but a file whose NAME contains 'benches' as a substring must NOT be OOS.
        self.assertFalse(se.is_test("src/benchesmark_utils.rs"),
                         "benchesmark_utils.rs wrongly OOS (substring false-positive)")

    def test_e2e_test_dir_not_production(self):
        """e2e-test dir is OOS; a production file named 'e2e_contract.rs' is NOT."""
        self.assertTrue(se.is_test("crates/e2e-test/src/client.rs"))
        self.assertFalse(se.is_test("src/e2e_contract.rs"),
                         "e2e_contract.rs (production file) wrongly marked OOS")


# ---------------------------------------------------------------------------
# Generated class.
# ---------------------------------------------------------------------------
class GeneratedTest(unittest.TestCase):
    def test_filename_markers_fire(self):
        for p in [
            "x/foo/types/query.pb.go",
            "x/foo/types/query.pb.gw.go",
            "x/foo/types/tx_grpc.pb.go",
            "contracts/abi/Token.abigen.go",
            "internal/bindings/Pool.abi.go",
            "x/foo/types/orm_gen.go",
            "x/foo/keeper/store.gen.go",
            "x/foo/types/codec_generated.go",
            "x/foo/types/state.cosmos_orm.go",
        ]:
            self.assertTrue(se.is_generated(p), f"expected generated: {p}")

    def test_generated_dir_and_xxx_prefix_fire(self):
        self.assertTrue(se.is_generated("internal/generated/api.go"))
        self.assertTrue(se.is_generated("x/foo/types/XXX_Unmarshal.go"))

    def test_do_not_edit_header_with_head(self):
        head_strict = "// Code generated by protoc-gen-go. DO NOT EDIT.\n\npackage types\n"
        self.assertTrue(se.is_generated("x/foo/types/oddname.go", head=head_strict))
        head_loose = "/* Code generated by mockgen v1.6 DO NOT EDIT */\npackage mocks\n"
        self.assertTrue(se.is_generated("x/foo/oddname2.go", head=head_loose))

    def test_no_header_no_marker_not_generated(self):
        # Plain protocol source with no marker + no head => NOT generated.
        self.assertFalse(se.is_generated("modules/exchange/keeper.go"))
        self.assertFalse(se.is_generated("modules/exchange/keeper.go", head="package keeper\n"))


# ---------------------------------------------------------------------------
# In-scope protocol source must NOT be excluded (false-green guard).
# ---------------------------------------------------------------------------
class InScopeProtocolSourceTest(unittest.TestCase):
    PROTOCOL_SOURCES = [
        "modules/exchange/keeper.go",
        "modules/exchange/keeper/latest_state.go",     # 'latest' contains 'test'
        "x/auction/keeper/msg_server.go",
        "contracts/Peggy.sol",
        "contracts/MyToken.sol",
        "swap-contract/src/contract.rs",
        "crates/core/src/lib.rs",
        "src/main.rs",
        "programs/amm/src/processor.rs",
        "sources/dex/pool.move",
        "src/Voting.cairo",
    ]

    def test_protocol_source_not_oos(self):
        for p in self.PROTOCOL_SOURCES:
            self.assertFalse(se.is_oos(p), f"protocol source wrongly OOS: {p}")

    def test_protocol_source_is_auditable(self):
        for p in self.PROTOCOL_SOURCES:
            self.assertTrue(se.is_auditable_source(p), f"protocol source not auditable: {p}")

    def test_protocol_source_in_scope_without_workspace(self):
        for p in self.PROTOCOL_SOURCES:
            self.assertTrue(se.is_in_scope(p), f"protocol source not in scope: {p}")

    def test_project_token_kept_but_oz_dropped(self):
        # A project contract under contracts/ is KEPT ...
        self.assertTrue(se.is_auditable_source("contracts/MyToken.sol"))
        self.assertFalse(se.is_oos("contracts/MyToken.sol"))
        # ... but a vendored OZ contract under contracts/@openzeppelin/ is DROPPED.
        self.assertTrue(se.is_oos("contracts/@openzeppelin/contracts/token/ERC20.sol"))
        self.assertFalse(se.is_auditable_source("contracts/@openzeppelin/contracts/token/ERC20.sol"))


# ---------------------------------------------------------------------------
# Whole-segment matching edge cases.
# ---------------------------------------------------------------------------
class SegmentMatchTest(unittest.TestCase):
    def test_lib_segment_vs_libname(self):
        # whole 'lib' dir => vendored
        self.assertTrue(se.is_vendored("lib/forge-std/src/Test.sol"))
        # a file whose NAME contains 'lib' must NOT be vendored on that basis
        self.assertFalse(se.is_vendored("crates/core/src/liberty.rs"))
        self.assertFalse(se.is_vendored("src/calibration.go"))

    def test_vendor_segment_vs_vendorname(self):
        self.assertTrue(se.is_vendored("vendor/x/y.go"))
        self.assertFalse(se.is_vendored("modules/vendormanager/keeper.go"))

    def test_out_build_dist_segment_only(self):
        self.assertTrue(se.is_vendored("out/Foo.json"))
        self.assertFalse(se.is_vendored("modules/checkout/keeper.go"))  # 'out' inside 'checkout'
        self.assertTrue(se.is_vendored("build/contracts/Foo.json"))
        self.assertFalse(se.is_vendored("src/rebuilder.rs"))            # 'build' inside 'rebuilder'

    def test_address_sol_basename_equality(self):
        # 'Address.sol' marker matches the basename even nested under a project dir
        self.assertTrue(se.is_vendored("contracts/libraries/Address.sol"))
        # but a differently-named project file is kept
        self.assertFalse(se.is_vendored("contracts/MyAddressBook.sol"))


# ---------------------------------------------------------------------------
# is_oos composition + is_auditable_source suffix gating.
# ---------------------------------------------------------------------------
class CompositionTest(unittest.TestCase):
    def test_is_oos_union(self):
        self.assertTrue(se.is_oos("test/Foo.sol"))                 # test
        self.assertTrue(se.is_oos("lib/forge-std/src/Test.sol"))   # vendored
        self.assertTrue(se.is_oos("x/foo/types/query.pb.go"))      # generated
        self.assertFalse(se.is_oos("modules/exchange/keeper.go"))  # in-scope

    def test_is_oos_generated_via_head(self):
        head = "// Code generated by tool. DO NOT EDIT.\npackage x\n"
        self.assertFalse(se.is_oos("x/foo/plain.go"))
        self.assertTrue(se.is_oos("x/foo/plain.go", head=head))

    def test_auditable_source_suffix_gate(self):
        # not a recognised source suffix => not auditable
        self.assertFalse(se.is_auditable_source("modules/exchange/config.json"))
        self.assertFalse(se.is_auditable_source("README.md"))
        self.assertFalse(se.is_auditable_source("Makefile"))
        # recognised suffix + in scope => auditable
        self.assertTrue(se.is_auditable_source("modules/exchange/keeper.go"))

    def test_auditable_source_custom_suffixes(self):
        # caller restricts to solidity only
        self.assertTrue(se.is_auditable_source("contracts/MyToken.sol", suffixes=(".sol",)))
        self.assertFalse(se.is_auditable_source("modules/exchange/keeper.go", suffixes=(".sol",)))

    def test_oos_file_never_auditable(self):
        self.assertFalse(se.is_auditable_source("test/Foo.sol"))
        self.assertFalse(se.is_auditable_source("lib/solmate/src/tokens/ERC20.sol"))


# ---------------------------------------------------------------------------
# Manifest-authoritative mode.
# ---------------------------------------------------------------------------
class ManifestAuthoritativeTest(unittest.TestCase):
    def _write_manifest(self, ws: Path, rows: list[dict]):
        d = ws / ".auditooor"
        d.mkdir(parents=True, exist_ok=True)
        with (d / "inscope_units.jsonl").open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    def test_inscope_fork_repo_manifest_row_is_kept(self):
        # An in-scope FORK repo whose top-level dir name matches a vendored
        # project marker (src/cosmos-sdk, src/cometbft) must be KEPT when it is a
        # curated manifest row - is_in_scope must NOT apply the project-name
        # vendored markers (that would drop the audit target = under-scope).
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            self._write_manifest(ws, [
                {"file": "src/cosmos-sdk/x/auth/ante.go", "function": "Ante",
                 "file_line": "src/cosmos-sdk/x/auth/ante.go:10", "lang": "go"},
                {"file": "src/cometbft/consensus/state.go", "function": "enterPropose",
                 "file_line": "src/cometbft/consensus/state.go:5", "lang": "go"},
                # still-excluded pollution even though manifest-listed:
                {"file": "src/cosmos-sdk/deps/forge/x.go", "function": "F",
                 "file_line": "x:1", "lang": "go"},
                {"file": "interchaintest/helpers/peggy.go", "function": "B",
                 "file_line": "x:1", "lang": "go"},
            ])
            self.assertTrue(se.is_in_scope("src/cosmos-sdk/x/auth/ante.go", workspace=ws))
            self.assertTrue(se.is_in_scope("src/cometbft/consensus/state.go", workspace=ws))
            self.assertFalse(se.is_in_scope("src/cosmos-sdk/deps/forge/x.go", workspace=ws))
            self.assertFalse(se.is_in_scope("interchaintest/helpers/peggy.go", workspace=ws))

    def test_load_returns_none_when_absent(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(se.load_inscope_manifest(Path(td)))

    def test_load_returns_none_when_empty(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "inscope_units.jsonl").write_text("\n\n", encoding="utf-8")
            self.assertIsNone(se.load_inscope_manifest(ws))

    def test_manifest_membership_verbatim(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            self._write_manifest(ws, [
                {"file": "modules/exchange/keeper.go", "function": "Foo",
                 "file_line": "modules/exchange/keeper.go:10", "lang": "go"},
                {"file": "contracts/Peggy.sol", "function": "transfer",
                 "file_line": "contracts/Peggy.sol:42", "lang": "solidity"},
            ])
            manifest = se.load_inscope_manifest(ws)
            self.assertEqual(
                manifest,
                {"/modules/exchange/keeper.go", "/contracts/Peggy.sol"},
            )
            # in the manifest => in scope
            self.assertTrue(se.is_in_scope("modules/exchange/keeper.go", workspace=ws))
            self.assertTrue(se.is_in_scope("contracts/Peggy.sol", workspace=ws))
            # NOT in the manifest => NOT in scope (manifest is authoritative)
            self.assertFalse(se.is_in_scope("contracts/OtherUntracked.sol", workspace=ws))

    def test_manifest_listed_oos_is_still_excluded(self):
        # CATEGORICAL-OOS OVERRIDE: an over-collecting intake routinely walks
        # vendored / generated / test files INTO inscope_units.jsonl
        # (@openzeppelin ERC20, *.pb.go, interchaintest/*). is_in_scope must
        # still exclude them - markers are authoritative for exclusion - while
        # keeping the genuine protocol rows. Otherwise every consumer leaks OOS
        # (the real injective manifest had 101 @openzeppelin + 96 .pb.go rows).
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            self._write_manifest(ws, [
                {"file": "modules/peggy/keeper/attestation.go", "function": "Attest",
                 "file_line": "modules/peggy/keeper/attestation.go:10", "lang": "go"},
                {"file": "peggo/solidity/contracts/@openzeppelin/contracts/IERC20.sol",
                 "function": "transfer", "file_line": "x:1", "lang": "solidity"},
                {"file": "modules/exchange/types/order.pb.go", "function": "Reset",
                 "file_line": "x:1", "lang": "go"},
                {"file": "interchaintest/helpers/peggy.go", "function": "Bridge",
                 "file_line": "x:1", "lang": "go"},
            ])
            # genuine protocol row kept...
            self.assertTrue(se.is_in_scope("modules/peggy/keeper/attestation.go", workspace=ws))
            # ...vendored / generated / test rows EXCLUDED despite manifest membership
            self.assertFalse(se.is_in_scope(
                "peggo/solidity/contracts/@openzeppelin/contracts/IERC20.sol", workspace=ws))
            self.assertFalse(se.is_in_scope("modules/exchange/types/order.pb.go", workspace=ws))
            self.assertFalse(se.is_in_scope("interchaintest/helpers/peggy.go", workspace=ws))

    def test_manifest_path_fallback_field(self):
        # legacy rows may use 'path' instead of 'file'
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            self._write_manifest(ws, [
                {"path": "src/main.rs", "function": "", "file_line": "src/main.rs"},
            ])
            self.assertEqual(se.load_inscope_manifest(ws), {"/src/main.rs"})
            self.assertTrue(se.is_in_scope("src/main.rs", workspace=ws))

    def test_no_workspace_falls_back_to_not_oos(self):
        # in-scope source is in scope ...
        self.assertTrue(se.is_in_scope("modules/exchange/keeper.go"))
        # ... an OOS file is not, even without a workspace
        self.assertFalse(se.is_in_scope("test/Foo.sol"))
        self.assertFalse(se.is_in_scope("lib/forge-std/src/Test.sol"))

    def test_missing_manifest_falls_back_not_zero(self):
        # workspace given but no manifest => fall back to not-OOS, NOT a blanket false.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            self.assertTrue(se.is_in_scope("modules/exchange/keeper.go", workspace=ws))
            self.assertFalse(se.is_in_scope("test/Foo.sol", workspace=ws))

    def test_malformed_lines_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            d = ws / ".auditooor"
            d.mkdir()
            (d / "inscope_units.jsonl").write_text(
                "not json at all\n"
                '{"file": "src/good.rs"}\n'
                "[1,2,3]\n"          # valid json, not a dict
                '{"nofield": true}\n',
                encoding="utf-8",
            )
            self.assertEqual(se.load_inscope_manifest(ws), {"/src/good.rs"})


# ---------------------------------------------------------------------------
# Env-hook extension (append-only).
# ---------------------------------------------------------------------------
class ToolArtifactTest(unittest.TestCase):
    """<ws>/.auditooor/ is the funnel's own artifact dir - always OOS."""

    def test_auditooor_dir_is_oos(self):
        self.assertTrue(se.is_tool_artifact(".auditooor/vcis-harness/src/Fuzz.sol"))
        self.assertTrue(se.is_oos(".auditooor/value_moving_functions.json"))
        self.assertTrue(se.is_oos("sub/.auditooor/mutant.sol"))

    def test_real_source_not_artifact(self):
        self.assertFalse(se.is_tool_artifact("src/Market.sol"))
        # A dir merely containing the substring must not match (segment-exact).
        self.assertFalse(se.is_tool_artifact("src/auditooor_helpers/Foo.sol"))


class EnvHookTest(unittest.TestCase):
    def setUp(self):
        self._saved = {}
        for v in (
            "AUDITOOOR_EXTRA_OOS_MARKERS",
            "AUDITOOOR_EXTRA_TEST_MARKERS",
            "AUDITOOOR_EXTRA_VENDORED_MARKERS",
            "AUDITOOOR_EXTRA_GENERATED_MARKERS",
        ):
            self._saved[v] = os.environ.pop(v, None)

    def tearDown(self):
        for v, val in self._saved.items():
            if val is None:
                os.environ.pop(v, None)
            else:
                os.environ[v] = val

    def test_extra_vendored_marker_appends(self):
        p = "deps/mycorp-libs/Foo.sol"
        self.assertFalse(se.is_vendored(p))               # not by default
        os.environ["AUDITOOOR_EXTRA_VENDORED_MARKERS"] = "mycorp-libs"
        self.assertTrue(se.is_vendored(p))                # appended marker fires
        # default markers still present
        self.assertTrue(se.is_vendored("lib/forge-std/src/Test.sol"))

    def test_extra_test_marker_appends_colon_separated(self):
        p = "src/myfuzzdir/Handler.sol"
        self.assertFalse(se.is_test(p))
        os.environ["AUDITOOOR_EXTRA_TEST_MARKERS"] = "ignore_me:myfuzzdir"
        self.assertTrue(se.is_test(p))

    def test_extra_generated_marker_appends(self):
        p = "x/foo/types/state.myorm.go"
        self.assertFalse(se.is_generated(p))
        os.environ["AUDITOOOR_EXTRA_GENERATED_MARKERS"] = ".myorm.go"
        self.assertTrue(se.is_generated(p))

    def test_extra_oos_catch_all_marker(self):
        p = "modules/legacy/old.go"
        self.assertFalse(se.is_oos(p))
        os.environ["AUDITOOOR_EXTRA_OOS_MARKERS"] = "legacy"
        # contributes to every classifier's OOS verdict
        self.assertTrue(se.is_oos(p))
        self.assertTrue(se.is_vendored(p) or se.is_test(p) or se.is_generated(p))


# ---------------------------------------------------------------------------
# Normalisation helpers.
# ---------------------------------------------------------------------------
class NormalisationTest(unittest.TestCase):
    def test_leading_slash_added(self):
        self.assertEqual(se._norm("test/Foo.sol"), "/test/Foo.sol")
        self.assertEqual(se._norm("/test/Foo.sol"), "/test/Foo.sol")

    def test_backslash_and_dotslash(self):
        self.assertEqual(se._norm("./src\\main.rs"), "/src/main.rs")

    def test_collapse_double_slash(self):
        self.assertEqual(se._norm("src//foo//bar.go"), "/src/foo/bar.go")

    def test_empty_and_none_safe(self):
        self.assertEqual(se._norm(""), "/")
        self.assertEqual(se._norm(None), "/")
        # an empty path is not auditable, not OOS-crashing
        self.assertFalse(se.is_auditable_source(""))


# ---------------------------------------------------------------------------
# Compose-with-resolver sanity (root re-derivation pass-through).
# ---------------------------------------------------------------------------
class ResolverCompositionTest(unittest.TestCase):
    def test_resolve_source_roots_returns_paths(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "src").mkdir()
            (ws / "src" / "lib.rs").write_text("pub fn f() {}\n", encoding="utf-8")
            roots = se.resolve_source_roots(ws)
            self.assertTrue(roots)
            self.assertTrue(all(isinstance(r, Path) for r in roots))

    def test_default_source_suffixes_align_with_resolver(self):
        # the module's default suffix set must include the canonical source exts
        for ext in (".go", ".rs", ".sol", ".move", ".cairo"):
            self.assertIn(ext, se.DEFAULT_SOURCE_SUFFIXES)


class HistoricalAndDocMarkersTest(unittest.TestCase):
    def test_previousversions_and_docs_are_oos(self):
        self.assertTrue(se.is_oos("src/agglayer-contracts/contracts/previousVersions/Old.sol"))
        self.assertTrue(se.is_oos("src/agglayer-contracts/docs/contracts/src/Mirror.sol"))

    def test_real_production_contract_not_oos(self):
        self.assertFalse(se.is_oos("src/pos-contracts/contracts/Registry.sol"))
        self.assertFalse(se.is_oos("src/sPOL-contracts/contracts/sPOL.sol"))


class IsOosDirTest(unittest.TestCase):
    """is_oos_dir is directory-shape-only: it must KEEP in-scope fork repos whose
    top-level name matches a vendored project marker (cosmos-sdk/cometbft), and
    drop only vendored-dep DIRS + test/mock/script/docs/historical."""

    def test_keeps_inscope_fork_production_source(self):
        # cosmos-sdk / cometbft are vendored project-NAME markers -> is_oos True,
        # but as in-scope FORK repos their production source must survive is_oos_dir.
        self.assertTrue(se.is_oos("src/cosmos-sdk/x/auth/ante.go"))   # name-marker fires
        self.assertFalse(se.is_oos_dir("src/cosmos-sdk/x/auth/ante.go"))  # but dir-shape keeps it
        self.assertFalse(se.is_oos_dir("src/cometbft/consensus/state.go"))
        self.assertFalse(se.is_oos_dir("src/bor/consensus/bor/bor.go"))

    def test_drops_oos_dirs(self):
        for p in ("src/cosmos-sdk/deps/x/forge.go",
                  "src/sPOL-contracts/dependencies/forge-std/src/Test.sol",
                  "src/agglayer-contracts/contracts/previousVersions/O.sol",
                  "src/pos-contracts/test/X.sol",
                  "src/x/node_modules/@openzeppelin/A.sol"):
            self.assertTrue(se.is_oos_dir(p), f"{p} should be OOS by dir shape")


class NonProdDirPerLanguageTest(unittest.TestCase):
    """LG2-nonprod-dir-per-language: the non-production-dir set is a PER-LANGUAGE
    map + a language-agnostic COMMON set. The COMMON set fires for EVERY language;
    a language-specific name fires ONLY when the path's language matches; an
    unknown language KEEPS everything language-specific (completeness-safe)."""

    # --- the four prompt-mandated invariants -------------------------------
    def test_go_cmd_dir_is_oos(self):
        # Go node-binary convention: cmd/<bin>/main.go drops.
        self.assertTrue(se.is_oos("x/cmd/geth/main.go"))
        self.assertTrue(se.is_nonprod_dir("x/cmd/geth/main.go"))

    def test_cmd_does_not_fire_on_solidity_path(self):
        # CRUCIAL: 'cmd' is a Go convention; a Solidity dir literally named 'cmd'
        # must NOT be dropped (dropping legit contract source = false-green).
        self.assertFalse(se.is_oos("contracts/cmd/Deploy.sol"))
        self.assertFalse(se.is_nonprod_dir("contracts/cmd/Deploy.sol"))

    def test_rust_benches_dir_is_oos(self):
        self.assertTrue(se.is_oos("crate/benches/b.rs"))
        self.assertTrue(se.is_nonprod_dir("crate/benches/b.rs"))

    def test_production_solidity_source_not_oos(self):
        self.assertFalse(se.is_oos("src/Foo.sol"))
        self.assertFalse(se.is_nonprod_dir("src/Foo.sol"))

    # --- COMMON set drops for EVERY language -------------------------------
    def test_common_dirs_drop_for_every_language(self):
        for d in ("test", "tests", "mock", "mocks", "docs"):
            for path in (f"{d}/x.sol", f"{d}/x.go", f"{d}/x.rs",
                         f"{d}/x.move", f"{d}/x.cairo", f"{d}/x.unknownext"):
                self.assertTrue(
                    se.is_nonprod_dir(path),
                    f"common dir {d!r} must drop for every language: {path}")

    # --- language-specific names DO NOT fire across languages --------------
    def test_solidity_script_is_lang_specific(self):
        # 'script' is a Solidity (foundry) convention -> drops a .sol file ...
        self.assertTrue(se.is_nonprod_dir("script/Deploy.sol"))
        self.assertTrue(se.is_nonprod_dir("scripts/Deploy.sol"))
        # ... but a Rust/Move file under a dir literally named 'script' is NOT a
        # foundry script and stays in scope under is_nonprod_dir.
        self.assertFalse(se.is_nonprod_dir("script/main.rs"))
        self.assertFalse(se.is_nonprod_dir("script/lib.move"))

    def test_benches_is_rust_specific(self):
        # benches drops a .rs file ...
        self.assertTrue(se.is_nonprod_dir("crate/benches/b.rs"))
        # ... but a dir literally named 'benches' holding a .sol file is NOT the
        # Rust micro-benchmark convention -> kept by is_nonprod_dir.
        self.assertFalse(se.is_nonprod_dir("contracts/benches/Bench.sol"))

    def test_rust_src_bin_prefix_is_oos(self):
        # Rust binary-target convention src/bin/<name>.rs is a CLI main.
        self.assertTrue(se.is_nonprod_dir("crate/src/bin/cli.rs"))
        # but a bare 'bin' dir is too generic to drop, and a .sol src/bin stays.
        self.assertFalse(se.is_nonprod_dir("contracts/src/bin/Foo.sol"))

    # --- whole-segment matching (no substring false-positives) -------------
    def test_segment_not_substring(self):
        self.assertFalse(se.is_nonprod_dir("src/cmdline/runner.go"),
                         "dir 'cmdline' must not match 'cmd' segment")
        self.assertFalse(se.is_nonprod_dir("src/benchesmark.rs"),
                         "file 'benchesmark.rs' must not match 'benches' segment")
        self.assertFalse(se.is_nonprod_dir("src/scripting.sol"),
                         "file 'scripting.sol' must not match 'scripts' segment")

    # --- explicit lang arg overrides extension detection -------------------
    def test_explicit_lang_arg_overrides_extension(self):
        # A .json file under cmd/ classified as Go via explicit lang= drops.
        self.assertTrue(se.is_nonprod_dir("x/cmd/config.json", lang="go"))
        # And is_oos honours the lang= passthrough.
        self.assertTrue(se.is_oos("x/cmd/config.json", lang="go"))
        # Same path with lang="solidity" does NOT drop on 'cmd'.
        self.assertFalse(se.is_nonprod_dir("x/cmd/config.json", lang="solidity"))

    # --- COMPLETENESS-SAFE: unknown language KEEPS + WARNs -----------------
    def test_unknown_language_keeps_language_specific_with_warn(self):
        # An unmapped extension under a language-specific dir name must be KEPT
        # (completeness-safe) and emit a loud WARN + manual step on stderr.
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            kept = se.is_nonprod_dir("pkg/cmd/main.huff")  # .huff unmapped
        self.assertFalse(kept, "unknown-lang under 'cmd' must be KEPT, not dropped")
        err = buf.getvalue()
        self.assertIn("WARN", err)
        self.assertIn("MANUAL STEP", err)
        self.assertIn("cmd", err)

    def test_unknown_language_common_dir_still_drops_silently(self):
        # A COMMON dir (test) drops for an unknown language with NO warn (it is
        # unambiguously non-production in every ecosystem).
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            dropped = se.is_nonprod_dir("test/x.huff")
        self.assertTrue(dropped)
        self.assertEqual(buf.getvalue(), "", "common-dir drop must not warn")


class HistoricalVersionSnapshotTests(unittest.TestCase):
    """SEI 2026-07-05: version-pinned legacy/vNNN snapshots are non-live (dispatched
    only for historical-block replay; a new tx always runs latestUpgrade), so they
    carry zero live-impact and are OOS for the coverage denominator."""

    def test_legacy_versioned_snapshot_is_oos(self):
        for p in (
            "src/sei-chain/precompiles/bank/legacy/v552/precompiles.go",
            "src/sei-chain/precompiles/common/legacy/v600/precompiles.go",
            "precompiles/staking/legacy/v6/staking.go",
            "x/foo/previousVersions/v3/impl.sol",
        ):
            self.assertTrue(se.is_oos_dir(p), f"{p} must be OOS (historical snapshot)")

    def test_live_precompile_not_dropped(self):
        for p in (
            "src/sei-chain/precompiles/bank/setup.go",   # the version dispatcher
            "src/sei-chain/precompiles/bank/bank.go",    # the live impl
        ):
            self.assertFalse(se.is_oos_dir(p), f"{p} is live and must stay in scope")

    def test_plain_legacy_dir_without_version_is_kept(self):
        # Precise: a dir literally named `legacy` with NO version-numbered child is
        # NOT auto-dropped (avoids over-exclusion of a real `legacy/` module).
        self.assertFalse(se.is_oos_dir("src/pkg/legacy/helper.go"))

    def test_public_historical_snapshot_predicate(self):
        # The shared predicate the function-coverage denominator also consumes.
        self.assertTrue(se.is_historical_version_snapshot(
            "src/sei-chain/precompiles/distribution/legacy/v552/distribution.go"))
        self.assertTrue(se.is_historical_version_snapshot(
            "x/foo/previousVersions/v3/impl.go"))
        self.assertFalse(se.is_historical_version_snapshot(
            "src/sei-chain/precompiles/distribution/distribution.go"))
        self.assertFalse(se.is_historical_version_snapshot("src/pkg/legacy/helper.go"))


if __name__ == "__main__":
    unittest.main()
