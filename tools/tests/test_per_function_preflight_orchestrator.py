import json
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import importlib.util


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "per-function-preflight-orchestrator.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("per_function_preflight_orchestrator", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PerFunctionPreflightOrchestratorTest(unittest.TestCase):
    def test_build_pack_records_mcp_blocks_and_local_shape(self):
        tool = load_tool()
        invariant = tool.load_invariant_module(ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Vault {
    uint256 public total;
    function deposit(uint256 amount) external { total += amount; }
}
""",
                encoding="utf-8",
            )
            manifest_dir = ws / "poc-tests" / "per_function_invariants"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "contract": "Vault",
                                "function": "deposit",
                                "harness_path": str(manifest_dir / "Halmos_Vault_deposit.t.sol"),
                                "halmos_invocation": {"match_contract": "Halmos_Vault_deposit"},
                                "status": "written",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            files = invariant.discover_solidity_files(ws, None)
            functions = invariant.parse_functions(ws, files, include_internal=False, function_filter=None)
            self.assertEqual(len(functions), 1)

            def fake_call(_repo_root, call, args, _timeout):
                return {"status": "ok", "call": call, "payload": {"selector": args["contract"] + "." + args["function"]}}

            with patch.object(tool, "call_vault", side_effect=fake_call):
                pack = tool.build_pack(ROOT, ws, functions[0], timeout=1, llm_enrich=False)

            self.assertEqual(pack["schema"], "auditooor.pre_flight_pack.v1")
            self.assertEqual(pack["selector"], "Vault.deposit")
            self.assertEqual(pack["function_shape_local"]["source_ref"] if "source_ref" in pack["function_shape_local"] else pack["source_ref"], "src/Vault.sol:5")
            self.assertEqual(set(pack["mcp_context"].keys()), set(tool.MCP_CALLS))
            self.assertTrue(all(block["status"] == "ok" for block in pack["mcp_context"].values()))
            self.assertIn("function_shape", pack)
            self.assertIn("attack_class_evidence", pack)
            self.assertIn("per_function_hunter_brief", pack)
            self.assertIn("chain_candidates", pack)
            self.assertIn("invariants_touched", pack)
            self.assertIn("anti_patterns", pack)
            self.assertIn("dead_ends_scoped", pack)
            self.assertIn("local_harness_manifest_references", pack)
            self.assertEqual(
                pack["local_harness_manifest_references"][0]["halmos_invocation"]["match_contract"],
                "Halmos_Vault_deposit",
            )
            self.assertEqual(pack["llm_enriched_hypotheses"]["status"], "disabled")

    def test_llm_enrich_without_live_env_is_explicit_skip(self):
        tool = load_tool()
        invariant = tool.load_invariant_module(ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Vault {
    function deposit(uint256 amount) external {}
}
""",
                encoding="utf-8",
            )
            fn = invariant.parse_functions(
                ws,
                invariant.discover_solidity_files(ws, None),
                include_internal=False,
                function_filter=None,
            )[0]

            def fake_call(_repo_root, call, args, _timeout):
                return {"status": "ok", "call": call, "payload": {"call": call, "args": args}}

            with patch.dict("os.environ", {}, clear=True), patch.object(tool, "call_vault", side_effect=fake_call):
                pack = tool.build_pack(ROOT, ws, fn, timeout=1, llm_enrich=True)

            self.assertEqual(pack["llm_enriched_hypotheses"]["status"], "skipped")
            self.assertEqual(pack["llm_enriched_hypotheses"]["mode"], "safe-dry-run")
            self.assertFalse(pack["llm_enriched_hypotheses"]["dispatch_invoked"])

    def test_cli_dry_run_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "contracts"
            src.mkdir()
            (src / "Token.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Token {
    function mint(address to, uint256 amount) public {}
}
""",
                encoding="utf-8",
            )
            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--dry-run", "--json", "--mcp-timeout", "1"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads(proc.stdout)
            self.assertEqual(manifest["schema"], "auditooor.pre_flight_pack_manifest.v1")
            self.assertEqual(manifest["pack_count"], 1)
            self.assertEqual(manifest["packs"][0]["status"], "would-write")
            self.assertFalse((ws / ".auditooor" / "pre_flight_packs" / "manifest.json").exists())

    def test_dry_run_manifest_reports_capped_function_coverage(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "contracts"
            src.mkdir()
            (src / "Token.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Token {
    function mint(address to, uint256 amount) public {}
    function burn(uint256 amount) public {}
    function transfer(address to, uint256 amount) public {}
}
""",
                encoding="utf-8",
            )

            def fake_call(_repo_root, call, args, _timeout):
                return {"status": "ok", "call": call, "payload": args}

            out = io.StringIO()
            with patch.object(tool, "call_vault", side_effect=fake_call), redirect_stdout(out):
                rc = tool.main([
                    "--workspace", str(ws),
                    "--dry-run",
                    "--json",
                    "--max-functions", "2",
                    "--mcp-timeout", "1",
                ])
            self.assertEqual(rc, 0)
            manifest = json.loads(out.getvalue())
        coverage = manifest["function_coverage"]
        self.assertEqual(coverage["total_in_scope"], 3)
        self.assertEqual(coverage["processed"], 2)
        self.assertEqual(coverage["max_functions"], 2)
        self.assertTrue(coverage["capped"])
        self.assertEqual(coverage["not_processed"], 1)
        self.assertEqual(coverage["function_denominator_status"], "capped")
        self.assertFalse(coverage["denominator_complete"])
        self.assertIn("MAX_FUNCTIONS=0", coverage["full_coverage_hint"])

    def test_dry_run_manifest_reports_mixed_solidity_and_rust_denominator(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            contracts = src / "contracts"
            contracts.mkdir(parents=True)
            (contracts / "Token.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Token {
    function mint(address to, uint256 amount) public {}
}
""",
                encoding="utf-8",
            )
            (ws / "src" / "api.rs").write_text("pub fn get_info() {}\n", encoding="utf-8")
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "rust_source_graph.json").write_text(
                json.dumps(
                    {
                        "_meta": {
                            "schema_version": "auditooor.rust_source_graph.v1",
                            "workspace": str(ws),
                            "crate_count": 1,
                        },
                        "demo-rpc": {
                            "crate_root": "src",
                            "entrypoints": [
                                {
                                    "file": "src/api.rs",
                                    "fn": "get_info",
                                    "kind": "jsonrpsee_method",
                                    "line": 1,
                                }
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )

            def fake_call(_repo_root, call, args, _timeout):
                return {"status": "ok", "call": call, "payload": args}

            out = io.StringIO()
            with patch.object(tool, "call_vault", side_effect=fake_call), redirect_stdout(out):
                rc = tool.main([
                    "--workspace", str(ws),
                    "--dry-run",
                    "--json",
                    "--mcp-timeout", "1",
                ])
            self.assertEqual(rc, 0)
            manifest = json.loads(out.getvalue())
        self.assertEqual(manifest["pack_count"], 1)
        coverage = manifest["function_coverage"]
        self.assertEqual(coverage["total_in_scope"], 2)
        self.assertEqual(coverage["processable_total"], 1)
        self.assertEqual(coverage["processed"], 1)
        self.assertEqual(coverage["selected_discovery_source"], "solidity")
        self.assertEqual(coverage["discovered_function_counts"]["solidity"], 1)
        self.assertEqual(coverage["discovered_function_counts"]["rust_graph"], 1)
        self.assertEqual(coverage["not_selected_discovered"], 1)
        self.assertEqual(coverage["not_processed"], 1)
        self.assertEqual(coverage["function_denominator_status"], "partial")
        self.assertFalse(coverage["denominator_complete"])

    def test_scoped_solidity_discovery_excludes_poc_and_test_artifacts(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            in_scope = ws / "src" / "src"
            in_scope.mkdir(parents=True)
            (in_scope / "Market.sol").write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Market {\n"
                "    function supply(uint256 assets) external {}\n"
                "}\n",
                encoding="utf-8",
            )
            poc = ws / ".auditooor" / "poc"
            poc.mkdir(parents=True)
            (poc / "Helper.sol").write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Helper {\n"
                "    function helper() external {}\n"
                "}\n",
                encoding="utf-8",
            )
            tests = ws / "test"
            tests.mkdir()
            (tests / "Market.t.sol").write_text(
                "pragma solidity ^0.8.20;\n"
                "contract MarketTest {\n"
                "    function testSupply() external {}\n"
                "}\n",
                encoding="utf-8",
            )

            def fake_call(_repo_root, call, args, _timeout):
                return {"status": "ok", "call": call, "payload": args}

            out = io.StringIO()
            with patch.object(tool, "call_vault", side_effect=fake_call), redirect_stdout(out):
                rc = tool.main([
                    "--workspace", str(ws),
                    "--dry-run",
                    "--json",
                    "--mcp-timeout", "1",
                    "--max-functions", "0",
                ])
            self.assertEqual(rc, 0)
            manifest = json.loads(out.getvalue())
        self.assertEqual(manifest["pack_count"], 1)
        self.assertEqual(manifest["packs"][0]["contract"], "Market")
        self.assertEqual(manifest["packs"][0]["function"], "supply")
        self.assertEqual(manifest["packs"][0]["source_ref"], "src/src/Market.sol:3")
        coverage = manifest["function_coverage"]
        self.assertEqual(coverage["total_in_scope"], 1)
        self.assertEqual(coverage["processed"], 1)
        self.assertEqual(coverage["selected_discovery_source"], "solidity")
        self.assertEqual(coverage["solidity_discovery"]["source"], "workspace-coverage-heatmap")
        self.assertEqual(coverage["solidity_discovery"]["solidity_file_count"], 1)
        self.assertTrue(coverage["denominator_complete"])

    def test_scoped_solidity_discovery_preserves_contract_and_function_filters(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Alpha.sol").write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Alpha {\n"
                "    function first() external {}\n"
                "    function second() external {}\n"
                "}\n",
                encoding="utf-8",
            )
            (src / "Beta.sol").write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Beta {\n"
                "    function second() external {}\n"
                "}\n",
                encoding="utf-8",
            )
            poc = ws / ".auditooor" / "poc"
            poc.mkdir(parents=True)
            (poc / "Alpha.sol").write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Alpha {\n"
                "    function second() external {}\n"
                "}\n",
                encoding="utf-8",
            )

            def fake_call(_repo_root, call, args, _timeout):
                return {"status": "ok", "call": call, "payload": args}

            out = io.StringIO()
            with patch.object(tool, "call_vault", side_effect=fake_call), redirect_stdout(out):
                rc = tool.main([
                    "--workspace", str(ws),
                    "--contract", "Alpha",
                    "--function", "second",
                    "--dry-run",
                    "--json",
                    "--mcp-timeout", "1",
                ])
            self.assertEqual(rc, 0)
            manifest = json.loads(out.getvalue())
        self.assertEqual(manifest["pack_count"], 1)
        self.assertEqual(manifest["packs"][0]["contract"], "Alpha")
        self.assertEqual(manifest["packs"][0]["function"], "second")
        self.assertEqual(manifest["packs"][0]["source_ref"], "src/Alpha.sol:4")
        coverage = manifest["function_coverage"]
        self.assertEqual(coverage["total_in_scope"], 1)
        self.assertEqual(coverage["processable_total"], 1)
        self.assertTrue(coverage["denominator_complete"])

    def test_dry_run_manifest_reports_go_only_as_unsupported_denominator(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "keeper.go").write_text(
                "package main\nfunc Foo() {}\nfunc Bar() {}\n",
                encoding="utf-8",
            )
            out = io.StringIO()
            with redirect_stdout(out):
                rc = tool.main([
                    "--workspace", str(ws),
                    "--dry-run",
                    "--json",
                    "--mcp-timeout", "1",
                ])
            self.assertEqual(rc, 0)
            manifest = json.loads(out.getvalue())
        self.assertEqual(manifest["pack_count"], 0)
        coverage = manifest["function_coverage"]
        self.assertEqual(coverage["total_in_scope"], 0)
        self.assertEqual(coverage["processable_total"], 0)
        self.assertEqual(coverage["processed"], 0)
        self.assertEqual(coverage["selected_discovery_source"], "none")
        self.assertEqual(coverage["discovered_function_counts"], {"rust_graph": 0, "solidity": 0})
        self.assertEqual(coverage["unsupported_language_file_counts"], {"go": 1})
        self.assertEqual(coverage["function_denominator_status"], "source-unit-only")
        self.assertFalse(coverage["denominator_complete"])

    def test_dry_run_manifest_reports_malformed_rust_source_refs(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "rust_source_graph.json").write_text(
                json.dumps(
                    {
                        "_meta": {"schema_version": "auditooor.rust_source_graph.v1"},
                        "demo-rpc": {
                            "entrypoints": [
                                {
                                    "file": "src/missing.rs",
                                    "fn": "get_info",
                                    "line": 42,
                                }
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )

            out = io.StringIO()
            with redirect_stdout(out):
                rc = tool.main([
                    "--workspace", str(ws),
                    "--dry-run",
                    "--json",
                    "--mcp-timeout", "1",
                ])
            self.assertEqual(rc, 0)
            manifest = json.loads(out.getvalue())
        coverage = manifest["function_coverage"]
        self.assertEqual(manifest["pack_count"], 0)
        self.assertEqual(coverage["total_in_scope"], 1)
        self.assertEqual(coverage["processable_total"], 0)
        self.assertEqual(coverage["malformed_source_ref_count"], 1)
        self.assertEqual(coverage["malformed_source_refs"][0]["source_ref"], "src/missing.rs:42")
        self.assertEqual(coverage["malformed_source_refs"][0]["reason"], "missing-source-file")
        self.assertEqual(coverage["function_denominator_status"], "malformed-source-refs")
        self.assertFalse(coverage["denominator_complete"])

    def test_non_dry_run_removes_stale_pack_files_before_manifest_is_clean(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "contracts"
            src.mkdir()
            (src / "Token.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Token {
    function mint(address to, uint256 amount) public {}
}
""",
                encoding="utf-8",
            )
            output_dir = ws / ".auditooor" / "pre_flight_packs"
            output_dir.mkdir(parents=True)
            stale_pack = output_dir / "pre_flight_pack_Old_old.json"
            stale_pack.write_text('{"stale": true}\n', encoding="utf-8")

            def fake_call(_repo_root, call, args, _timeout):
                return {"status": "ok", "call": call, "payload": args}

            out = io.StringIO()
            with patch.object(tool, "call_vault", side_effect=fake_call), redirect_stdout(out):
                rc = tool.main([
                    "--workspace", str(ws),
                    "--json",
                    "--mcp-timeout", "1",
                ])
            self.assertEqual(rc, 0)
            manifest = json.loads(out.getvalue())
        self.assertFalse(stale_pack.exists())
        coverage = manifest["function_coverage"]
        self.assertEqual(coverage["stale_pack_count_removed"], 1)
        self.assertIn(str(stale_pack.resolve()), coverage["stale_pack_paths_removed"])
        self.assertEqual(manifest["pack_count"], 1)

    def test_targeted_run_includes_read_only_function_and_preserves_other_packs(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "contracts"
            src.mkdir()
            (src / "Ratifier.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Ratifier {
    mapping(bytes32 => bool) public isRootRatified;
    function setRoot(bytes32 root, bool value) external { isRootRatified[root] = value; }
    function isRatified(bytes32 root) external view returns (bool) { return isRootRatified[root]; }
}
""",
                encoding="utf-8",
            )
            output_dir = ws / ".auditooor" / "pre_flight_packs"
            output_dir.mkdir(parents=True)
            existing_pack = output_dir / "pre_flight_pack_Ratifier_setRoot.json"
            existing_pack.write_text('{"existing": true}\n', encoding="utf-8")

            def fake_call(_repo_root, call, args, _timeout):
                return {"status": "ok", "call": call, "payload": args}

            out = io.StringIO()
            with patch.object(tool, "call_vault", side_effect=fake_call), redirect_stdout(out):
                rc = tool.main([
                    "--workspace", str(ws),
                    "--contract", "Ratifier",
                    "--function", "isRatified",
                    "--json",
                    "--mcp-timeout", "1",
                ])
            self.assertEqual(rc, 0)
            manifest = json.loads(out.getvalue())
            self.assertTrue(existing_pack.exists())
            self.assertEqual(manifest["pack_count"], 1)
            self.assertEqual(manifest["packs"][0]["function"], "isRatified")
            coverage = manifest["function_coverage"]
            self.assertEqual(coverage["stale_pack_count_removed"], 0)
            self.assertEqual(coverage["stale_pack_cleanup_skipped"], "targeted-filter")
            self.assertEqual(coverage["total_in_scope"], 1)
            self.assertEqual(coverage["processable_total"], 1)

    def test_cli_dry_run_rust_graph_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir()
            src_file = ws / "src" / "zebra-rpc" / "src" / "methods.rs"
            src_file.parent.mkdir(parents=True)
            src_file.write_text("\n" * 193 + "pub fn get_info() {}\n", encoding="utf-8")
            (aud / "rust_source_graph.json").write_text(
                json.dumps(
                    {
                        "_meta": {
                            "schema_version": "auditooor.rust_source_graph.v1",
                            "workspace": str(ws),
                            "crate_count": 1,
                        },
                        "zebra-rpc": {
                            "crate_root": "src/zebra-rpc/src/lib.rs",
                            "entrypoints": [
                                {
                                    "attrs": ["method", "rpc:getinfo"],
                                    "cfg_attrs": [],
                                    "file": "src/zebra-rpc/src/methods.rs",
                                    "fn": "get_info",
                                    "kind": "jsonrpsee_method",
                                    "line": 194,
                                }
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--dry-run",
                    "--json",
                    "--mcp-timeout",
                    "1",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads(proc.stdout)
            self.assertEqual(manifest["schema"], "auditooor.pre_flight_pack_manifest.v1")
            self.assertEqual(manifest["pack_count"], 1)
            self.assertEqual(manifest["packs"][0]["contract"], "zebra-rpc")
            self.assertEqual(manifest["packs"][0]["function"], "get_info")
            self.assertEqual(manifest["packs"][0]["source_ref"], "src/zebra-rpc/src/methods.rs:194")
            self.assertEqual(manifest["packs"][0]["status"], "would-write")
            self.assertFalse((ws / ".auditooor" / "pre_flight_packs" / "manifest.json").exists())

    def test_cli_dry_run_rust_graph_contract_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir()
            epoch_file = ws / "src" / "chain" / "epoch-manager" / "src" / "lib.rs"
            epoch_file.parent.mkdir(parents=True)
            epoch_file.write_text("\n" * 881 + "pub fn record_block_info() {}\n", encoding="utf-8")
            jsonrpc_file = ws / "src" / "chain" / "jsonrpc" / "src" / "methods.rs"
            jsonrpc_file.parent.mkdir(parents=True)
            jsonrpc_file.write_text("\n" * 832 + "pub fn status() {}\n", encoding="utf-8")
            (aud / "rust_source_graph.json").write_text(
                json.dumps(
                    {
                        "_meta": {
                            "schema_version": "auditooor.rust_source_graph.v1",
                            "workspace": str(ws),
                            "crate_count": 2,
                        },
                        "near-epoch-manager": {
                            "crate_root": "src/chain/epoch-manager",
                            "entrypoints": [
                                {
                                    "attrs": [],
                                    "cfg_attrs": [],
                                    "file": "src/chain/epoch-manager/src/lib.rs",
                                    "fn": "record_block_info",
                                    "kind": "lib_rs_pub",
                                    "line": 882,
                                }
                            ],
                        },
                        "near-jsonrpc": {
                            "crate_root": "src/chain/jsonrpc",
                            "entrypoints": [
                                {
                                    "attrs": [],
                                    "cfg_attrs": [],
                                    "file": "src/chain/jsonrpc/src/methods.rs",
                                    "fn": "status",
                                    "kind": "lib_rs_pub",
                                    "line": 833,
                                }
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--contract",
                    "jsonrpc",
                    "--dry-run",
                    "--json",
                    "--mcp-timeout",
                    "1",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads(proc.stdout)
            self.assertEqual(manifest["schema"], "auditooor.pre_flight_pack_manifest.v1")
            self.assertEqual(manifest["pack_count"], 1)
            self.assertEqual(manifest["packs"][0]["contract"], "near-jsonrpc")
            self.assertEqual(manifest["packs"][0]["function"], "status")
            self.assertEqual(manifest["packs"][0]["source_ref"], "src/chain/jsonrpc/src/methods.rs:833")
            self.assertFalse((ws / ".auditooor" / "pre_flight_packs" / "manifest.json").exists())

    def test_parallel_path_writes_one_pack_per_function_in_order(self):
        # The default (unbounded) sweep parallelizes per-function pack building.
        # It must (a) write exactly one pack per in-scope function with no loss or
        # filename collision, and (b) keep manifest rows in the original function
        # order. Each pack does ~10 MCP calls; here call_vault is mocked so the
        # test exercises the threadpool wiring, not the live vault.
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "contracts"
            src.mkdir()
            # Several contracts, each with a couple of external state-changing
            # functions -> distinct pack filenames.
            (src / "Aaa.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Aaa {\n"
                "  function a1(uint256 x) external {}\n"
                "  function a2(uint256 x) external {}\n}\n",
                encoding="utf-8",
            )
            (src / "Bbb.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Bbb {\n"
                "  function b1(uint256 x) external {}\n"
                "  function b2(uint256 x) external {}\n"
                "  function b3(uint256 x) external {}\n}\n",
                encoding="utf-8",
            )
            (src / "Ccc.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Ccc {\n"
                "  function c1(uint256 x) external {}\n}\n",
                encoding="utf-8",
            )

            def fake_call(_repo_root, call, args, _timeout):
                return {"status": "ok", "call": call, "payload": args}

            out = io.StringIO()
            # Force >1 worker so the parallel branch is genuinely exercised.
            with patch.dict("os.environ", {"AUDITOOOR_PREFLIGHT_WORKERS": "4"}), \
                    patch.object(tool, "call_vault", side_effect=fake_call), \
                    redirect_stdout(out):
                rc = tool.main([
                    "--workspace", str(ws),
                    "--json",
                    "--mcp-timeout", "1",
                ])
            self.assertEqual(rc, 0)
            manifest = json.loads(out.getvalue())
            # 6 external state-changing functions total -> 6 packs, no loss.
            self.assertEqual(manifest["pack_count"], 6)
            pack_files = sorted(
                p.name for p in (ws / ".auditooor" / "pre_flight_packs").glob(
                    "pre_flight_pack_*.json"
                )
            )
            self.assertEqual(len(pack_files), 6, pack_files)
            # Order preserved: manifest rows match the discovery order exactly.
            rows = manifest["packs"]
            self.assertEqual(
                [(r["contract"], r["function"]) for r in rows],
                [("Aaa", "a1"), ("Aaa", "a2"), ("Bbb", "b1"), ("Bbb", "b2"),
                 ("Bbb", "b3"), ("Ccc", "c1")],
            )
            self.assertTrue(all(r["status"] == "written" for r in rows))

    def test_total_budget_default_is_unbounded(self):
        # An audit must build a pack for EVERY in-scope function - the default
        # total-budget must be 0 (unbounded), not a wall-clock cap that silently
        # skips part of the coverage surface.
        import os as _os
        env = dict(_os.environ)
        env.pop("AUDITOOOR_PREFLIGHT_TOTAL_BUDGET", None)
        out = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            capture_output=True, text=True, env=env, timeout=30,
        ).stdout
        self.assertIn("UNBOUNDED", out)
        self.assertNotIn("Default 1200", out)


if __name__ == "__main__":
    unittest.main()
