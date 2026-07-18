#!/usr/bin/env python3
"""Tests for tools/workspace-scan-orchestrator.py manifest helpers."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "workspace-scan-orchestrator.py"
ENGAGE = REPO_ROOT / "tools" / "engage.py"
SCAN_SH = REPO_ROOT / "tools" / "scan.sh"
W68_COSMOS_FIXTURE = (
    REPO_ROOT
    / "detectors"
    / "fixtures"
    / "w68_consensus_param_corruption_no_validate"
    / "positive"
)


def load_tool():
    spec = importlib.util.spec_from_file_location("workspace_scan_orchestrator", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_engage():
    tools_dir = str(REPO_ROOT / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("engage_for_cosmos_scan_test", ENGAGE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Solidity snippet that matches the pool-liveness advisory shape patterns:
# PoolKey init + factory create + later swap action.
_POOL_SHAPE_SOL = """\
pragma solidity ^0.8.20;
struct PoolKey { address token0; address token1; address hooks; }
contract PoolFactory {
    IPoolManager poolManager;
    function createPool(PoolKey memory key, uint24 fee, uint256 ampConfig)
        external
    {
        poolManager.initialize(key, fee, ampConfig);
    }
    function swap(bytes calldata data) external {
        poolManager.swap(data);
    }
}
interface IPoolManager {
    function initialize(PoolKey memory key, uint24 fee, uint256 ampConfig) external;
    function swap(bytes calldata data) external;
}
"""



class WorkspaceScanOrchestratorManifestTest(unittest.TestCase):
    def test_select_slither_python_prefers_importable_candidate(self) -> None:
        tool = load_tool()
        calls: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0 if argv[0] == "/good/python" else 1, "", "")

        with mock.patch.dict(os.environ, {"AUDITOOOR_PYTHON_SLITHER": "/bad/python"}):
            with mock.patch.object(tool.sys, "executable", "/also/bad"):
                with mock.patch.object(tool, "slither_python_candidates", return_value=["/bad/python", "/also/bad", "/good/python"]):
                    with mock.patch.object(tool.subprocess, "run", side_effect=fake_run):
                        self.assertEqual(tool.select_slither_python(), "/good/python")

        self.assertEqual([call[0] for call in calls], ["/bad/python", "/also/bad", "/good/python"])

    def test_solidity_scan_target_prefers_ready_source_root(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            root = ws / "external" / "reserve-governor"
            root.mkdir(parents=True)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (root / "contracts").mkdir()
            (root / "contracts" / "A.sol").write_text("contract A {}\n", encoding="utf-8")
            auditooor = ws / ".auditooor"
            auditooor.mkdir()
            (auditooor / "project_source_root_readiness.json").write_text(
                json.dumps(
                    {
                        "roots": [
                            {
                                "usable": True,
                                "workspace_relative_path": "external/reserve-governor",
                                "language_presence": {"solidity": 1, "rust": 0},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(tool.solidity_scan_target(ws), root)

    def test_skipped_compilation_counts_from_status_and_logs(self) -> None:
        tool = load_tool()
        counts = tool.skipped_compilation_counts(
            {
                "detectors/run_custom.py": "RC=1",
                "tools/rust-detect.py": "SKIPPED (missing)",
                "tools/circom-detect.py": "SKIPPED (no .circom)",
            },
            {
                "detectors/run_custom.py": "\n".join(
                    [
                        "[error] Slither compile failed: boom",
                        "=== module: Vault (FAILED exit=1, see custom-detectors-errors.log) ===",
                        "Modules failed     : 2",
                    ]
                )
            },
        )
        self.assertEqual(counts["skipped_tools"], 1)
        self.assertEqual(counts["compile_failure_markers"], 2)
        self.assertEqual(counts["modules_failed"], 2)
        self.assertEqual(counts["total"], 5)

    def test_environment_manifest_contract(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            out = root / "out"
            ws.mkdir()
            out.mkdir()

            original_command_version = tool.command_version
            try:
                tool.command_version = lambda argv: f"{argv[0]}-fixture"
                manifest_path = tool.write_environment_manifest(
                    out,
                    ws,
                    {"sol"},
                    {"detectors/run_custom.py": "SKIPPED (missing)"},
                    {"detectors/run_custom.py": "compile failed"},
                )
            finally:
                tool.command_version = original_command_version

            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "auditooor.detector_environment.v1")
            self.assertEqual(payload["workspace"], str(ws))
            self.assertEqual(payload["languages_detected"], ["sol"])
            self.assertEqual(payload["versions"]["slither"], "slither-fixture")
            self.assertEqual(payload["versions"]["solc"], "solc-fixture")
            self.assertEqual(payload["tool_status"]["detectors/run_custom.py"], "SKIPPED (missing)")
            self.assertEqual(payload["skipped_compilation_counts"]["skipped_tools"], 1)
            self.assertEqual(payload["skipped_compilation_counts"]["compile_failure_markers"], 1)
            advisory_block = payload["scanner_promotion_advisories"]
            self.assertEqual(advisory_block["artifact"], "scanner_promotion_advisories.json")
            self.assertEqual(
                advisory_block["artifact_path"],
                str(out / "scanner_promotion_advisories.json"),
            )
            self.assertEqual(
                advisory_block["artifact_relative_to_manifest"],
                "scanner_promotion_advisories.json",
            )

    def test_scan_report_surfaces_skipped_compilation_counts(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            out = root / "out"
            ws.mkdir()
            report = tool.write_report(
                out,
                ws,
                [],
                {"detectors/run_custom.py": "RC=1"},
                {
                    "skipped_tools": 1,
                    "compile_failure_markers": 2,
                    "modules_failed": 3,
                    "total": 6,
                },
            )

            text = report.read_text(encoding="utf-8")
            self.assertIn("Skipped/failed compilation coverage", text)
            self.assertIn("total=6", text)
            self.assertIn("skipped_tools=1", text)
            self.assertIn("compile_failure_markers=2", text)
            self.assertIn("modules_failed=3", text)

    def test_low_config_liveness_shape_emits_needs_poc_advisory(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            src = ws / "src"
            src.mkdir(parents=True)
            (src / "RevertLikeFactory.sol").write_text(
                """
                pragma solidity ^0.8.20;

                struct PoolKey { address token0; address token1; address hooks; }

                contract RevertLikeFactory {
                    IPoolManager poolManager;

                    function createPool(PoolKey memory key, uint24 fee, uint256 ampConfig)
                        external
                    {
                        poolManager.initialize(key, fee, ampConfig);
                    }

                    function swap(bytes calldata data) external {
                        poolManager.swap(data);
                    }
                }

                interface IPoolManager {
                    function initialize(PoolKey memory key, uint24 fee, uint256 ampConfig) external;
                    function swap(bytes calldata data) external;
                }
                """,
                encoding="utf-8",
            )

            rows = tool.find_low_config_liveness_advisories(
                ws,
                [("m02-initial-fee-rates-and-amplification-coefficient", "LOW")],
            )

            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["kind"], "capability_gap")
            self.assertEqual(row["promotion_status"], "needs_poc")
            self.assertEqual(row["severity_floor"], "LOW")
            self.assertFalse(row["severity_promotion_allowed"])
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(row["submit_ready"])
            self.assertTrue(row["impact_contract_required"])
            self.assertEqual(row["impact_contract_summary"]["status"], "not_required")
            self.assertEqual(row["shape"], "factory_constructor_pool_liveness_config")
            self.assertIn("later_swap_or_liquidity_action", row["signals"])
            self.assertTrue(any("Foundry PoC" in cmd for cmd in row["next_commands"]))

            out = ws / "out"
            report = tool.write_report(
                out,
                ws,
                [("m02-initial-fee-rates-and-amplification-coefficient", "LOW")],
                {"detectors/run_custom.py": "OK"},
                scanner_promotion_advisories=rows,
            )
            text = report.read_text(encoding="utf-8")
            self.assertIn("## Low-hit promotion advisories", text)
            self.assertIn("needs_poc", text)
            self.assertIn("capability_gap", text)


    def test_solidity_sources_excludes_test_and_script_files(self) -> None:
        """_solidity_sources() must exclude .t.sol and .s.sol files.

        Before the fix, test/Token.t.sol and script/Deploy.s.sol both matched
        the pool-liveness advisory shape and generated spurious advisories.
        After the fix, only src/Token.sol generates an advisory.
        """
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "test").mkdir(parents=True)
            (ws / "script").mkdir(parents=True)

            # Production file - must be included and produce an advisory
            (ws / "src" / "Token.sol").write_text(_POOL_SHAPE_SOL, encoding="utf-8")
            # Foundry test file - must be excluded, must NOT produce an advisory
            (ws / "test" / "Token.t.sol").write_text(_POOL_SHAPE_SOL, encoding="utf-8")
            # Foundry script file - must be excluded, must NOT produce an advisory
            (ws / "script" / "Deploy.s.sol").write_text(_POOL_SHAPE_SOL, encoding="utf-8")

            rows = tool.find_low_config_liveness_advisories(
                ws,
                [("m02-initial-fee-rates-and-amplification-coefficient", "LOW")],
            )

            # Only the production file must generate an advisory - exactly 1
            advisory_files = [r["file"].replace("\\", "/") for r in rows]
            self.assertEqual(
                len(rows),
                1,
                "Expected exactly 1 advisory (from src/Token.sol) but got "
                f"{len(rows)}: {advisory_files}",
            )

            # The advisory must reference the production file
            self.assertIn(
                "src/Token.sol",
                advisory_files[0],
                f"Advisory file must point to src/Token.sol; got {advisory_files[0]!r}",
            )

            # Explicit: no advisory must reference a .t.sol or .s.sol file
            t_sol_advisories = [f for f in advisory_files if f.endswith(".t.sol")]
            self.assertEqual(
                t_sol_advisories,
                [],
                f"No advisory should reference a .t.sol test file; got {t_sol_advisories}",
            )
            s_sol_advisories = [f for f in advisory_files if f.endswith(".s.sol")]
            self.assertEqual(
                s_sol_advisories,
                [],
                f"No advisory should reference a .s.sol script file; got {s_sol_advisories}",
            )

    def test_is_vendored_sol_excludes_non_production_dirs(self) -> None:
        """_is_vendored_sol must exclude in-tree OOS/non-production directories
        (docs/ mirrors, mocks/, test(s)/, previousVersions/) - which routinely
        DUPLICATE the real contracts/ tree - while keeping genuine contract
        sources, including a file merely NAMED Mock*.sol under contracts/."""
        tool = load_tool()
        from pathlib import Path as _P
        excluded = [
            "docs/contracts/src/contracts/PolygonZkEVMBridge.sol",
            "contracts/mocks/VerifierRollupHelperMock.sol",
            "contracts/mock/Foo.sol",
            "contracts/previousVersions/OldManager.sol",
            "test/Token.sol",
            "tests/Token.sol",
            "node_modules/@openzeppelin/contracts/Ownable.sol",
        ]
        for rel in excluded:
            self.assertTrue(tool._is_vendored_sol(_P(rel)),
                            f"{rel} must be excluded as vendored/non-production")
        kept = [
            "contracts/PolygonRollupManager.sol",
            "contracts/v2/PolygonZkEVMBridgeV2.sol",
            "src/PolygonMigration.sol",
            "contracts/MockableToken.sol",  # file named Mock*, but under contracts/ - keep
        ]
        for rel in kept:
            self.assertFalse(tool._is_vendored_sol(_P(rel)),
                             f"{rel} is a production source and must be kept")

    def test_low_config_liveness_requires_relevant_low_detector(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            src = ws / "src"
            src.mkdir(parents=True)
            (src / "RevertLikeFactory.sol").write_text(
                """
                pragma solidity ^0.8.20;
                struct PoolKey { address token0; address token1; address hooks; }
                contract RevertLikeFactory {
                    function createPool(PoolKey memory key, uint24 fee) external {
                        IPoolManager(address(0)).initialize(key, fee);
                    }
                    function addLiquidity(bytes calldata data) external {}
                }
                interface IPoolManager {
                    function initialize(PoolKey memory key, uint24 fee) external;
                }
                """,
                encoding="utf-8",
            )

            rows = tool.find_low_config_liveness_advisories(
                ws,
                [("unrelated-low-detector", "LOW"), ("fee-cap-check", "MEDIUM")],
            )

            self.assertEqual(rows, [])

    def test_workspace_scan_runs_cosmos_detector_for_w68_go_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scan-out"
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(W68_COSMOS_FIXTURE),
                    "--out",
                    str(out),
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=60,
            )

            self.assertEqual(
                result.returncode,
                0,
                f"stdout={result.stdout}\nstderr={result.stderr}",
            )
            payload = json.loads((out / "cosmos_findings.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["findings_count"], 1)
            self.assertEqual(
                payload["findings"][0]["pattern"],
                "w68-consensus-param-corruption-no-validate",
            )
            report = (out / "scan_report.md").read_text(encoding="utf-8")
            self.assertIn("w68-consensus-param-corruption-no-validate", report)
            self.assertIn("tools/cosmos-detector-runner.py", report)

    def test_scan_facade_allows_go_cosmos_only_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "cosmos-ws"
            shutil.copytree(
                W68_COSMOS_FIXTURE,
                ws,
                ignore=shutil.ignore_patterns(".auditooor"),
            )

            result = subprocess.run(
                ["bash", str(SCAN_SH), str(ws)],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=60,
            )

            self.assertEqual(
                result.returncode,
                0,
                f"stdout={result.stdout}\nstderr={result.stderr}",
            )
            report = (ws / "SCAN_REPORT.md").read_text(encoding="utf-8")
            self.assertIn("Go/Cosmos workspace", report)
            self.assertIn("cosmos_findings.json", report)

    def test_engage_collect_hits_reads_cosmos_findings_from_scan_out(self) -> None:
        engage = load_engage()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            out = root / "out"
            ws.mkdir()
            out.mkdir()
            (out / "cosmos_findings.json").write_text(
                json.dumps(
                    {
                        "summary": {"findings_count": 1},
                        "findings": [
                            {
                                "pattern": "w68-consensus-param-corruption-no-validate",
                                "severity": "HIGH",
                                "file": str(ws / "x/consensus/keeper/params.go"),
                                "line": 14,
                                "function": "UpdateConsensusParams",
                                "help": "consensus params are written without validation",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            hits, dropped = engage.collect_hits(out, workspace=ws)

            self.assertEqual(dropped, 0)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["source"], "cosmos")
            self.assertEqual(
                hits[0]["detector"],
                "w68-consensus-param-corruption-no-validate",
            )


class SolTargetNoFrameworkTest(unittest.TestCase):
    """Tests for the no-framework skip fix (V3 closeout backlog #4).

    A Go/Rust workspace that contains precompile .sol stubs but has no
    foundry.toml or hardhat.config.* must NOT cause the Slither-backed scan
    path to fail with 'Expected a Solidity file when not using a compilation
    framework'.  solidity_scan_target() must return None, and the caller must
    skip gracefully.
    """

    def test_solidity_scan_target_returns_none_for_go_only_workspace(self) -> None:
        """Go workspace with precompile .sol stubs and no compilation framework
        must yield None from solidity_scan_target()."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "sei"
            # Mimic Sei: Go source + precompile .sol stubs, no foundry.toml
            go_pkg = ws / "app" / "ante"
            go_pkg.mkdir(parents=True)
            (go_pkg / "fee.go").write_text("package ante\n", encoding="utf-8")
            precompile_dir = ws / "src" / "sei-chain" / "precompiles" / "bank"
            precompile_dir.mkdir(parents=True)
            (precompile_dir / "Bank.sol").write_text(
                "// SPDX-License-Identifier: MIT\ncontract Bank {}\n",
                encoding="utf-8",
            )
            # No foundry.toml, no hardhat.config.* at workspace root or anywhere
            result = tool.solidity_scan_target(ws)
            self.assertIsNone(
                result,
                "Expected None when no compilation framework found; "
                f"got {result!r}",
            )

    def test_solidity_scan_target_returns_path_for_foundry_workspace(self) -> None:
        """A workspace with foundry.toml must still return the project root."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "evm_project"
            src = ws / "src"
            src.mkdir(parents=True)
            (src / "Token.sol").write_text("contract Token {}\n", encoding="utf-8")
            (ws / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            result = tool.solidity_scan_target(ws)
            self.assertIsNotNone(result)
            self.assertEqual(result, ws)

    def test_solidity_scan_target_returns_path_for_nested_foundry(self) -> None:
        """foundry.toml nested under external/ is discovered correctly."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "multi_repo"
            sub = ws / "external" / "protocol"
            sub.mkdir(parents=True)
            (sub / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (sub / "src").mkdir()
            (sub / "src" / "Core.sol").write_text("contract Core {}\n", encoding="utf-8")
            result = tool.solidity_scan_target(ws)
            self.assertIsNotNone(result)
            self.assertEqual(result, sub)

    def test_run_custom_skipped_gracefully_when_no_framework(self) -> None:
        """Passing a no-framework Go workspace to workspace-scan-orchestrator
        must succeed (rc=0) without calling run_custom.py / Slither."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "sei"
            (ws / "app").mkdir(parents=True)
            (ws / "app" / "main.go").write_text("package main\n", encoding="utf-8")
            precompile = ws / "src" / "precompiles"
            precompile.mkdir(parents=True)
            (precompile / "Stub.sol").write_text("contract Stub {}\n", encoding="utf-8")
            out = Path(tmp) / "out"
            out.mkdir()
            result = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--out", str(out)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(
                result.returncode, 0,
                f"Expected rc=0 for Go-only workspace; got {result.returncode}\n"
                f"stdout: {result.stdout[-1000:]}\n"
                f"stderr: {result.stderr[-500:]}",
            )
            # The warn message must appear in stdout
            self.assertIn(
                "no-solidity-project",
                result.stdout,
                "Expected 'no-solidity-project' skip signal in stdout for no-framework workspace",
            )
            # run_custom.log must exist and must NOT contain the Slither error
            run_log = out / "run_custom.log"
            self.assertTrue(
                run_log.exists(),
                "run_custom.log must be written even when Slither is skipped",
            )
            content = run_log.read_text(encoding="utf-8")
            self.assertNotIn(
                "Expected a Solidity file",
                content,
                "Slither compilation-framework error must not appear in run_custom.log",
            )


class SolTargetSeparateHardhatContractsTest(unittest.TestCase):
    """Regression for the Injective Peggy.sol scan miss.

    The in-scope contracts live at ``.../solidity/contracts/Peggy.sol`` while the
    only hardhat.config.js sits in a DIFFERENT dir (``.../test/ethereum``).  The
    old resolver pointed Slither at the Go repo root (error: 'is a directory.
    Expected a Solidity file') and never analyzed Peggy.sol.  The resolver must
    now return the directory that actually holds the in-scope .sol files, and
    ``solidity_scan_inputs`` must enumerate the real .sol files (excluding
    vendored @openzeppelin) so Slither compiles each via solc directly.
    """

    def _build_injective_like_layout(self, root: Path) -> Path:
        """Go repo root + nested solidity/contracts/Foo.sol + far-away hardhat
        config + vendored @openzeppelin + a precompile stub.  Returns the
        contracts dir."""
        go_root = root / "src" / "injective-core"
        (go_root / "injective-chain" / "modules" / "peggy").mkdir(parents=True)
        (go_root / "injective-chain" / "modules" / "peggy" / "keeper.go").write_text(
            "package peggy\n", encoding="utf-8"
        )
        contracts = go_root / "peggo" / "solidity" / "contracts"
        contracts.mkdir(parents=True)
        # In-scope production contract with a co-located relative OZ import.
        (contracts / "Foo.sol").write_text(
            "// SPDX-License-Identifier: Apache-2.0\n"
            "pragma solidity ^0.8.0;\n"
            'import "./@openzeppelin/contracts/IERC20.sol";\n'
            "contract Foo {\n"
            "    function bar(address a) external pure returns (address) { return a; }\n"
            "}\n",
            encoding="utf-8",
        )
        # Vendored upstream — must be excluded from the compilation input set.
        oz = contracts / "@openzeppelin" / "contracts"
        oz.mkdir(parents=True)
        (oz / "IERC20.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "interface IERC20 {}\n",
            encoding="utf-8",
        )
        # A Foundry test contract — must be excluded.
        (contracts / "Foo.t.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract FooTest {}\n", encoding="utf-8"
        )
        # hardhat.config.js in a DIFFERENT dir than the contracts.
        ht = go_root / "peggo" / "test" / "ethereum"
        ht.mkdir(parents=True)
        (ht / "hardhat.config.js").write_text(
            "module.exports = {};\n", encoding="utf-8"
        )
        # An out-of-scope precompile stub elsewhere (should not be the target).
        precompile = go_root / "injective-chain" / "modules" / "evm" / "precompiles" / "bank"
        precompile.mkdir(parents=True)
        (precompile / "Bank.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Bank {}\n", encoding="utf-8"
        )
        return contracts

    def _write_inscope_manifest(self, ws: Path, sol_rel_paths: list[str]) -> None:
        adir = ws / ".auditooor"
        adir.mkdir(parents=True, exist_ok=True)
        rows = [
            json.dumps({"file": rel, "function": "bar", "lang": "solidity"})
            for rel in sol_rel_paths
        ]
        (adir / "inscope_units.jsonl").write_text(
            "\n".join(rows) + "\n", encoding="utf-8"
        )

    def test_resolver_returns_contracts_dir_not_go_root_with_manifest(self) -> None:
        """With an inscope manifest, the resolver returns the contracts dir,
        not the Go repo root nor the far-away hardhat root."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "injective"
            contracts = self._build_injective_like_layout(ws)
            self._write_inscope_manifest(
                ws,
                ["src/injective-core/peggo/solidity/contracts/Foo.sol"],
            )
            result = tool.solidity_scan_target(ws)
            self.assertIsNotNone(result, "Expected a target, got None")
            self.assertEqual(
                result.resolve(),
                contracts.resolve(),
                f"Expected the contracts dir {contracts}, got {result}",
            )

    def test_resolver_returns_contracts_dir_no_manifest_heuristic(self) -> None:
        """Without a manifest, the path-shape heuristic still resolves the
        solidity/contracts dir (not the Go root, not the precompile stub)."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "injective"
            contracts = self._build_injective_like_layout(ws)
            result = tool.solidity_scan_target(ws)
            self.assertIsNotNone(result, "Expected a target, got None")
            self.assertEqual(
                result.resolve(),
                contracts.resolve(),
                f"Expected the contracts dir {contracts}, got {result}",
            )

    def test_scan_inputs_lists_inscope_sol_excludes_vendored_and_tests(self) -> None:
        """solidity_scan_inputs must return Foo.sol but NOT vendored
        @openzeppelin/IERC20.sol nor the .t.sol test contract."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "injective"
            contracts = self._build_injective_like_layout(ws)
            self._write_inscope_manifest(
                ws,
                ["src/injective-core/peggo/solidity/contracts/Foo.sol"],
            )
            inputs = tool.solidity_scan_inputs(ws)
            names = {p.name for p in inputs}
            self.assertIn("Foo.sol", names)
            self.assertNotIn(
                "IERC20.sol", names, "vendored @openzeppelin must be excluded"
            )
            self.assertNotIn(
                "Foo.t.sol", names, ".t.sol test contracts must be excluded"
            )
            self.assertNotIn(
                "Bank.sol", names,
                "out-of-scope precompile stub must not be in the input set",
            )

    def test_detect_solc_pragma(self) -> None:
        """Pragma floor detection returns the highest minor seen."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "Foo.sol"
            f.write_text("pragma solidity ^0.8.0;\ncontract Foo {}\n", encoding="utf-8")
            self.assertEqual(tool.detect_solc_pragma([f]), "0.8.0")

    def test_separate_hardhat_does_not_shadow_contracts_dir(self) -> None:
        """A hardhat.config.js that does NOT contain the in-scope contracts must
        NOT be returned as the framework root (the core Injective bug)."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "injective"
            contracts = self._build_injective_like_layout(ws)
            self._write_inscope_manifest(
                ws,
                ["src/injective-core/peggo/solidity/contracts/Foo.sol"],
            )
            result = tool.solidity_scan_target(ws)
            # Must be the contracts dir, not the hardhat (test/ethereum) dir.
            self.assertNotIn(
                "ethereum", result.parts,
                "resolver must not return the far-away hardhat config dir",
            )
            self.assertEqual(result.resolve(), contracts.resolve())


class TestScopeAwareLanguageDetection(unittest.TestCase):
    """detect_languages must honor scope.json so a polyglot monorepo where only
    one language is in scope does not trigger OOS-language detectors (the
    hyperlane step-1 perf/scope bug: ~948 OOS Rust files ran rust-detect)."""

    def _make_polyglot_ws(self, tmp: Path) -> Path:
        ws = tmp
        (ws / "src" / "solidity" / "contracts").mkdir(parents=True)
        (ws / "src" / "solidity" / "contracts" / "Mailbox.sol").write_text(
            "// SPDX\ncontract Mailbox {}\n")
        (ws / "src" / "rust").mkdir(parents=True)
        (ws / "src" / "rust" / "lib.rs").write_text("fn main() {}\n")  # OOS rust
        return ws

    def test_no_scope_json_is_legacy_whole_ws_detection(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as d:
            ws = self._make_polyglot_ws(Path(d))
            langs = mod.detect_languages(ws)
            self.assertEqual({"sol", "rs"}, langs,
                             "without scope.json detection stays whole-workspace")

    def test_scope_json_restricts_detection_to_inscope_language(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as d:
            ws = self._make_polyglot_ws(Path(d))
            (ws / "scope.json").write_text(json.dumps({
                "in_scope": ["solidity/contracts"],
                "out_of_scope": ["test", "mock"],
            }))
            langs = mod.detect_languages(ws)
            self.assertEqual({"sol"}, langs,
                             "OOS rust must NOT be detected -> rust-detect skipped")

    def test_scope_json_with_unresolvable_paths_falls_back(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as d:
            ws = self._make_polyglot_ws(Path(d))
            (ws / "scope.json").write_text(json.dumps({
                "in_scope": ["does/not/exist/anywhere"],
            }))
            # nothing resolves -> fall back to whole-ws (never silently empty)
            langs = mod.detect_languages(ws)
            self.assertEqual({"sol", "rs"}, langs)


if __name__ == "__main__":
    unittest.main()
