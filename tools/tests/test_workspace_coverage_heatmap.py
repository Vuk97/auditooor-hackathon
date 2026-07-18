# <!-- r36-rebuttal: lane-COVERAGE-MAP-L37 registered in .auditooor/agent_pathspec.json -->
"""Tests for tools/workspace-coverage-heatmap.py SWEPT-SURFACE coverage report.

Covers the mode-2 (--coverage-report) generator:
  - in-scope unit enumeration (Solidity FUNCTION granularity; file-level
    degrade for .go/.rs/.move/.cairo),
  - covered vs UNCOVERED classification from hypothesis/candidate tokens,
  - schema-versioned JSON shape,
  - NO-SILENT-CAPS discipline: the true uncovered count is never truncated,
  - fully-covered fixture => coverage_fraction == 1.0,
  - mostly-uncovered fixture => correct uncovered count.

The tool name has hyphens so it is loaded as a module via importlib.
"""
import importlib.util
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "workspace-coverage-heatmap.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("_cov_heatmap_under_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_cov_heatmap_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_mod()


def _write(p: Path, txt: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(txt, encoding="utf-8")


def _write_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


class EnumerationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_solidity_function_granularity(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "Vault.sol",
               "contract Vault {\n"
               "  function deposit(uint256 a) external {}\n"
               "  function withdraw(uint256 a) public {}\n"
               "  constructor() {}\n"
               "}\n")
        units, detail = _MOD.enumerate_units(ws)
        self.assertIn("Vault.sol::deposit", units)
        self.assertIn("Vault.sol::withdraw", units)
        self.assertIn("Vault.sol::constructor", units)
        self.assertEqual(detail["granularity"][".sol"], "function")
        self.assertEqual(detail["denominator_mode_by_ext"][".sol"], "function-level")

    def test_go_function_granularity(self):
        # Item 3 (auto-coverage-closer-extend): .go is now FUNCTION-granular
        # (was file-degraded). Each Go func is its own unit.
        # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
        ws = self._tmp / "ws"
        _write(ws / "src" / "keeper.go", "package main\nfunc Foo() {}\n")
        units, detail = _MOD.enumerate_units(ws)
        self.assertEqual(units, ["keeper.go::Foo"])
        self.assertEqual(detail["granularity"][".go"], "function")
        self.assertEqual(detail["denominator_mode_by_ext"][".go"], "function-level")

    def test_go_report_marks_function_level_denominator(self):
        # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
        ws = self._tmp / "ws"
        _write(ws / "src" / "keeper.go",
               "package main\nfunc Foo() {}\nfunc Bar() {}\n")
        report = _MOD.build_coverage_report(ws)
        # two functions -> two function-level units (was 1 file unit)
        self.assertEqual(report["total_units"], 2)
        self.assertIn(".go", report["function_level_extensions"])
        self.assertNotIn(".go", report["source_unit_extensions"])

    def test_go_test_file_excluded_from_denominator(self):
        # BUG: *_test.go files were included in the coverage denominator.
        # The per-function-invariant-gen skips *_test.go at line 531 (via
        # _gen_is_test_file) but the regex-fallback path in enumerate_units did
        # not - inflating the denominator with test helpers the hunt never
        # produces questions for, causing a false low coverage fraction.
        # After the fix, staking_test.go functions must NOT appear in units.
        ws = self._tmp / "ws"
        _write(
            ws / "src" / "keeper" / "staking.go",
            "package keeper\n\n"
            "func Deposit(ctx Context, amount int64) error {\n"
            "    return nil\n"
            "}\n\n"
            "func NewKeeper(store Store) *Keeper {\n"
            "    return &Keeper{store: store}\n"
            "}\n",
        )
        _write(
            ws / "src" / "keeper" / "staking_test.go",
            'package keeper\n\nimport "testing"\n\n'
            "func TestDeposit(t *testing.T) {}\n\n"
            "func setupTest(t *testing.T) *Keeper { return nil }\n\n"
            "func TestStakingInvariant(t *testing.T) {}\n",
        )
        units, detail = _MOD.enumerate_units(ws)
        # Production functions are enumerated.
        self.assertIn("staking.go::Deposit", units)
        self.assertIn("staking.go::NewKeeper", units)
        # Test-file functions are excluded from the denominator.
        self.assertNotIn("staking_test.go::TestDeposit", units)
        self.assertNotIn("staking_test.go::setupTest", units)
        self.assertNotIn("staking_test.go::TestStakingInvariant", units)
        # Only the 2 production functions count.
        go_units = [u for u in units if u.endswith(".go") or "staking" in u]
        self.assertEqual(sorted(go_units), ["staking.go::Deposit", "staking.go::NewKeeper"])
        # denominator_mode is still function-level (not degraded)
        self.assertEqual(detail["denominator_mode_by_ext"][".go"], "function-level")

    def test_go_test_file_exclusion_does_not_affect_non_test_go_files(self):
        # Confirm the filename exclusion is tight: a .go file that contains
        # Test-prefixed functions but is NOT named *_test.go must still be
        # included (it is a legitimate production helper, not a test file).
        ws = self._tmp / "ws"
        _write(
            ws / "src" / "helpers" / "testing_utils.go",
            "package helpers\n\n"
            "func TestHelper() {}\n"
            "func SetupEnv() {}\n",
        )
        units, _ = _MOD.enumerate_units(ws)
        self.assertIn("testing_utils.go::TestHelper", units)
        self.assertIn("testing_utils.go::SetupEnv", units)

    def test_source_artifacts_require_explicit_review_schema(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "A.sol", "contract A { function hit() external {} }\n")
        _write_json(
            ws / ".auditooor" / "source_artifacts" / "queue-echo.json",
            {"queue": [{"file": "src/A.sol", "function": "hit"}]},
        )

        report = _MOD.build_coverage_report(ws)

        self.assertIn("A.sol::hit", report["uncovered_units"])

    def test_source_artifacts_review_schema_counts_as_covered(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "A.sol", "contract A { function hit() external {} }\n")
        _write_json(
            ws / ".auditooor" / "source_artifacts" / "review.json",
            {
                "scanned_units": [
                    {
                        "source_unit": "A.sol::hit",
                        "source_ref": "src/A.sol:1",
                    }
                ]
            },
        )

        report = _MOD.build_coverage_report(ws)

        self.assertNotIn("A.sol::hit", report["uncovered_units"])

    def test_prunes_test_and_vendor_dirs(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "Real.sol", "contract R { function f() external {} }\n")
        _write(ws / "src" / "test" / "RealTest.sol",
               "contract T { function tf() external {} }\n")
        _write(ws / "lib" / "Dep.sol", "contract D { function df() external {} }\n")
        units, _ = _MOD.enumerate_units(ws)
        self.assertIn("Real.sol::f", units)
        self.assertNotIn("RealTest.sol::tf", units)
        self.assertNotIn("Dep.sol::df", units)


class RustSourceGraphEnumerationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_rust_graph(self, ws: Path, entrypoints: list[dict]) -> None:
        _write_json(ws / ".auditooor" / "rust_source_graph.json", {
            "_meta": {
                "schema_version": "auditooor.rust_source_graph.v1",
                "workspace": str(ws),
                "crate_count": 1,
            },
            "zebra-rpc": {
                "crate_root": "src/zebra-rpc",
                "files_scanned": 1,
                "entrypoints": entrypoints,
            },
        })

    def test_rust_source_graph_entrypoint_denominator(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "zebra-rpc" / "src" / "methods.rs",
               "pub fn helper() {}\n")
        self._write_rust_graph(ws, [
            {
                "file": "src/zebra-rpc/src/methods.rs",
                "line": 194,
                "fn": "get_info",
                "kind": "jsonrpsee_method",
            },
            {
                "file": "src/zebra-rpc/src/methods.rs",
                "line": 547,
                "fn": "submit_block",
                "kind": "jsonrpsee_method",
            },
        ])

        units, detail = _MOD.enumerate_units(ws)
        self.assertEqual(units, ["methods.rs::get_info", "methods.rs::submit_block"])
        self.assertEqual(detail["granularity"][".rs"], "rust_source_graph_entrypoint")
        self.assertEqual(detail["denominator_mode_by_ext"][".rs"], "rust-source-graph-only")
        self.assertEqual(detail["rust_source_unit_fallback_files"], [])
        self.assertEqual(detail["rust_source_unit_fallback_units"], 0)
        self.assertEqual(detail["rust_source_graph_entrypoints"], 2)
        self.assertEqual(detail["rust_source_graph_units"], 2)

    def test_rust_source_graph_partial_keeps_ungraphed_files(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "api.rs", "pub fn get_info() {}\n")
        _write(ws / "src" / "state.rs", "pub fn helper() {}\n")
        self._write_rust_graph(ws, [
            {
                "file": "src/api.rs",
                "line": 1,
                "fn": "get_info",
                "kind": "jsonrpsee_method",
            },
        ])

        units, detail = _MOD.enumerate_units(ws)
        self.assertIn("api.rs::get_info", units)
        self.assertIn("state.rs", units)
        self.assertEqual(detail["files_scanned"], 2)
        self.assertEqual(detail["rust_source_graph_units"], 1)
        self.assertEqual(detail["rust_source_graph_files"], ["src/api.rs"])
        self.assertEqual(
            detail["denominator_mode_by_ext"][".rs"],
            "rust-source-graph-partial-plus-source-unit-fallback",
        )
        self.assertEqual(detail["rust_source_unit_fallback_files"], ["src/state.rs"])
        self.assertEqual(detail["rust_source_unit_fallback_units"], 1)

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["function_denominator_status"], "partial")
        self.assertIn(".rs", report["partial_function_extensions"])
        self.assertIn(".rs", report["source_unit_extensions"])
        self.assertEqual(
            report["partial_function_reasons"][".rs"],
            "rust_source_graph_entrypoints_only",
        )
        self.assertFalse(report["full_in_scope_function_denominator"])

    def test_rust_source_graph_ignores_missing_entrypoint_files(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "state.rs", "pub fn helper() {}\n")
        self._write_rust_graph(ws, [
            {
                "file": "src/missing.rs",
                "line": 1,
                "fn": "ghost",
                "kind": "jsonrpsee_method",
            },
        ])

        # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
        # When a graph entrypoint file is missing, the graph contributes nothing
        # and the present .rs file is enumerated at FUNCTION granularity (item 3
        # upgrade; was file-degraded). `state.rs` -> `state.rs::helper`.
        units, detail = _MOD.enumerate_units(ws)
        self.assertEqual(units, ["state.rs::helper"])
        self.assertNotIn("missing.rs::ghost", units)
        self.assertNotIn("rust_source_graph_units", detail)

    def test_rust_source_graph_fallback_to_function_level_when_absent(self):
        # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
        # Item 3: with NO rust_source_graph and NO per-fn manifest, .rs degrades
        # to FUNCTION granularity via the in-file regex parse (was file-level).
        ws = self._tmp / "ws"
        _write(ws / "src" / "keeper.rs", "pub fn run() {}\n")

        units, detail = _MOD.enumerate_units(ws)
        self.assertEqual(units, ["keeper.rs::run"])
        self.assertEqual(detail["granularity"][".rs"], "function")
        self.assertEqual(detail["denominator_mode_by_ext"][".rs"], "function-level")
        self.assertNotIn("rust_source_graph_units", detail)

    def test_rust_source_graph_scope_restriction(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "core" / "methods.rs", "pub fn get_info() {}\n")
        _write(ws / "src" / "extra" / "admin.rs", "pub fn stop() {}\n")
        _write_json(ws / "scope.json", {"in_scope": ["src/core/*"]})
        self._write_rust_graph(ws, [
            {
                "file": "src/core/methods.rs",
                "line": 10,
                "fn": "get_info",
                "kind": "jsonrpsee_method",
            },
            {
                "file": "src/extra/admin.rs",
                "line": 20,
                "fn": "stop",
                "kind": "jsonrpsee_method",
            },
        ])

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 1)
        self.assertEqual(report["enumeration"]["granularity"][".rs"], "rust_source_graph_entrypoint")
        self.assertEqual(report["enumeration"]["rust_source_graph_scoped_out"], 1)
        self.assertIn("methods.rs::get_info", report["uncovered_units"])
        self.assertNotIn("admin.rs::stop", report["uncovered_units"])

    def test_rust_source_graph_duplicate_basenames_stay_path_qualified(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "core" / "methods.rs", "pub fn submit() {}\n")
        _write(ws / "src" / "extra" / "methods.rs", "pub fn submit() {}\n")
        self._write_rust_graph(ws, [
            {
                "file": "src/core/methods.rs",
                "line": 10,
                "fn": "submit",
                "kind": "jsonrpsee_method",
            },
            {
                "file": "src/extra/methods.rs",
                "line": 20,
                "fn": "submit",
                "kind": "jsonrpsee_method",
            },
        ])

        units, detail = _MOD.enumerate_units(ws)
        self.assertEqual(
            units,
            ["src/core/methods.rs::submit", "src/extra/methods.rs::submit"],
        )
        self.assertEqual(detail["rust_source_graph_units"], 2)

    def test_rust_source_graph_scope_filtered_duplicate_stays_ambiguous(self):
        ws = self._tmp / "ws"
        _write(ws / "SCOPE.md", "## In Scope\n\n- `src/core/methods.rs`\n")
        _write(ws / "src" / "core" / "methods.rs", "pub fn submit() {}\n")
        _write(ws / "src" / "extra" / "methods.rs", "pub fn submit() {}\n")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [{"file": "methods.rs", "fn": "submit"}],
        })
        self._write_rust_graph(ws, [
            {
                "file": "src/core/methods.rs",
                "line": 10,
                "fn": "submit",
                "kind": "jsonrpsee_method",
            },
            {
                "file": "src/extra/methods.rs",
                "line": 20,
                "fn": "submit",
                "kind": "jsonrpsee_method",
            },
        ])

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 1)
        self.assertEqual(report["covered"], 0)
        self.assertIn("src/core/methods.rs::submit", report["uncovered_units"])

    def test_rust_source_graph_precise_coverage(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "zebra-rpc" / "src" / "methods.rs",
               "pub fn get_info() {}\npub fn submit_block() {}\n")
        self._write_rust_graph(ws, [
            {
                "file": "src/zebra-rpc/src/methods.rs",
                "line": 194,
                "fn": "get_info",
                "kind": "jsonrpsee_method",
            },
            {
                "file": "src/zebra-rpc/src/methods.rs",
                "line": 547,
                "fn": "submit_block",
                "kind": "jsonrpsee_method",
            },
        ])
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [
                {"file": "src/zebra-rpc/src/methods.rs", "fn": "get_info"},
            ],
        })

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 2)
        self.assertEqual(report["covered"], 1)
        self.assertEqual(report["uncovered"], 1)
        self.assertNotIn("methods.rs::get_info", report["uncovered_units"])
        self.assertIn("methods.rs::submit_block", report["uncovered_units"])

    def test_source_freshness_hash_changes_when_rust_graph_content_changes(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "zebra-rpc" / "src" / "methods.rs", "pub fn get_info() {}\n")
        self._write_rust_graph(ws, [
            {
                "file": "src/zebra-rpc/src/methods.rs",
                "line": 194,
                "fn": "get_info",
                "kind": "jsonrpsee_method",
            },
        ])
        before = _MOD.build_coverage_report(ws)["source_freshness"]
        self._write_rust_graph(ws, [
            {
                "file": "src/zebra-rpc/src/methods.rs",
                "line": 195,
                "fn": "get_info",
                "kind": "jsonrpsee_method",
            },
        ])
        after = _MOD.build_coverage_report(ws)["source_freshness"]

        self.assertEqual(before["source_units_sha256"], after["source_units_sha256"])
        self.assertNotEqual(before["rust_source_graph_sha256"], after["rust_source_graph_sha256"])
        self.assertNotEqual(before["denominator_sha256"], after["denominator_sha256"])


class NoirEnumerationTest(unittest.TestCase):
    """Noir (.nr) is enumerated at FUNCTION granularity, mirroring Solidity.

    Anchor: the Aztec workspace carries Noir circuits whose `.nr` files were
    silently invisible to the enumerator (extension not mapped), so a workspace
    with only Noir source read 0/0 and degenerated to a FALSE
    coverage_fraction=1.0. These tests lock in that .nr is recognized,
    function-parsed, and that the `/lib/` Noir package-layout segment does not
    auto-prune .nr source.
    """

    FIXTURE = Path(__file__).resolve().parent / "fixtures" / "noir_circuit.nr"

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_noir_function_granularity(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "circuit.nr", self.FIXTURE.read_text(encoding="utf-8"))
        units, detail = _MOD.enumerate_units(ws)
        # fn / pub fn / unconstrained fn all parsed at function granularity
        self.assertIn("circuit.nr::verify_proof", units)
        self.assertIn("circuit.nr::hash_inputs", units)
        self.assertIn("circuit.nr::debug_dump", units)
        self.assertEqual(detail["granularity"][".nr"], "function")
        self.assertEqual(detail["denominator_mode_by_ext"][".nr"], "function-level")
        self.assertEqual(detail["languages"][".nr"], 1)

    def test_noir_lib_segment_not_pruned(self):
        # Noir packages canonically nest source under `lib/<pkg>/src/`; that
        # `/lib/` must NOT auto-exclude the .nr file the way it excludes a
        # Foundry Solidity dependency.
        ws = self._tmp / "ws"
        _write(ws / "src" / "lib" / "disclose" / "src" / "lib.nr",
               "pub fn get_disclosed_bytes(x: Field) -> Field { x }\n")
        units, detail = _MOD.enumerate_units(ws)
        self.assertIn("lib.nr::get_disclosed_bytes", units)
        self.assertEqual(detail["granularity"][".nr"], "function")

    def test_noir_lib_still_prunes_solidity_dependency(self):
        # The /lib/ exemption is .nr-specific: a .sol under /lib/ is still a
        # vendored Foundry dependency and stays pruned.
        ws = self._tmp / "ws"
        _write(ws / "src" / "lib" / "Dep.sol",
               "contract D { function df() external {} }\n")
        units, _ = _MOD.enumerate_units(ws)
        self.assertNotIn("Dep.sol::df", units)

    def test_noir_workspace_not_false_empty(self):
        # A workspace whose only source is Noir must NOT read 0/0 -> 1.0.
        ws = self._tmp / "ws"
        _write(ws / "src" / "main.nr",
               "fn a() {}\nfn b() {}\nfn c() {}\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 3)
        self.assertEqual(report["covered"], 0)
        self.assertEqual(report["uncovered"], 3)
        self.assertEqual(report["coverage_fraction"], 0.0)  # NOT a false 1.0
        self.assertEqual(report["enumeration"]["granularity"][".nr"], "function")

    def test_noir_covered_vs_uncovered_classification(self):
        # Covered classification works identically for Noir: a hypothesis token
        # referencing a function marks it covered; siblings stay uncovered.
        ws = self._tmp / "ws"
        _write(ws / "src" / "circuit.nr", self.FIXTURE.read_text(encoding="utf-8"))
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [{"file": "src/circuit.nr", "function": "verify_proof"}],
        })
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 3)
        self.assertEqual(report["covered"], 1)
        self.assertEqual(report["uncovered"], 2)
        self.assertIn("circuit.nr::hash_inputs", report["uncovered_units"])
        self.assertIn("circuit.nr::debug_dump", report["uncovered_units"])


class CoverageReportTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ws_with_two_functions(self) -> Path:
        ws = self._tmp / "ws"
        _write(ws / "src" / "Vault.sol",
               "contract Vault {\n"
               "  function deposit(uint256 a) external {}\n"
               "  function withdraw(uint256 a) public {}\n"
               "}\n")
        return ws

    # ---- (a) fully covered => coverage_fraction == 1.0 ----
    def test_full_coverage_fraction_one(self):
        ws = self._ws_with_two_functions()
        # candidate tokens that reference both functions
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [
                {"file": "src/Vault.sol", "function": "deposit"},
                {"file": "src/Vault.sol", "function": "withdraw"},
            ],
        })
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["schema"], "auditooor.workspace_coverage_report.v1")
        self.assertEqual(report["coverage_basis"], "source-unit")
        self.assertEqual(report["total_units"], 2)
        self.assertEqual(report["covered"], 2)
        self.assertEqual(report["uncovered"], 0)
        self.assertEqual(report["coverage_fraction"], 1.0)
        self.assertFalse(report["uncovered_units_truncated"])

    # ---- (b) mostly uncovered => correct uncovered count ----
    def test_partial_coverage_uncovered_count(self):
        ws = self._ws_with_two_functions()
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [{"file": "src/Vault.sol", "function": "deposit"}],
        })
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 2)
        self.assertEqual(report["covered"], 1)
        self.assertEqual(report["uncovered"], 1)
        self.assertEqual(report["coverage_fraction"], 0.5)
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])
        self.assertEqual(report["covered"] + report["uncovered"], report["total_units"])
        self.assertEqual(report["coverage_fraction"], round(report["covered"] / report["total_units"], 6))
        self.assertEqual(report["uncovered_units_listed"], len(report["uncovered_units"]))
        self.assertEqual(
            report["uncovered"],
            len(report["uncovered_units"]) + report["uncovered_units_omitted"],
        )
        self.assertEqual(report["uncovered_units_truncated"], report["uncovered_units_omitted"] > 0)

    def test_numerator_freshness_artifact_content_hash_changes_without_token_change(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "Vault.sol", "contract Vault {}\n")
        artifact = ws / "agent_outputs" / "lane.md"
        _write(artifact, "First review cites src/Vault.sol:1\n")
        first = _MOD.build_coverage_report(ws)["numerator_freshness"]

        _write(artifact, "Changed review prose still cites src/Vault.sol:1\n")
        second = _MOD.build_coverage_report(ws)["numerator_freshness"]

        self.assertEqual(first["coverage_tokens_sha256"], second["coverage_tokens_sha256"])
        self.assertEqual(first["covered_units_sha256"], second["covered_units_sha256"])
        self.assertEqual(first["uncovered_units_sha256"], second["uncovered_units_sha256"])
        self.assertEqual(first["numerator_artifacts_count"], second["numerator_artifacts_count"])
        self.assertNotEqual(
            first["numerator_artifacts_sha256"],
            second["numerator_artifacts_sha256"],
        )
        self.assertNotEqual(first["numerator_sha256"], second["numerator_sha256"])

    def test_numerator_freshness_artifact_inventory_hash_changes_without_token_change(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "Vault.sol", "contract Vault {}\n")
        _write(ws / "agent_outputs" / "lane-a.md", "Review cites src/Vault.sol:1\n")
        first = _MOD.build_coverage_report(ws)["numerator_freshness"]

        _write(ws / "agent_outputs" / "lane-b.md", "Second review cites src/Vault.sol:1\n")
        second = _MOD.build_coverage_report(ws)["numerator_freshness"]

        self.assertEqual(first["coverage_tokens_sha256"], second["coverage_tokens_sha256"])
        self.assertEqual(first["covered_units_sha256"], second["covered_units_sha256"])
        self.assertEqual(first["uncovered_units_sha256"], second["uncovered_units_sha256"])
        self.assertEqual(first["numerator_artifacts_count"] + 1, second["numerator_artifacts_count"])
        self.assertNotEqual(
            first["numerator_artifacts_sha256"],
            second["numerator_artifacts_sha256"],
        )
        self.assertNotEqual(first["numerator_sha256"], second["numerator_sha256"])

    def test_same_basename_units_keep_path_qualified_denominator(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "a" / "Vault.sol", "contract VaultA { function deposit() external {} }\n")
        _write(ws / "src" / "b" / "Vault.sol", "contract VaultB { function deposit() external {} }\n")

        units, _detail = _MOD.enumerate_units(ws)
        self.assertEqual(units, ["src/a/Vault.sol::deposit", "src/b/Vault.sol::deposit"])

    def test_path_qualified_duplicate_basename_covers_only_matching_file(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "a" / "Vault.sol", "contract VaultA { function deposit() external {} }\n")
        _write(ws / "src" / "b" / "Vault.sol", "contract VaultB { function deposit() external {} }\n")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [{"file": "src/a/Vault.sol", "function": "deposit"}],
        })

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 2)
        self.assertEqual(report["covered"], 1)
        self.assertEqual(report["uncovered"], 1)
        self.assertIn("src/b/Vault.sol::deposit", report["uncovered_units"])

    def test_draft_path_qualified_duplicate_basename_covers_only_matching_file(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "a" / "Vault.sol", "contract VaultA { function deposit() external {} }\n")
        _write(ws / "src" / "b" / "Vault.sol", "contract VaultB { function deposit() external {} }\n")
        _write(ws / "submissions" / "staging" / "finding.md", "Source: src/a/Vault.sol::deposit\n")

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 1)
        self.assertIn("src/b/Vault.sol::deposit", report["uncovered_units"])

    def test_draft_file_line_duplicate_basename_does_not_cover_function_units(self):
        ws = self._tmp / "ws"
        _write(
            ws / "src" / "a" / "Vault.sol",
            "contract VaultA { function deposit() external {} function withdraw() external {} }\n",
        )
        _write(ws / "src" / "b" / "Vault.sol", "contract VaultB { function deposit() external {} }\n")
        _write(ws / "submissions" / "staging" / "finding.md", "Source: src/a/Vault.sol:1\n")

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 0)
        self.assertIn("src/a/Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("src/a/Vault.sol::withdraw", report["uncovered_units"])
        self.assertIn("src/b/Vault.sol::deposit", report["uncovered_units"])

    def test_json_file_only_duplicate_basename_does_not_cover_function_units(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "a" / "Vault.sol", "contract VaultA { function deposit() external {} }\n")
        _write(ws / "src" / "b" / "Vault.sol", "contract VaultB { function deposit() external {} }\n")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [{"file": "src/a/Vault.sol"}],
        })

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 0)
        self.assertIn("src/a/Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("src/b/Vault.sol::deposit", report["uncovered_units"])

    def test_ambiguous_duplicate_basename_does_not_cover_either_file(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "a" / "Vault.sol", "contract VaultA { function deposit() external {} }\n")
        _write(ws / "src" / "b" / "Vault.sol", "contract VaultB { function deposit() external {} }\n")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [{"file": "Vault.sol", "function": "deposit"}],
        })

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 2)
        self.assertEqual(report["covered"], 0)
        self.assertEqual(report["uncovered"], 2)

    def test_scope_filtered_out_of_scope_duplicate_keeps_basename_ambiguous(self):
        ws = self._tmp / "ws"
        _write(ws / "SCOPE.md", "## In Scope\n\n- `src/a/Vault.sol`\n")
        _write(ws / "src" / "a" / "Vault.sol", "contract VaultA { function deposit() external {} }\n")
        _write(ws / "src" / "b" / "Vault.sol", "contract VaultB { function deposit() external {} }\n")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [{"file": "src/b/Vault.sol", "function": "deposit"}],
        })

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 1)
        self.assertEqual(report["covered"], 0)
        self.assertEqual(report["uncovered"], 1)

    # ---- zero coverage tokens => everything uncovered ----
    def test_zero_tokens_all_uncovered(self):
        ws = self._ws_with_two_functions()
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 0)
        self.assertEqual(report["uncovered"], 2)
        self.assertEqual(report["coverage_fraction"], 0.0)

    # ---- NO-SILENT-CAPS: list capped but TRUE count preserved ----
    def test_no_silent_caps(self):
        ws = self._tmp / "ws"
        # 50 uncovered file-units, cap the inline list at 10
        for i in range(50):
            _write(ws / "src" / f"C{i}.go", "package main\n")
        report = _MOD.build_coverage_report(ws, list_cap=10)
        self.assertEqual(report["total_units"], 50)
        self.assertEqual(report["uncovered"], 50)  # TRUE count, untruncated
        self.assertEqual(report["uncovered_units_listed"], 10)
        self.assertTrue(report["uncovered_units_truncated"])
        self.assertEqual(report["uncovered_units_omitted"], 40)
        # the inline list is bounded but the count field is the real total
        self.assertEqual(len(report["uncovered_units"]), 10)

    # ---- empty surface => trivially fraction 1.0 (no divide-by-zero) ----
    def test_empty_surface_fraction_one(self):
        ws = self._tmp / "ws"
        (ws / "src").mkdir(parents=True)
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 0)
        self.assertEqual(report["coverage_fraction"], 1.0)

    # ---- write_coverage_report lands the JSON where L37 reads it ----
    def test_write_lands_in_auditooor(self):
        ws = self._ws_with_two_functions()
        out, report = _MOD.write_coverage_report(ws)
        self.assertEqual(out, ws / ".auditooor" / "coverage_report.json")
        self.assertTrue(out.is_file())
        on_disk = json.loads(out.read_text())
        self.assertEqual(on_disk["total_units"], report["total_units"])
        self.assertEqual(on_disk["coverage_basis"], "source-unit")
        self.assertEqual(on_disk["enumeration"]["denominator_mode_by_ext"][".sol"], "function-level")

    def test_source_freshness_fields_present(self):
        ws = self._ws_with_two_functions()
        report = _MOD.build_coverage_report(ws)
        freshness = report["source_freshness"]
        self.assertEqual(freshness["schema"], "auditooor.coverage_source_freshness.v1")
        self.assertEqual(freshness["algorithm"], "sha256-canonical-json-v1")
        self.assertEqual(freshness["coverage_basis"], "source-unit")
        self.assertEqual(freshness["source_units_count"], report["total_units"])
        self.assertIn("source_files_sha256", freshness)
        self.assertIn("source_units_sha256", freshness)
        self.assertIn("denominator_sha256", freshness)

    def test_source_freshness_content_hash_changes_with_same_units(self):
        ws = self._ws_with_two_functions()
        before = _MOD.build_coverage_report(ws)["source_freshness"]
        _write(ws / "src" / "Vault.sol",
               "contract Vault {\n"
               "  function deposit(uint256 a) external { a; }\n"
               "  function withdraw(uint256 a) public {}\n"
               "}\n")
        after = _MOD.build_coverage_report(ws)["source_freshness"]
        self.assertEqual(before["source_units_count"], after["source_units_count"])
        self.assertEqual(before["source_units_sha256"], after["source_units_sha256"])
        self.assertNotEqual(before["source_files_sha256"], after["source_files_sha256"])
        self.assertNotEqual(before["denominator_sha256"], after["denominator_sha256"])

    def test_source_freshness_unit_hash_changes_with_new_unit(self):
        ws = self._ws_with_two_functions()
        before = _MOD.build_coverage_report(ws)["source_freshness"]
        _write(ws / "src" / "Vault.sol",
               "contract Vault {\n"
               "  function deposit(uint256 a) external {}\n"
               "  function withdraw(uint256 a) public {}\n"
               "  function claim(uint256 a) public {}\n"
               "}\n")
        after = _MOD.build_coverage_report(ws)["source_freshness"]
        self.assertEqual(after["source_units_count"], 3)
        self.assertNotEqual(before["source_units_sha256"], after["source_units_sha256"])
        self.assertNotEqual(before["denominator_sha256"], after["denominator_sha256"])

    def test_source_freshness_hashes_are_temp_root_stable(self):
        ws1 = self._ws_with_two_functions()
        ws2 = self._tmp / "ws-copy"
        _write(ws2 / "src" / "Vault.sol",
               "contract Vault {\n"
               "  function deposit(uint256 a) external {}\n"
               "  function withdraw(uint256 a) public {}\n"
               "}\n")
        a = _MOD.build_coverage_report(ws1)["source_freshness"]
        b = _MOD.build_coverage_report(ws2)["source_freshness"]
        self.assertEqual(a["scope_globs_sha256"], b["scope_globs_sha256"])
        self.assertEqual(a["source_files_sha256"], b["source_files_sha256"])
        self.assertEqual(a["source_units_sha256"], b["source_units_sha256"])
        self.assertEqual(a["denominator_sha256"], b["denominator_sha256"])

    def test_denominator_disclosure_fields_are_explicit(self):
        ws = self._ws_with_two_functions()
        report = _MOD.build_coverage_report(ws)
        disclosure = report["denominator_disclosure"]

        self.assertTrue(disclosure["explicit"])
        self.assertEqual(disclosure["coverage_basis"], "source-unit")
        self.assertEqual(disclosure["total_units"], report["total_units"])
        self.assertEqual(disclosure["covered_units"], report["covered"])
        self.assertEqual(disclosure["uncovered_units"], report["uncovered"])
        self.assertEqual(disclosure["unit_denominator_by_kind"]["function"], 2)
        self.assertEqual(disclosure["unit_denominator_by_kind"]["source_file"], 0)
        self.assertEqual(disclosure["uncovered_units_by_kind"]["function"], 2)
        self.assertEqual(disclosure["function_denominator_status"], "complete")


class CliTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_cli_coverage_report_json(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "Vault.sol",
               "contract V { function f() external {} }\n")
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--coverage-report",
             "--workspace-path", str(ws), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["schema"], "auditooor.workspace_coverage_report.v1")
        self.assertEqual(out["coverage_basis"], "source-unit")
        self.assertEqual(out["total_units"], 1)
        self.assertEqual(out["uncovered"], 1)
        # the report was also written to disk
        self.assertTrue((ws / ".auditooor" / "coverage_report.json").is_file())

    def test_cli_missing_workspace_path_errors(self):
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--coverage-report",
             "--workspace-path", str(self._tmp / "nope"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)


class SubmissionNumeratorTest(unittest.TestCase):
    """BUG 1: source references cited in finding DRAFTS under <ws>/submissions/
    count toward the COVERAGE NUMERATOR. A draft citing ``Vault.sol::deposit``
    covers THAT unit precisely - it must NOT blanket-cover sibling functions."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ws_two_fn(self) -> Path:
        ws = self._tmp / "ws"
        _write(ws / "src" / "Vault.sol",
               "contract Vault {\n"
               "  function deposit(uint256 a) external {}\n"
               "  function withdraw(uint256 a) public {}\n"
               "}\n")
        return ws

    def test_draft_function_precise_ref_covers_only_that_unit(self):
        # A filed draft cites Vault.sol::deposit -> deposit COVERED, withdraw NOT.
        ws = self._ws_two_fn()
        _write(ws / "submissions" / "filed" / "finding-a" / "finding-a.md",
               "# Finding A\n\nThe bug is in `Vault.sol::deposit` at line 2.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 2)
        self.assertEqual(report["covered"], 1)
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])

    def test_draft_file_line_ref_does_not_cover_function_units(self):
        # A draft citing only `Vault.sol:2` proves a file was mentioned, not
        # that every function in the file was swept.
        ws = self._ws_two_fn()
        _write(ws / "submissions" / "staging" / "finding-b" / "finding-b.md",
               "# Finding B\n\nSee `Vault.sol:2` for the issue.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 0)
        self.assertEqual(report["uncovered"], 2)
        self.assertIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])

    def test_draft_does_not_blanket_cover_uncited_sibling_file(self):
        # A draft citing Vault.sol::deposit must NOT cover a different file the
        # workspace happens to contain. Precise, not blanket-by-workspace.
        ws = self._ws_two_fn()
        _write(ws / "src" / "Other.sol",
               "contract Other { function ping() external {} }\n")
        _write(ws / "submissions" / "filed" / "finding-c" / "finding-c.md",
               "# Finding C\n\nBug in `Vault.sol::deposit`.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertIn("Other.sol::ping", report["uncovered_units"])

    def test_bookkeeping_files_are_not_harvested(self):
        # SUBMISSIONS.md / README.md citing a unit must NOT count - they are
        # trackers, not finding drafts.
        ws = self._ws_two_fn()
        _write(ws / "submissions" / "SUBMISSIONS.md",
               "tracker referencing `Vault.sol::deposit` and `Vault.sol::withdraw`\n")
        _write(ws / "submissions" / "filed" / "README.md",
               "index referencing `Vault.sol::withdraw`\n")
        report = _MOD.build_coverage_report(ws)
        # neither function credited from bookkeeping files
        self.assertEqual(report["covered"], 0)
        self.assertEqual(report["uncovered"], 2)

    def test_legacy_flat_draft_layout_harvested(self):
        # Pre-R41 flat layout: a draft md directly under a status dir is still a
        # finding draft and is harvested.
        ws = self._ws_two_fn()
        _write(ws / "submissions" / "paste_ready" / "VAULT-DEPOSIT-HIGH.md",
               "# Deposit bug\n\n`Vault.sol::deposit` is exploitable.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 1)
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])

    def test_bare_function_ref_with_no_file_covers_nothing(self):
        # OVER-CREDIT FIX (co-occurrence scoping): a draft saying
        # "function withdraw" with NO file basename co-cited covers NOTHING.
        # No file context = no credit. (Previously a global bare-fn token
        # blanket-credited Vault.sol::withdraw - the over-credit honesty hole.)
        ws = self._ws_two_fn()
        _write(ws / "submissions" / "held" / "f" / "f.md",
               "# F\n\nThe issue is in function withdraw(uint256).\n")
        report = _MOD.build_coverage_report(ws)
        # bare fn with no co-cited file -> NEITHER unit credited.
        self.assertIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])
        self.assertEqual(report["covered"], 0)

    def test_bare_fn_scoped_to_cocited_file_only(self):
        # OVER-CREDIT FIX (the core test): a draft citing bare
        # "function deposit" AND the file Vault.sol covers Vault.sol::deposit
        # but does NOT blanket-cover a same-named function in an unrelated file.
        ws = self._ws_two_fn()
        _write(ws / "src" / "Other.sol",
               "contract Other { function deposit() external {} }\n")
        _write(ws / "submissions" / "held" / "f" / "f.md",
               "# F\n\nThe issue is `Vault.sol` in function deposit(uint256).\n")
        report = _MOD.build_coverage_report(ws)
        # Vault.sol::deposit credited (file co-cited in the same artifact)...
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])
        # ...but Other.sol::deposit is NOT (Other.sol never co-cited here).
        self.assertIn("Other.sol::deposit", report["uncovered_units"])


class ScopeModeTest(unittest.TestCase):
    """BUG 2: the DENOMINATOR is scope-aware and the report carries scope_mode.
    Precedence: curated-src > scope-file > unscoped-fallback."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_unscoped_fallback_mode_labelled(self):
        # No symlink farm, no parseable scope file -> unscoped-fallback, and the
        # report says so (so a low number is honestly labelled).
        ws = self._tmp / "ws"
        _write(ws / "src" / "A.sol", "contract A { function f() external {} }\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "unscoped-fallback")
        self.assertEqual(report["scope_globs"], [])
        self.assertEqual(report["enumeration"]["scope_mode"], "unscoped-fallback")

    def test_curated_src_mode_detected_structurally(self):
        # A symlinked src/ child is the structural signature of a curated
        # symlink-farm in-scope root -> curated-src.
        ws = self._tmp / "ws"
        real_pkg = self._tmp / "real_pkg"
        _write(real_pkg / "Vault.sol",
               "contract V { function f() external {} }\n")
        (ws / "src").mkdir(parents=True)
        (ws / "src" / "pkg").symlink_to(real_pkg)
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "curated-src")
        self.assertGreaterEqual(report["total_units"], 1)

    def test_scope_file_overrides_curated_src_symlink(self):
        ws = self._tmp / "ws"
        real_pkg = self._tmp / "real_pkg"
        _write(real_pkg / "Ignored.sol",
               "contract Ignored { function ignored() external {} }\n")
        (ws / "src").mkdir(parents=True)
        (ws / "src" / "pkg").symlink_to(real_pkg)
        _write(ws / "contracts" / "Core.sol",
               "contract Core { function live() external {} }\n")
        _write_json(ws / "scope.json", {"in_scope": ["contracts/Core.sol"]})
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "scope-file")
        self.assertIn("contracts/Core.sol", report["scope_globs"])
        self.assertIn("Core.sol::live", report["uncovered_units"])
        self.assertNotIn("Ignored.sol::ignored", report["uncovered_units"])

    def test_scope_file_mode_restricts_to_in_scope_paths(self):
        # A scope.json listing in-scope path globs -> scope-file, and ONLY the
        # in-scope files are enumerated (the out-of-scope file is excluded from
        # the denominator).
        ws = self._tmp / "ws"
        _write(ws / "src" / "core" / "InScope.sol",
               "contract InScope { function a() external {} }\n")
        _write(ws / "src" / "extra" / "OutScope.sol",
               "contract OutScope { function b() external {} }\n")
        _write_json(ws / "scope.json", {"in_scope": ["src/core/*"]})
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "scope-file")
        self.assertIn("src/core/*", report["scope_globs"])
        # ONLY the in-scope file's units are enumerated
        self.assertIn("InScope.sol::a", report["uncovered_units"])
        self.assertNotIn("OutScope.sol::b",
                         report["uncovered_units"])
        self.assertEqual(report["total_units"], 1)

    def test_scope_json_ignores_out_of_scope_entries(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "core" / "InScope.sol",
               "contract InScope { function a() external {} }\n")
        _write(ws / "src" / "extra" / "OutScope.sol",
               "contract OutScope { function b() external {} }\n")
        _write_json(
            ws / "scope.json",
            {
                "in_scope": ["src/core/*"],
                "out_of_scope": ["src/extra/*"],
            },
        )
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "scope-file")
        self.assertEqual(report["scope_globs"], ["src/core/*"])
        self.assertIn("InScope.sol::a", report["uncovered_units"])
        self.assertNotIn("OutScope.sol::b", report["uncovered_units"])
        self.assertEqual(report["total_units"], 1)

    def test_scope_file_can_select_in_scope_paths_outside_src_when_src_exists(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "Ignored.sol",
               "contract Ignored { function z() external {} }\n")
        _write(ws / "packages" / "core" / "contracts" / "Vault.sol",
               "contract Vault { function deposit() external {} }\n")
        _write_json(ws / "scope.json",
                    {"in_scope": ["packages/core/contracts/Vault.sol"]})
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "scope-file")
        self.assertIn("packages/core/contracts/Vault.sol", report["scope_globs"])
        self.assertIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertNotIn("Ignored.sol::z", report["uncovered_units"])
        self.assertEqual(report["total_units"], 1)

    def test_scope_file_broad_glob_still_prunes_vendor_and_test_dirs(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "core" / "InScope.sol",
               "contract InScope { function a() external {} }\n")
        _write(ws / "test" / "Harness.sol",
               "contract Harness { function h() external {} }\n")
        _write(ws / "lib" / "Dep.sol",
               "contract Dep { function d() external {} }\n")
        _write(ws / "vendor" / "Vendored.sol",
               "contract Vendored { function v() external {} }\n")
        _write(ws / "third_party" / "Third.sol",
               "contract Third { function t() external {} }\n")
        _write_json(ws / "scope.json", {"in_scope": ["**/*.sol"]})
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "scope-file")
        self.assertEqual(report["total_units"], 1)
        self.assertIn("InScope.sol::a", report["uncovered_units"])
        self.assertNotIn("Harness.sol::h", report["uncovered_units"])
        self.assertNotIn("Dep.sol::d", report["uncovered_units"])
        self.assertNotIn("Vendored.sol::v", report["uncovered_units"])
        self.assertNotIn("Third.sol::t", report["uncovered_units"])

    def test_scope_json_subtracts_explicit_oos_from_broad_include(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "core" / "InScope.sol",
               "contract InScope { function a() external {} }\n")
        _write(ws / "src" / "generated" / "OOS.sol",
               "contract OOS { function generated() external {} }\n")
        _write_json(
            ws / "scope.json",
            {
                "in_scope": ["src/**/*.sol"],
                "out_of_scope": ["src/generated/*"],
            },
        )
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "scope-file")
        self.assertEqual(report["scope_globs"], ["src/**/*.sol"])
        self.assertEqual(report["scope_exclude_globs"], ["src/generated/*"])
        self.assertEqual(report["total_units"], 1)
        self.assertIn("InScope.sol::a", report["uncovered_units"])
        self.assertNotIn("OOS.sol::generated", report["uncovered_units"])

    def test_scope_md_prose_excludes_populate_scope_exclude_globs(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "core" / "InScope.sol",
               "contract InScope { function a() external {} }\n")
        _write(ws / "src" / "generated" / "OOS.sol",
               "contract OOS { function generated() external {} }\n")
        _write(ws / "SCOPE.md",
               "# Program\n\n## Assets in scope\n\n"
               "- `src/**/*.sol`\n"
               "- Excluded examples: `src/generated/OOS.sol`\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "scope-file")
        self.assertEqual(report["scope_globs"], ["src/**/*.sol"])
        self.assertEqual(report["scope_exclude_globs"], ["src/generated/OOS.sol"])
        self.assertEqual(report["total_units"], 1)
        self.assertIn("InScope.sol::a", report["uncovered_units"])
        self.assertNotIn("OOS.sol::generated", report["uncovered_units"])

    def test_scope_md_negative_path_does_not_become_only_include(self):
        # NOTE: the second fixture deliberately lives under a NON-OOS dir
        # (`src/extra/`, not `src/generated/`): a `generated/` dir name is
        # independently pruned as codegen by the shared is_oos check, which would
        # confound this test's actual subject (a SCOPE.md "Excluded examples"
        # *prose* line must not narrow scope into scope-file mode).
        ws = self._tmp / "ws"
        _write(ws / "src" / "core" / "InScope.sol",
               "contract InScope { function a() external {} }\n")
        _write(ws / "src" / "extra" / "Extra.sol",
               "contract Extra { function b() external {} }\n")
        _write(ws / "SCOPE.md",
               "# Program\n\n## Assets in scope\n\n"
               "All production contracts are in scope.\n"
               "Excluded examples: `src/extra/Extra.sol`\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "unscoped-fallback")
        self.assertEqual(report["scope_globs"], [])
        self.assertEqual(report["total_units"], 2)
        self.assertIn("InScope.sol::a", report["uncovered_units"])
        self.assertIn("Extra.sol::b", report["uncovered_units"])

    def test_scope_file_md_section_parsed_generically(self):
        # A prose SCOPE.md with an in-scope section listing a real path is parsed
        # generically (no hardcoded literal) into scope-file mode.
        ws = self._tmp / "ws"
        _write(ws / "src" / "contracts" / "Token.sol",
               "contract Token { function mint() external {} }\n")
        _write(ws / "src" / "mocks_off" / "Mock.sol",
               "contract Mock { function m() external {} }\n")
        _write(ws / "SCOPE.md",
               "# Program\n\n## Assets in scope\n\n"
               "- `src/contracts/Token.sol`\n\n"
               "## Out of scope\n\n- `src/mocks_off/Mock.sol`\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "scope-file")
        self.assertEqual(report["total_units"], 1)
        self.assertIn("Token.sol::mint", report["uncovered_units"])

    def test_scope_md_does_not_start_at_assets_out_of_scope_heading(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "contracts" / "Token.sol",
               "contract Token { function mint() external {} }\n")
        _write(ws / "src" / "mocks_off" / "Mock.sol",
               "contract Mock { function m() external {} }\n")
        _write(ws / "SCOPE.md",
               "# Program\n\n## Assets out of scope\n\n"
               "- `src/mocks_off/Mock.sol`\n\n"
               "## Assets in scope\n\n- `src/contracts/Token.sol`\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "scope-file")
        self.assertEqual(report["scope_globs"], ["src/contracts/Token.sol"])
        self.assertIn("Token.sol::mint", report["uncovered_units"])
        self.assertNotIn("Mock.sol::m", report["uncovered_units"])
        self.assertEqual(report["total_units"], 1)

    def test_descriptive_prose_scope_does_not_false_restrict(self):
        # A SCOPE.md that is pure prose (reward tiers, trust model) with NO real
        # asset path must NOT flip into scope-file mode on prose tokens like
        # "network/liveness" or "2/3" - it falls back to unscoped-fallback.
        ws = self._tmp / "ws"
        _write(ws / "src" / "A.sol", "contract A { function f() external {} }\n")
        _write(ws / "SCOPE.md",
               "# Bounty\n\n## In scope\n\n"
               "Trust model: network/liveness under 2/3 honest validators.\n"
               "Reward tiers: Critical/High. Stack: Rust/TS.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["scope_mode"], "unscoped-fallback")
        self.assertEqual(report["total_units"], 1)  # the real .sol still counted


class MegaMimoAnchorNumeratorTest(unittest.TestCase):
    """BUG 3 (part 1): SUCCESS-ONLY mega/mimo per-fn ``function_anchor`` records
    count toward the COVERAGE NUMERATOR. The honesty line: a failed /
    rate-limited record, or one whose anchor file is ``"?"``, must contribute
    NOTHING (crediting it would FABRICATE coverage)."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self._old_root = _MOD.AUDITOOOR_ROOT
        _MOD.AUDITOOOR_ROOT = self._tmp

    def tearDown(self):
        _MOD.AUDITOOOR_ROOT = self._old_root
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_mimo_sidecar(self, path: Path, workspace_path: Path,
                            hint: str = "src/Vault.sol") -> None:
        _write_json(
            path,
            {
                "status": "ok",
                "workspace_path": str(workspace_path),
                "result": json.dumps({
                    "file_path_hint": hint,
                    "applies_to_target": "yes",
                }),
            },
        )

    def test_collect_hits_skips_mismatched_workspace_path(self):
        ws = self._tmp / "audits" / "demo"
        other = self._tmp / "other" / "demo"
        path = (
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mimo_harness_demo" / "mimo_harness_demo_0001.json"
        )
        self._write_mimo_sidecar(path, other)
        hits, _applies = _MOD.collect_hits("demo", workspace_path=ws)
        self.assertEqual(sum(hits.values()), 0)

    def test_collect_hits_keeps_matching_workspace_path(self):
        ws = self._tmp / "audits" / "demo"
        path = (
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mimo_harness_demo" / "mimo_harness_demo_0001.json"
        )
        self._write_mimo_sidecar(path, ws)
        hits, _applies = _MOD.collect_hits("demo", workspace_path=ws)
        self.assertEqual(hits["Vault.sol"], 1)

    def test_collect_hits_skips_missing_workspace_path_when_bound_required(self):
        ws = self._tmp / "audits" / "demo"
        _write_json(
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mimo_harness_demo" / "mimo_harness_demo_0001.json",
            {
                "status": "ok",
                "result": json.dumps({
                    "file_path_hint": "src/Vault.sol",
                    "applies_to_target": "yes",
                }),
            },
        )
        hits, _applies = _MOD.collect_hits("demo", workspace_path=ws)
        self.assertEqual(sum(hits.values()), 0)

    def test_mega_anchor_harvest_skips_mismatched_workspace_path(self):
        ws = self._tmp / "audits" / "demo"
        other = self._tmp / "other" / "demo"
        _write_json(
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mega_demo" / "record.json",
            {
                "status": "ok",
                "workspace_path": str(other),
                "function_anchor": {"file": "src/Vault.sol", "fn": "deposit"},
            },
        )
        tokens: set[str] = set()
        _MOD._harvest_mega_mimo_anchor_tokens("demo", tokens, workspace_path=ws)
        self.assertEqual(tokens, set())

    def test_mega_anchor_harvest_keeps_matching_workspace_path(self):
        ws = self._tmp / "audits" / "demo"
        _write_json(
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mega_demo" / "record.json",
            {
                "status": "ok",
                "workspace_path": str(ws),
                "function_anchor": {"file": "src/Vault.sol", "fn": "deposit"},
            },
        )
        tokens: set[str] = set()
        _MOD._harvest_mega_mimo_anchor_tokens("demo", tokens, workspace_path=ws)
        self.assertIn("Vault.sol", tokens)
        self.assertIn("Vault.sol::deposit", tokens)

    def test_mega_anchor_harvest_covers_only_matching_duplicate_path(self):
        ws = self._tmp / "audits" / "demo"
        _write(ws / "src" / "a" / "Vault.sol",
               "contract VaultA { function deposit() external {} }\n")
        _write(ws / "src" / "b" / "Vault.sol",
               "contract VaultB { function deposit() external {} }\n")
        _write_json(
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mega_demo" / "record.json",
            {
                "status": "ok",
                "workspace_path": str(ws),
                "function_anchor": {"file": "src/a/Vault.sol", "fn": "deposit"},
            },
        )
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 1)
        self.assertEqual(report["uncovered"], 1)
        self.assertIn("src/b/Vault.sol::deposit", report["uncovered_units"])
        self.assertNotIn("src/a/Vault.sol::deposit", report["uncovered_units"])

    def test_mimo_file_path_hint_covers_only_matching_duplicate_path(self):
        ws = self._tmp / "audits" / "demo"
        _write(ws / "src" / "a" / "keeper.go", "package a\n")
        _write(ws / "src" / "b" / "keeper.go", "package b\n")
        path = (
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mimo_harness_demo" / "mimo_harness_demo_0001.json"
        )
        self._write_mimo_sidecar(path, ws, hint="src/a/keeper.go")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 1)
        self.assertEqual(report["uncovered"], 1)
        self.assertIn("src/b/keeper.go", report["uncovered_units"])
        self.assertNotIn("src/a/keeper.go", report["uncovered_units"])

    def test_excluded_duplicate_path_hint_does_not_cover_in_scope_duplicate(self):
        ws = self._tmp / "audits" / "demo"
        _write_json(ws / "scope.json", {
            "in_scope": ["src/core/*"],
            "out_of_scope": ["src/extra/*"],
        })
        _write(ws / "src" / "core" / "Vault.sol",
               "contract VaultCore { function deposit() external {} }\n")
        _write(ws / "src" / "extra" / "Vault.sol",
               "contract VaultExtra { function deposit() external {} }\n")
        _write_json(
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mega_demo" / "record.json",
            {
                "status": "ok",
                "workspace_path": str(ws),
                "function_anchor": {"file": "src/extra/Vault.sol", "fn": "deposit"},
            },
        )
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 1)
        self.assertEqual(report["covered"], 0)
        self.assertIn("src/core/Vault.sol::deposit", report["uncovered_units"])

    def test_mega_anchor_harvest_skips_missing_workspace_path_when_bound_required(self):
        ws = self._tmp / "audits" / "demo"
        _write_json(
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mega_demo" / "record.json",
            {
                "status": "ok",
                "function_anchor": {"file": "src/Vault.sol", "fn": "deposit"},
            },
        )
        tokens: set[str] = set()
        _MOD._harvest_mega_mimo_anchor_tokens("demo", tokens, workspace_path=ws)
        self.assertEqual(tokens, set())

    def test_real_hunt_anchor_marks_unit_covered(self):
        # status=success + real function_anchor.file/fn -> that unit COVERED.
        rec = {
            "status": "ok",
            "error": None,
            "function_anchor": {"file": "src/Vault.sol", "fn": "deposit"},
        }
        self.assertEqual(
            _MOD._mega_record_is_real_hunt(rec), ("src/Vault.sol", "deposit"))
        toks = set()
        # exercise the gate + token shape directly
        real = _MOD._mega_record_is_real_hunt(rec)
        self.assertIsNotNone(real)
        af, fn = real
        base = af.split("/")[-1]
        toks.add(base)
        toks.add(f"{base}::{fn}")
        self.assertTrue(_MOD._unit_is_covered("Vault.sol::deposit", toks))
        # precision: sibling NOT covered by a function-precise token
        self.assertFalse(_MOD._unit_is_covered("Vault.sol::withdraw", toks))

    def test_failed_record_contributes_nothing(self):
        # THE CRITICAL HONESTY TEST: a failed / rate-limited record with anchor
        # "?" must NOT add any token.
        failed = {
            "status": "failed",
            "error": "retry-max-exhausted: rate-limited",
            "function_anchor": {"file": "?", "fn": "?"},
        }
        self.assertIsNone(_MOD._mega_record_is_real_hunt(failed))

    def test_ok_status_but_question_anchor_contributes_nothing(self):
        # status=ok but anchor file "?" (unable-to-anchor) -> NOT a real hunt.
        ok_no_anchor = {
            "status": "ok",
            "error": None,
            "function_anchor": {"file": "?", "fn": "?"},
        }
        self.assertIsNone(_MOD._mega_record_is_real_hunt(ok_no_anchor))

    def test_ok_status_but_nonempty_error_contributes_nothing(self):
        # status ok-ish but a non-empty error string still means the run did
        # not complete a real hunt.
        rec = {
            "status": "ok",
            "error": "rate-limited",
            "function_anchor": {"file": "src/Vault.sol", "fn": "deposit"},
        }
        self.assertIsNone(_MOD._mega_record_is_real_hunt(rec))

    def test_missing_status_contributes_nothing(self):
        rec = {
            "function_anchor": {"file": "src/Vault.sol", "fn": "deposit"},
        }
        self.assertIsNone(_MOD._mega_record_is_real_hunt(rec))

    def test_queued_status_contributes_nothing(self):
        rec = {
            "status": "queued",
            "function_anchor": {"file": "src/Vault.sol", "fn": "deposit"},
        }
        self.assertIsNone(_MOD._mega_record_is_real_hunt(rec))

    def test_anchor_without_fn_is_file_granularity(self):
        # A real file anchor with no fn -> file-granularity token only.
        rec = {
            "status": "ok",
            "function_anchor": {"file": "keeper.go", "fn": "?"},
        }
        real = _MOD._mega_record_is_real_hunt(rec)
        self.assertEqual(real, ("keeper.go", ""))

    def test_stale_source_sidecar_is_skipped_not_covered(self):
        ws = self._tmp / "audits" / "demo"
        _write(ws / "src" / "Vault.sol",
               "contract Vault { function deposit() external {} }\n")
        old_sha = hashlib.sha256(b"old source").hexdigest()
        _write_json(
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mega_demo" / "record.json",
            {
                "status": "ok",
                "workspace_path": str(ws),
                "function_anchor": {"file": "src/Vault.sol", "fn": "deposit"},
                "source_sha256": old_sha,
            },
        )

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 0)
        self.assertIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertEqual(report["skipped_coverage_count"], 1)
        self.assertEqual(report["skipped_coverage"][0]["reason"], "stale_source_sha256")
        self.assertEqual(report["skipped_coverage"][0]["file"], "src/Vault.sol")
        self.assertEqual(report["skipped_coverage"][0]["function"], "deposit")

    def test_missing_denominator_sidecar_path_is_skipped_not_covered(self):
        ws = self._tmp / "audits" / "demo"
        _write(ws / "src" / "keeper.go", "package keeper\n")
        _write_json(
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mimo_harness_demo" / "mimo_harness_demo_0001.json",
            {
                "status": "ok",
                "workspace_path": str(ws),
                "result": json.dumps({
                    "file_path_hint": "contracts/keeper.go",
                    "applies_to_target": "yes",
                }),
            },
        )

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 0)
        self.assertIn("keeper.go", report["uncovered_units"])
        self.assertEqual(report["skipped_coverage_count"], 1)
        self.assertEqual(
            report["skipped_coverage"][0]["reason"],
            "missing_denominator_file",
        )
        self.assertEqual(report["skipped_coverage"][0]["file"], "contracts/keeper.go")

    def test_hallucination_tainted_sidecar_is_skipped_not_covered(self):
        ws = self._tmp / "audits" / "demo"
        _write(ws / "src" / "Vault.sol",
               "contract Vault { function deposit() external {} }\n")
        _write_json(
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mega_demo" / "record.json",
            {
                "status": "ok",
                "workspace_path": str(ws),
                "function_anchor": {"file": "src/Vault.sol", "fn": "deposit"},
                "result": json.dumps({
                    "applies_to_target": "no",
                    "file_line": "N/A",
                    "notes": "R76 hallucination guard: unable-to-anchor",
                }),
            },
        )

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 0)
        self.assertIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertEqual(report["skipped_coverage_count"], 1)
        self.assertEqual(report["skipped_coverage"][0]["reason"], "hallucination_tainted")
        self.assertEqual(report["skipped_coverage"][0]["file"], "src/Vault.sol")
        self.assertEqual(report["skipped_coverage"][0]["function"], "deposit")

    def test_failed_hunt_status_is_reported_not_silent(self):
        ws = self._tmp / "audits" / "demo"
        _write(ws / "src" / "Vault.sol",
               "contract Vault { function deposit() external {} }\n")
        _write_json(
            self._tmp / "audit" / "corpus_tags" / "derived" /
            "mega_demo" / "failed.json",
            {
                "status": "rate-limited",
                "workspace_path": str(ws),
                "function_anchor": {"file": "src/Vault.sol", "fn": "deposit"},
            },
        )

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 0)
        self.assertIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertEqual(report["skipped_coverage_count"], 1)
        self.assertEqual(report["skipped_coverage"][0]["reason"], "hunt_status_rate_limited")
        self.assertEqual(report["skipped_coverage"][0]["file"], "src/Vault.sol")
        self.assertEqual(report["skipped_coverage"][0]["function"], "deposit")

    def test_report_exports_full_denominator_units(self):
        ws = self._tmp / "audits" / "demo"
        _write(
            ws / "src" / "Vault.sol",
            "contract Vault { function deposit() external {} function withdraw() external {} }\n",
        )

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(
            report["denominator_units"],
            ["Vault.sol::deposit", "Vault.sol::withdraw"],
        )
        self.assertEqual(report["total_units"], len(report["denominator_units"]))


class AgentArtifactNumeratorTest(unittest.TestCase):
    """BUG 3 (part 2): source references cited in agent artifact dirs
    (agent_outputs/, poc-tests/, mining_rounds/, findings/,
    deep_counterexamples/, swarm/) count toward the COVERAGE NUMERATOR -
    precisely (not blanket)."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ws_sol_two_fn(self) -> Path:
        ws = self._tmp / "ws"
        _write(ws / "src" / "Vault.sol",
               "contract Vault {\n"
               "  function deposit(uint256 a) external {}\n"
               "  function withdraw(uint256 a) public {}\n"
               "}\n")
        return ws

    def test_agent_output_file_line_ref_does_not_cover_function_units(self):
        # an agent_outputs/ .md citing Foo.sol:52 does not prove every function
        # in the file was covered.
        ws = self._ws_sol_two_fn()
        _write(ws / "agent_outputs" / "dispatch_deposit.md",
               "# Lane\n\nThe issue is at `Vault.sol:2` in deposit.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 0)
        self.assertEqual(report["uncovered"], 2)
        self.assertIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])

    def test_agent_output_fn_precise_ref_is_precise_not_blanket(self):
        # an artifact citing Vault.sol::deposit covers deposit, NOT withdraw.
        ws = self._ws_sol_two_fn()
        _write(ws / "poc-tests" / "lead_deposit" / "PLAN.md",
               "# PoC\n\nDrive `Vault.sol::deposit`.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 1)
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])

    def test_poc_generated_output_dirs_are_not_harvested(self):
        ws = self._ws_sol_two_fn()
        _write(ws / "poc-tests" / "lead_deposit" / "PLAN.md",
               "# PoC\n\nDrive `Vault.sol::deposit`.\n")
        _write_json(ws / "poc-tests" / "lead_deposit" / "out" / "build-info" / "x.json", {
            "file": "src/Vault.sol",
            "function": "withdraw",
        })
        _write_json(ws / "poc-tests" / "lead_deposit" / "crytic-export" / "combined_solc.json", {
            "file": "src/Vault.sol",
            "function": "withdraw",
        })

        report = _MOD.build_coverage_report(ws)

        self.assertEqual(report["covered"], 1)
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])

    def test_agent_output_go_function_precise_ref(self):
        # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
        # Item 3: .go is now FUNCTION-granular, so the SAME precision/honesty
        # rule that governs .sol applies: a function unit (main.go::Foo) is
        # covered only by a function-precise citation, NOT a bare file:line. A
        # file:line `main.go:50` no longer blanket-covers every function (that
        # would fake coverage of uncited functions - the R80 honesty rule).
        ws = self._tmp / "ws"
        _write(ws / "src" / "main.go", "package main\nfunc Foo() {}\n")
        # bare file:line citation does NOT cover the function unit
        _write(ws / "agent_outputs" / "dispatch_file.md",
               "# Lane\n\nPanic reaches make-slice at `main.go:50`.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["total_units"], 1)
        self.assertIn("main.go::Foo", report["uncovered_units"])
        self.assertEqual(report["covered"], 0)
        # a function-precise citation DOES cover it
        _write(ws / "agent_outputs" / "dispatch_fn.md",
               "# Lane\n\nBug in `main.go::Foo`.\n")
        report2 = _MOD.build_coverage_report(ws)
        self.assertEqual(report2["covered"], 1)
        self.assertEqual(report2["uncovered"], 0)

    def test_agent_artifact_does_not_blanket_cover_uncited_file(self):
        # citing Vault.sol::deposit must NOT cover a different file.
        ws = self._ws_sol_two_fn()
        _write(ws / "src" / "Other.sol",
               "contract Other { function ping() external {} }\n")
        _write(ws / "mining_rounds" / "round1.md",
               "# Round\n\nBug in `Vault.sol::deposit`.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertIn("Other.sol::ping", report["uncovered_units"])

    def test_agent_artifact_bookkeeping_index_skipped(self):
        # a README.md / INDEX.md in an artifact dir is bookkeeping, not work.
        ws = self._ws_sol_two_fn()
        _write(ws / "agent_outputs" / "README.md",
               "index referencing `Vault.sol::deposit` and `Vault.sol::withdraw`\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 0)
        self.assertEqual(report["uncovered"], 2)

    def test_swarm_and_deep_counterexamples_dirs_harvested(self):
        # the remaining two artifact dirs are walked too.
        ws = self._ws_sol_two_fn()
        _write(ws / "swarm" / "s.md", "Bug in `Vault.sol::deposit`.\n")
        _write(ws / "deep_counterexamples" / "dc.md",
               "Counterexample on `Vault.sol::withdraw`.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 2)
        self.assertEqual(report["uncovered"], 0)


class PreflightPackNumeratorTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ws_sol_two_fn(self) -> Path:
        ws = self._tmp / "ws"
        _write(ws / "src" / "Vault.sol",
               "contract Vault {\n"
               "  function deposit(uint256 a) external {}\n"
               "  function withdraw(uint256 a) public {}\n"
               "}\n")
        return ws

    def _write_preflight_pack(
        self,
        ws: Path,
        *,
        source_ref: str = "src/Vault.sol:2",
        contract: str = "Vault",
        function: str = "deposit",
        name: str = "pre_flight_pack_Vault_deposit.json",
    ) -> Path:
        pack = ws / ".auditooor" / "pre_flight_packs" / name
        _write_json(pack, {
            "schema": "auditooor.pre_flight_pack.v1",
            "source_ref": source_ref,
            "contract": contract,
            "function": function,
            "target": {
                "contract": contract,
                "function": function,
                "source_ref": source_ref,
            },
        })
        return pack

    def test_preflight_pack_covers_exact_function_not_sibling(self):
        ws = self._ws_sol_two_fn()
        self._write_preflight_pack(ws)

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 1)
        self.assertEqual(report["uncovered"], 1)
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])

        scope = _MOD.resolve_scope(ws)
        units, enum_detail = _MOD.enumerate_units(ws, scope=scope)
        tokens, skipped = _MOD.collect_coverage_tokens_with_skips(
            ws,
            scope=scope,
            units=units,
            enum_detail=enum_detail,
        )
        self.assertEqual(skipped, [])
        self.assertIn("Vault.sol::deposit", tokens)
        self.assertNotIn("Vault.sol::withdraw", tokens)

    def test_preflight_pack_covers_matching_duplicate_path_only(self):
        ws = self._tmp / "ws"
        _write(ws / "src" / "a" / "Vault.sol",
               "contract VaultA { function deposit() external {} }\n")
        _write(ws / "src" / "b" / "Vault.sol",
               "contract VaultB { function deposit() external {} }\n")
        self._write_preflight_pack(
            ws,
            source_ref="src/a/Vault.sol:1",
            name="pre_flight_pack_VaultA_deposit.json",
        )

        report = _MOD.build_coverage_report(ws)
        self.assertEqual(report["covered"], 1)
        self.assertEqual(report["uncovered"], 1)
        self.assertNotIn("src/a/Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("src/b/Vault.sol::deposit", report["uncovered_units"])

        scope = _MOD.resolve_scope(ws)
        units, enum_detail = _MOD.enumerate_units(ws, scope=scope)
        tokens, skipped = _MOD.collect_coverage_tokens_with_skips(
            ws,
            scope=scope,
            units=units,
            enum_detail=enum_detail,
        )
        self.assertEqual(skipped, [])
        self.assertIn("src/a/Vault.sol::deposit", tokens)
        self.assertNotIn("Vault.sol::deposit", tokens)

    def test_preflight_pack_and_manifest_are_numerator_freshness_artifacts(self):
        ws = self._ws_sol_two_fn()
        self._write_preflight_pack(ws)
        manifest = ws / ".auditooor" / "pre_flight_packs" / "manifest.json"
        _write_json(manifest, {
            "schema": "auditooor.pre_flight_pack_manifest.v1",
            "packs": [{
                "contract": "Vault",
                "function": "deposit",
                "source_ref": "src/Vault.sol:2",
                "status": "written",
            }],
        })

        records = _MOD.collect_coverage_numerator_artifact_records(ws)
        paths = {row["path"] for row in records}
        self.assertIn(
            "workspace:.auditooor/pre_flight_packs/manifest.json",
            paths,
        )
        self.assertIn(
            "workspace:.auditooor/pre_flight_packs/pre_flight_pack_Vault_deposit.json",
            paths,
        )

        first = _MOD.build_coverage_report(ws)["numerator_freshness"]
        _write_json(manifest, {
            "schema": "auditooor.pre_flight_pack_manifest.v1",
            "packs": [{
                "contract": "Vault",
                "function": "deposit",
                "source_ref": "src/Vault.sol:2",
                "status": "written",
            }],
            "note": "fresh manifest content changed",
        })
        second = _MOD.build_coverage_report(ws)["numerator_freshness"]

        self.assertEqual(first["coverage_tokens_sha256"], second["coverage_tokens_sha256"])
        self.assertEqual(first["covered_units_sha256"], second["covered_units_sha256"])
        self.assertNotEqual(
            first["numerator_artifacts_sha256"],
            second["numerator_artifacts_sha256"],
        )
        self.assertNotEqual(first["numerator_sha256"], second["numerator_sha256"])


class BareFnCooccurrenceScopingTest(unittest.TestCase):
    """OVER-CREDIT FIX: a bare function-name token must NOT blanket-credit a
    same-named function across ALL files. A bare fn is scoped to the source
    files CO-CITED in the SAME artifact. With no co-cited file it covers
    nothing. File-precise and bare-file coverage are preserved exactly."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ws_vault_other(self) -> Path:
        # Two files, EACH with a deposit() so a bare ``deposit`` is ambiguous.
        ws = self._tmp / "ws"
        _write(ws / "src" / "Vault.sol",
               "contract Vault {\n"
               "  function deposit(uint256 a) external {}\n"
               "  function withdraw(uint256 a) public {}\n"
               "}\n")
        _write(ws / "src" / "Other.sol",
               "contract Other {\n"
               "  function deposit(uint256 a) external {}\n"
               "  function ping() external {}\n"
               "}\n")
        return ws

    # ---- (a) bare fn + co-cited file -> covers ONLY the co-cited file's fn ----
    def test_agent_artifact_bare_fn_scoped_to_cocited_file(self):
        ws = self._ws_vault_other()
        # artifact cites bare `function deposit` AND the file Vault.sol.
        _write(ws / "agent_outputs" / "lane.md",
               "# Lane\n\nLook at `Vault.sol` - the bug is in "
               "function deposit(uint256).\n")
        report = _MOD.build_coverage_report(ws)
        # Vault.sol::deposit COVERED (file co-cited)...
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])
        # ...Other.sol::deposit NOT covered (Other.sol never co-cited).
        self.assertIn("Other.sol::deposit", report["uncovered_units"])
        # withdraw / ping not mentioned -> uncovered
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])
        self.assertIn("Other.sol::ping", report["uncovered_units"])

    # ---- (b) bare fn + NO file -> covers nothing cross-file ----
    def test_agent_artifact_bare_fn_no_file_covers_nothing(self):
        ws = self._ws_vault_other()
        _write(ws / "agent_outputs" / "lane.md",
               "# Lane\n\nThe issue is in function deposit(uint256). No file.\n")
        report = _MOD.build_coverage_report(ws)
        # no co-cited file -> NEITHER deposit credited.
        self.assertIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("Other.sol::deposit", report["uncovered_units"])
        self.assertEqual(report["covered"], 0)

    # ---- (c) file-precise ref still covers exactly that unit (no regression) ----
    def test_file_precise_ref_no_regression(self):
        ws = self._ws_vault_other()
        _write(ws / "poc-tests" / "p.md",
               "# PoC\n\nDrive `Vault.sol::deposit`.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])
        self.assertIn("Other.sol::deposit", report["uncovered_units"])

    # ---- (d) bare-file ref does not cover function-granularity units ----
    def test_bare_file_ref_does_not_cover_function_units(self):
        ws = self._ws_vault_other()
        # citing bare Vault.sol is not enough to credit every function in it.
        _write(ws / "mining_rounds" / "r.md",
               "# Round\n\nSwept file `Vault.sol`.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])
        # Other.sol untouched.
        self.assertIn("Other.sol::deposit", report["uncovered_units"])
        self.assertIn("Other.sol::ping", report["uncovered_units"])

    # ---- JSON harvester: a fn key with no file in the same dict -> no credit --
    def test_json_fn_without_file_in_same_dict_covers_nothing(self):
        ws = self._ws_vault_other()
        # exploit_queue row carries ONLY a function, no file -> no credit.
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [{"function": "deposit"}],
        })
        report = _MOD.build_coverage_report(ws)
        self.assertIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("Other.sol::deposit", report["uncovered_units"])
        self.assertEqual(report["covered"], 0)

    def test_json_path_bare_function_name_does_not_cover_any_function(self):
        ws = self._ws_vault_other()
        # Malformed JSON can put a bare function name into a path-like field.
        # That token must not blanket-credit every same-named function.
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [{"path": "deposit"}],
        })
        report = _MOD.build_coverage_report(ws)
        self.assertIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("Other.sol::deposit", report["uncovered_units"])
        self.assertEqual(report["covered"], 0)

    # ---- JSON harvester: fn + file in the same dict -> file-scoped credit -----
    def test_json_fn_with_file_in_same_dict_is_file_scoped(self):
        ws = self._ws_vault_other()
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [{"file": "src/Vault.sol", "function": "deposit"}],
        })
        report = _MOD.build_coverage_report(ws)
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])
        self.assertIn("Other.sol::deposit", report["uncovered_units"])

    # ---- (e) bare fn is scoped to SAME-LINE files only (tight proximity) ----
    def test_bare_fn_tight_same_line_scoping_no_cross_file_leak(self):
        ws = self._ws_vault_other()
        # The artifact cites Vault.sol on the line that names ``function
        # deposit``. Other.sol is NOT cited anywhere as a bare file (citing it
        # would file-level-credit ALL its fns via the bare-base rule, which is a
        # SEPARATE behavior). We test the bare-FN cross-file attribution: the
        # bare ``function deposit`` must produce a Vault.sol::deposit fn-precise
        # token and NOT an Other.sol::deposit token.
        _write(ws / "swarm" / "s.md",
               "# Swarm\n\n"
               "The bug is in `Vault.sol` function deposit(uint256).\n")
        report = _MOD.build_coverage_report(ws)
        # same-line file (Vault.sol) -> deposit covered
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])
        # Other.sol never cited -> bare ``deposit`` did NOT leak to Other.sol.
        self.assertIn("Other.sol::deposit", report["uncovered_units"])
        # withdraw / ping never named -> uncovered.
        self.assertIn("Vault.sol::withdraw", report["uncovered_units"])
        self.assertIn("Other.sol::ping", report["uncovered_units"])

    # ---- MANDATORY: the exact scenario the partial fix (finite-I) failed ------
    def test_mandatory_same_line_file_credit_no_other_file_leak(self):
        # Two SEPARATE source files each with a ``deposit``. The draft puts
        # ``function deposit`` on a line WITH Vault.sol, and cites Other.sol's
        # deposit ONLY via a fn-PRECISE token (Other.sol::ping) on a different
        # line - so Other.sol has a fn-precise token and the bare-base rule does
        # NOT file-credit its siblings. Assert Vault.sol::deposit COVERED (same
        # line) and Other.sol::deposit NOT covered (the bare ``deposit`` must not
        # leak across to Other.sol from a different line). This is the exact
        # artifact-wide-leak scenario finite-I failed.
        ws = self._ws_vault_other()
        _write(ws / "submissions" / "filed" / "f" / "f.md",
               "# Finding\n\n"
               "`Vault.sol` is vulnerable: function deposit(uint256 a) lets ...\n"
               "Compare against `Other.sol::ping` which guards the same path.\n")
        report = _MOD.build_coverage_report(ws)
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])
        # Other.sol has a fn-precise token (ping) so bare-base does not blanket
        # it; the bare ``deposit`` is scoped to Vault.sol's line only.
        self.assertIn("Other.sol::deposit", report["uncovered_units"])

    # ---- MANDATORY: prose "function is" must NOT emit an ``is`` token ---------
    def test_prose_function_word_does_not_emit_stopword_token(self):
        ws = self._ws_vault_other()
        # A prose line "this function is called" with Vault.sol cited on the SAME
        # line must NOT credit a fn named ``is`` to Vault.sol. The stopword
        # filter (not the absence of a file) is what blocks it - Vault.sol IS on
        # the line. We harvest the tokens directly so the bare-base file-level
        # crediting of Vault.sol does not mask the assertion.
        _write(ws / "submissions" / "filed" / "g" / "g.md",
               "# Note\n\n"
               "Inside `Vault.sol` this function is called during settlement, "
               "and the function for that path is unguarded.\n")
        tokens = _MOD.collect_coverage_tokens(ws)
        # No ::is / ::for fn-precise tokens were manufactured from the prose.
        self.assertNotIn("Vault.sol::is", tokens)
        self.assertNotIn("Vault.sol::for", tokens)
        self.assertNotIn("Other.sol::is", tokens)
        self.assertFalse(
            any(t.endswith("::is") or t.endswith("::for") for t in tokens),
            "prose 'function is' / 'function for' must not manufacture tokens")


class GenericityTest(unittest.TestCase):
    """The coverage logic must contain no hardcoded target/workspace literal."""

    def test_no_hardcoded_target_in_coverage_logic(self):
        src = TOOL.read_text(encoding="utf-8")
        # split off the heatmap mode-1 helpers (which legitimately name the
        # known workspaces for the --all-workspaces convenience list) and check
        # the mode-2 coverage functions carry no target literal.
        start = src.index("def enumerate_units(")
        end = src.index("def main(")
        cov_logic = src[start:end].lower()
        for lit in ("hyperbridge", "dydx", "spark", "mezo", "superearn"):
            self.assertNotIn(lit, cov_logic,
                             f"coverage logic must not hardcode '{lit}'")


class ExplicitScopeAuthoritativeTests(unittest.TestCase):
    """An explicit scope.json is AUTHORITATIVE: it overrides the SCOPE.md prose
    harvest (which over-includes cargo-workspace siblings + can miss sibling-lang
    dirs - observed on the OP Stack monorepo). _-prefixed comment keys in
    scope.json are ignored. Without a JSON scope file, prose parsing is unchanged."""

    def test_scope_json_overrides_prose(self):
        with tempfile.TemporaryDirectory(prefix="scope-auth-") as tmp:
            ws = Path(tmp)
            _write(ws / "SCOPE.md", "# In scope\n- src/rust\n- src/rust/oos-sibling-crate\n")
            _write_json(ws / "scope.json", {
                "_comment": "only op-reth + go dirs; src/rust/oos-sibling-crate is OOS",
                "in_scope": ["src/op-node", "src/rust/op-reth"],
                "out_of_scope": ["src/rust/oos-sibling-crate"],
            })
            g, x = _MOD._parse_scope_globs(ws)
            self.assertEqual(sorted(g), ["src/op-node", "src/rust/op-reth"],
                             "scope.json in_scope must be authoritative (no prose globs)")
            self.assertIn("src/rust/oos-sibling-crate", x)
            self.assertNotIn("src/rust", g, "prose 'src/rust' must NOT leak in")
            self.assertFalse([s for s in g if "only op-reth" in s],
                             "_comment must not be harvested as a glob")

    def test_prose_only_unchanged_without_json(self):
        with tempfile.TemporaryDirectory(prefix="scope-prose-") as tmp:
            ws = Path(tmp)
            _write(ws / "SCOPE.md", "# In scope\n- src/contracts\n")
            g, _x = _MOD._parse_scope_globs(ws)
            self.assertIn("src/contracts", g,
                          "without a JSON scope file, prose parsing must still work")


if __name__ == "__main__":
    unittest.main()
