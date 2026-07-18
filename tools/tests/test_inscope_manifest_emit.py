# <!-- r36-rebuttal: lane-INSCOPE-MANIFEST-EMIT registered in .auditooor/agent_pathspec.json -->
"""Tests for the GENERIC in-scope manifest emitter in
tools/workspace-coverage-heatmap.py (--emit-inscope-manifest, mode 3).

The emitter writes <ws>/.auditooor/inscope_units.jsonl with one row per
in-scope unit, matching the hyperbridge manifest shape EXACTLY:
  {"file", "function", "file_line", "lang", "prior_covered"}.

Covers:
  - a tmpdir fixture with .sol + .rs files yields a non-empty JSONL of the
    right shape (right keys, right lang names, file_line == file:line),
  - the row set REUSES enumerate_units' unit set (function granularity for
    .sol, file granularity for plain .rs),
  - idempotency: a second run keeps the fresh existing manifest (wrote=False),
  - --force overwrites even a fresh manifest,
  - the CLI --emit-inscope-manifest path writes the file and exits 0.

The tool name has hyphens so it is loaded as a module via importlib.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "workspace-coverage-heatmap.py"

_EXPECTED_KEYS = {"file", "function", "file_line", "lang", "prior_covered"}


def _load_mod():
    spec = importlib.util.spec_from_file_location("_inscope_manifest_under_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_inscope_manifest_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_mod()


def _write(p: Path, txt: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(txt, encoding="utf-8")


def _make_ws(tmp: Path) -> Path:
    """A tmpdir fixture workspace with a couple of .sol + .rs source files."""
    ws = tmp / "ws"
    src = ws / "src"
    _write(src / "Vault.sol", (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    constructor() {}\n"
        "    function deposit(uint256 amount) external {}\n"
        "    function withdraw(uint256 amount) external {}\n"
        "}\n"
    ))
    _write(src / "Router.sol", (
        "pragma solidity ^0.8.0;\n"
        "contract Router {\n"
        "    function swap() public {}\n"
        "}\n"
    ))
    _write(src / "engine.rs", (
        "pub fn run() {}\n"
        "fn helper() {}\n"
    ))
    _write(src / "state.rs", (
        "pub struct State;\n"
        "impl State { pub fn commit(&self) {} }\n"
    ))
    return ws


def _read_rows(manifest: Path) -> list[dict]:
    return [
        json.loads(ln)
        for ln in manifest.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]


class TestInscopeManifestEmit(unittest.TestCase):
    # Case 1: emit writes a non-empty JSONL of the right shape.
    def test_emit_writes_nonempty_correct_shape(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            out, count, wrote = _MOD.write_inscope_manifest(ws)
            self.assertTrue(wrote)
            self.assertGreater(count, 0)
            self.assertTrue(out.is_file())
            rows = _read_rows(out)
            self.assertEqual(len(rows), count)
            self.assertGreater(len(rows), 0)
            for r in rows:
                self.assertEqual(set(r.keys()), _EXPECTED_KEYS, r)
                self.assertIsInstance(r["file"], str)
                self.assertIsInstance(r["function"], str)
                self.assertIsInstance(r["file_line"], str)
                self.assertIsInstance(r["lang"], str)
                self.assertIsInstance(r["prior_covered"], bool)
            langs = {r["lang"] for r in rows}
            self.assertIn("solidity", langs)
            self.assertIn("rust", langs)
            # no extension leakage into the lang field
            self.assertNotIn(".sol", langs)
            self.assertNotIn(".rs", langs)

    # Case 2: Solidity AND plain .rs (no rust_source_graph) are BOTH
    # function-granularity - the manifest emitter's generic per-language
    # decomposition (_GENERIC_FN_RE_BY_EXT) mirrors enumerate_units (the
    # coverage denominator), which has function-granularized .rs/.go/.move/
    # .cairo/.vy since bf67eeb0c0. Before this fix .rs collapsed to one
    # function='' placeholder row per file regardless of how many fns it
    # defined (the NUVA .go completeness-matrix divergence bug).
    def test_solidity_and_rust_function_granularity(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            rows = _MOD.build_inscope_manifest_rows(ws)
            sol_fns = {
                r["function"] for r in rows
                if r["lang"] == "solidity" and r["file"].endswith("Vault.sol")
            }
            self.assertIn("deposit", sol_fns)
            self.assertIn("withdraw", sol_fns)
            self.assertIn("constructor", sol_fns)
            # function-level sol rows carry a real file:line
            for r in rows:
                if r["lang"] == "solidity" and r["function"]:
                    f, _, line = r["file_line"].rpartition(":")
                    self.assertEqual(f, r["file"])
                    self.assertTrue(line.isdigit())
                    self.assertGreater(int(line), 0)
            # plain .rs (no rust_source_graph) now decomposes into its real
            # top-level functions, exactly like Solidity - the fixture's
            # engine.rs defines run()+helper() at the top level (the shared
            # _GENERIC_FN_RE_BY_EXT[".rs"] regex, identical to the one
            # enumerate_units uses, anchors on start-of-line `fn`, so a
            # same-line `impl State { pub fn commit(&self) {} }` method in
            # state.rs is a genuine pre-existing regex limitation shared by
            # BOTH enumerators - that file correctly falls back to its
            # never-silently-dropped file-granularity unit, parity-preserved).
            rs_rows = [r for r in rows if r["lang"] == "rust"]
            self.assertTrue(rs_rows)
            engine_fns = {
                r["function"] for r in rs_rows if r["file"].endswith("engine.rs")
            }
            self.assertEqual(engine_fns, {"run", "helper"})
            for r in rs_rows:
                if r["file"].endswith("engine.rs"):
                    self.assertNotEqual(r["function"], "")
                    f, _, line = r["file_line"].rpartition(":")
                    self.assertEqual(f, r["file"])
                    self.assertTrue(line.isdigit())
                    self.assertGreater(int(line), 0)

    # Case 2b: the legacy escape-hatch env gate freezes the PRE-fix shape (one
    # function='' row per non-Solidity/Noir file) for an operator who needs to
    # pin a prior-certified workspace's matrix bit-for-bit.
    def test_legacy_filegran_env_gate_freezes_old_shape(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            os.environ["AUDITOOOR_INSCOPE_MANIFEST_LEGACY_FILEGRAN"] = "1"
            try:
                rows = _MOD.build_inscope_manifest_rows(ws)
            finally:
                del os.environ["AUDITOOOR_INSCOPE_MANIFEST_LEGACY_FILEGRAN"]
            rs_rows = [r for r in rows if r["lang"] == "rust"]
            self.assertTrue(rs_rows)
            for r in rs_rows:
                self.assertEqual(r["function"], "")
                self.assertEqual(r["file_line"], r["file"])

    # Case 3: row unit set matches enumerate_units' denominator exactly.
    def test_rows_match_enumerate_units(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            scope = _MOD.resolve_scope(ws)
            units, _detail = _MOD.enumerate_units(ws, scope=scope)
            rows = _MOD.build_inscope_manifest_rows(ws, scope=scope)
            # rebuild each row's canonical unit key and compare to the unit set.
            row_units = set()
            for r in rows:
                base = Path(r["file"]).name
                key = base  # file granularity (.sol basenames are unambiguous here)
                row_units.add(f"{key}::{r['function']}" if r["function"] else key)
            self.assertEqual(row_units, set(units))

    # Case 2c (NUVA 2026-07-03 reproduction): a Go value-mover file with
    # MULTIPLE real functions must decompose into one row PER function, not
    # collapse to a single function='' placeholder row. Before this fix every
    # .go file in the completeness matrix enumerated as asset_id ending .go ->
    # functions=[{function: '', coverage_status: 'no-callable-function'}]
    # regardless of how many real funcs it defined, so the F1 invariant axis
    # could never demand/credit invariants on the REAL Go value-movers
    # (reconcile.go::CalculateAccruedAUMFee, valuation_engine.go::
    # GetNAVPerShareInUnderlyingAsset, ...).
    def test_go_file_decomposes_into_real_functions(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            _write(ws / "src" / "keeper" / "reconcile.go", (
                "package keeper\n\n"
                "func (k Keeper) CalculateAccruedAUMFee(ctx int) int {\n"
                "\treturn ctx\n"
                "}\n\n"
                "func (k Keeper) Reconcile(ctx int) error {\n"
                "\treturn nil\n"
                "}\n"
            ))
            rows = _MOD.build_inscope_manifest_rows(ws)
            go_rows = [r for r in rows if r["file"].endswith("reconcile.go")]
            self.assertTrue(go_rows)
            go_fns = {r["function"] for r in go_rows}
            # the old bug: {""} (a single no-callable-function placeholder row).
            self.assertEqual(go_fns, {"CalculateAccruedAUMFee", "Reconcile"})
            for r in go_rows:
                self.assertEqual(r["lang"], "go")
                self.assertNotEqual(r["function"], "")
                f, _, line = r["file_line"].rpartition(":")
                self.assertEqual(f, r["file"])
                self.assertTrue(line.isdigit())
                self.assertGreater(int(line), 0)

    # Case 2d: the per-function-invariant manifest (when present) is the
    # authoritative function list, exactly as _enumerate_functions prefers it
    # for the coverage denominator - a manifest-only name (the in-file regex
    # table alone would miss it) still yields a well-formed row.
    def test_go_manifest_index_preferred_over_regex(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            go_rel = "src/keeper/vault.go"
            _write(ws / go_rel, "package keeper\n\nfunc Deposit() {}\n")
            manifest_dir = ws / ".auditooor" / "per_function_invariants"
            manifest_dir.mkdir(parents=True, exist_ok=True)
            (manifest_dir / "manifest.json").write_text(json.dumps({
                "functions": [
                    {"source": f"{go_rel}:3", "function": "Deposit"},
                    {"source": f"{go_rel}:9", "function": "Withdraw"},
                ]
            }), encoding="utf-8")
            rows = _MOD.build_inscope_manifest_rows(ws)
            go_rows = [r for r in rows if r["file"] == go_rel]
            go_fns = {r["function"] for r in go_rows}
            self.assertEqual(go_fns, {"Deposit", "Withdraw"})

    # Case 4: idempotency - a fresh existing manifest is kept; --force overwrites.
    def test_idempotent_then_force(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            out1, count1, wrote1 = _MOD.write_inscope_manifest(ws)
            self.assertTrue(wrote1)
            mtime1 = out1.stat().st_mtime
            time.sleep(0.05)
            # second run: source unchanged + manifest fresh => kept, not rewritten.
            out2, count2, wrote2 = _MOD.write_inscope_manifest(ws)
            self.assertFalse(wrote2)
            self.assertEqual(count2, count1)
            self.assertEqual(out2.stat().st_mtime, mtime1)
            # --force rewrites even though the manifest is fresh.
            time.sleep(0.05)
            out3, count3, wrote3 = _MOD.write_inscope_manifest(ws, force=True)
            self.assertTrue(wrote3)
            self.assertEqual(count3, count1)
            self.assertGreaterEqual(out3.stat().st_mtime, mtime1)

    # Case 5: prior_covered is a bool and at least defaults False with no tokens.
    def test_prior_covered_defaults_false_without_coverage(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            rows = _MOD.build_inscope_manifest_rows(ws)
            # No MIMO sidecars / candidates / drafts in this bare fixture, so no
            # unit can be covered.
            self.assertTrue(all(r["prior_covered"] is False for r in rows))

    # Case 6: the CLI path writes the file and exits 0.
    def test_cli_emit_inscope_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))
            proc = subprocess.run(
                [sys.executable, str(TOOL),
                 "--emit-inscope-manifest",
                 "--workspace-path", str(ws)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = ws / ".auditooor" / "inscope_units.jsonl"
            self.assertTrue(manifest.is_file())
            rows = _read_rows(manifest)
            self.assertGreater(len(rows), 0)
            for r in rows:
                self.assertEqual(set(r.keys()), _EXPECTED_KEYS)

    def test_emitter_excludes_oos_dirs(self):
        # The manifest (and the shared _source_file_records walk) must drop OOS
        # dir segments: previousVersions / dependencies / mocks / script / .t.sol.
        import tempfile
        mod = _load_mod()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            src = ws / "src"
            _write(src / "previousVersions" / "OldVault.sol", "contract OldVault {}\n")
            _write(src / "dependencies" / "forge-std" / "Test.sol", "contract T {}\n")
            _write(src / "mocks" / "MockToken.sol", "contract MockToken {}\n")
            _write(src / "script" / "Deploy.s.sol", "contract D {}\n")
            _write(src / "test" / "Vault.t.sol", "contract VaultTest {}\n")
            mod.write_inscope_manifest(ws)
            files = {r["file"] for r in _read_rows(ws / ".auditooor" / "inscope_units.jsonl")}
            self.assertTrue(any("Vault.sol" in f and "Old" not in f for f in files))
            for oos in ("previousVersions", "/dependencies/", "/mocks/", "/script/", ".t.sol", ".s.sol"):
                self.assertFalse(any(oos in f for f in files), f"{oos} leaked into manifest: {files}")


if __name__ == "__main__":
    unittest.main()
