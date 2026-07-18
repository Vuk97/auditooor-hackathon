"""Tests for coverage-plane-build.py - the durable (unit x impact-frame) coverage
plane artifact.

THE GAP THIS CLOSES: vault_coverage_plane (tools/vault-mcp-server.py) exposes the
(unit x frame) completeness plane only on-demand via MCP; nothing writes a durable
file-based artifact a gate/CI step can read without an MCP round trip. This tool
materializes `.auditooor/coverage_plane.jsonl` + a summary JSON.

Core guarantees under test:
  (a) JOIN correctness: N in-scope units x M applicable-language impact frames ->
      exactly N*M rows, one per (unit, frame) cell.
  (b) the applicable-frame-per-language JOIN and per-unit status are REUSED from
      completeness-matrix-build.py (not reimplemented) - same frame set for the
      same language.
  (c) summary counts (cells_total/covered/open/not_enumerated/out_of_scope) are
      internally consistent (they sum to cells_total) and match a hand count.
  (d) language-agnostic: works off inscope_units.jsonl `lang`/extension, no
      solidity-only path assumption (`src/` is not required).
  (e) two distinct inscope_units.jsonl rows for the same (file, function) at
      different `file_line`s (e.g. an overloaded/duplicate-named declaration) are
      NOT collapsed into one unit (regression: this under-counted units_total on a
      real workspace before the file_line disambiguator was added).
  (f) STRICT/--check fail-closed posture is gated behind an explicit opt-in
      (AUDITOOOR_COVERAGE_PLANE_STRICT or --strict) so a default invocation never
      returns rc 1 merely because a workspace has zero units.
"""
import importlib.util
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

_MOD_PATH = Path(__file__).resolve().parents[1] / "coverage-plane-build.py"
_CMB_PATH = Path(__file__).resolve().parents[1] / "completeness-matrix-build.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cpb = _load_module(_MOD_PATH, "coverage_plane_build_under_test")
cmb = _load_module(_CMB_PATH, "completeness_matrix_build_under_test")

# The real solidity applicable-frame set from the shared seed (same source
# _inscope_impact_frames_for_lang / _load_mechanism_library draws from). Read
# dynamically rather than hardcoded so this test tracks the seed, not a snapshot.
_SOLIDITY_FRAMES = sorted(
    cmb._inscope_impact_frames_for_lang("solidity", cmb._MECHANISM_LIBRARY_SEED)
)


def _write_inscope(ws: Path, rows: list[dict]) -> None:
    a = ws / ".auditooor"
    a.mkdir(parents=True, exist_ok=True)
    (a / "inscope_units.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
    )


class JoinCorrectnessTest(unittest.TestCase):
    """(a)/(c): a small 2-file fixture must produce exactly units*frames rows and
    internally-consistent summary counts."""

    def test_two_files_join_produces_exact_cross_product(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inscope(ws, [
                {"file": "chain/moduleA.sol", "function": "deposit", "lang": "solidity"},
                {"file": "chain/moduleB.sol", "function": "withdraw", "lang": "solidity"},
            ])
            result = cpb.build_plane(ws)
            rows = result["rows"]
            summary = result["summary"]

            expected_frames = len(_SOLIDITY_FRAMES)
            self.assertGreaterEqual(expected_frames, 1, "fixture needs >=1 solidity frame")
            self.assertEqual(len(rows), 2 * expected_frames)
            self.assertEqual(summary["units_total"], 2)
            self.assertEqual(summary["frames_total"], expected_frames)
            self.assertEqual(summary["cells_total"], 2 * expected_frames)

            # every row is schema-tagged and carries a frame from the shared seed
            for r in rows:
                self.assertEqual(r["schema"], cpb.SCHEMA)
                self.assertIn(r["frame"], _SOLIDITY_FRAMES)
                self.assertIn(r["status"], (
                    "covered", "open", "not-enumerated", "out-of-scope-fcc-filtered"
                ))

            # both units appear, each with exactly `expected_frames` rows
            units = {}
            for r in rows:
                units.setdefault(r["unit"], set()).add(r["frame"])
            self.assertEqual(len(units), 2)
            for frames in units.values():
                self.assertEqual(len(frames), expected_frames)

    def test_summary_counts_are_internally_consistent(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inscope(ws, [
                {"file": "chain/moduleA.sol", "function": "deposit", "lang": "solidity"},
                {"file": "chain/moduleB.sol", "function": "withdraw", "lang": "solidity"},
                {"file": "chain/moduleC.sol", "function": "redeem", "lang": "solidity"},
            ])
            result = cpb.build_plane(ws)
            s = result["summary"]
            self.assertEqual(
                s["cells_covered"] + s["cells_open"] + s["cells_not_enumerated"]
                + s["cells_out_of_scope"],
                s["cells_total"],
            )
            # no coverage evidence at all -> every cell not-enumerated (fail-closed)
            self.assertEqual(s["cells_not_enumerated"], s["cells_total"])
            self.assertEqual(s["cells_covered"], 0)


class ReuseNotDuplicateTest(unittest.TestCase):
    """(b): the frame set materialized per language must be IDENTICAL to
    completeness-matrix-build.py's own applicable-frame JOIN for that language - this
    tool must not silently drift from the shared source of truth."""

    def test_frame_set_matches_completeness_matrix_build_join(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inscope(ws, [
                {"file": "chain/moduleA.sol", "function": "f", "lang": "solidity"},
            ])
            result = cpb.build_plane(ws)
            frames_in_plane = {r["frame"] for r in result["rows"]}
            self.assertEqual(frames_in_plane, set(_SOLIDITY_FRAMES))


class CoverageStatusJoinTest(unittest.TestCase):
    """A unit with a hunt verdict sidecar (any frame, legacy no-suffix form) is
    credited 'covered' for every applicable frame - matches
    completeness-matrix-build.py's backward-compat any-sidecar crediting."""

    def test_hunt_examined_unit_credits_covered(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inscope(ws, [
                {"file": "chain/moduleA.sol", "function": "f", "lang": "solidity"},
            ])
            d = ws / ".auditooor" / "hunt_findings_sidecars"
            d.mkdir(parents=True)
            (d / "hunt__moduleA.sol__f__deadbeef__L2.json").write_text(
                json.dumps({
                    "function_anchor": {"fn": "f", "file": "chain/moduleA.sol"},
                    "file_line": "chain/moduleA.sol:2", "verdict": "KILL",
                }),
                encoding="utf-8",
            )
            result = cpb.build_plane(ws)
            statuses = {r["status"] for r in result["rows"]}
            self.assertEqual(statuses, {"covered"})
            self.assertEqual(result["summary"]["cells_open"], 0)
            self.assertEqual(result["summary"]["cells_not_enumerated"], 0)


class FccFilteredNonEntryTest(unittest.TestCase):
    """A unit fcc's terminal gate would drop as non-entry (internal/view/pure) reuses
    _is_fcc_filtered_nonentry and is credited 'out-of-scope-fcc-filtered', matching
    completeness_matrix.json's own classification rather than reading as a gap."""

    def test_internal_function_credited_out_of_scope(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "chain").mkdir(parents=True)
            (ws / "chain" / "moduleA.sol").write_text(
                "contract A {\n"
                "    function _helper(uint256 x) internal pure returns (uint256) {\n"
                "        return x;\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            _write_inscope(ws, [
                {"file": "chain/moduleA.sol", "function": "_helper", "lang": "solidity"},
            ])
            (ws / ".auditooor" / "function_coverage_completeness.json").write_text(
                json.dumps({
                    "verdict": "pass-fully-covered",
                    "counts": {"hollow": 0, "untouched": 0},
                    "functions": [],
                }),
                encoding="utf-8",
            )
            result = cpb.build_plane(ws)
            statuses = {r["status"] for r in result["rows"]}
            self.assertEqual(statuses, {"out-of-scope-fcc-filtered"})
            self.assertEqual(result["summary"]["cells_not_enumerated"], 0)
            self.assertEqual(result["summary"]["cells_out_of_scope"], len(_SOLIDITY_FRAMES))


class DuplicateFileLineDisambiguationTest(unittest.TestCase):
    """(e) regression: two inscope_units.jsonl rows for the SAME (file, function) at
    different file_line (e.g. an overloaded/duplicate-named declaration - observed on
    a real workspace: Accounting.sol::totalAssets declared at both line 148 and 164)
    must be treated as two DISTINCT units, not collapsed into one units_total entry."""

    def test_duplicate_function_name_different_lines_counted_separately(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inscope(ws, [
                {"file": "chain/moduleA.sol", "function": "totalAssets",
                 "file_line": "chain/moduleA.sol:148", "lang": "solidity"},
                {"file": "chain/moduleA.sol", "function": "totalAssets",
                 "file_line": "chain/moduleA.sol:164", "lang": "solidity"},
            ])
            result = cpb.build_plane(ws)
            s = result["summary"]
            self.assertEqual(s["units_total"], 2)
            self.assertEqual(s["cells_total"], 2 * len(_SOLIDITY_FRAMES))
            units = {r["unit"] for r in result["rows"]}
            self.assertEqual(len(units), 2)


class LanguageAgnosticTest(unittest.TestCase):
    """(d): a non-solidity, non-`src/`-rooted unit still joins against its language's
    applicable frame set (no solidity/`src/`-path assumption)."""

    def test_go_unit_without_src_prefix_gets_go_frames(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inscope(ws, [
                {"file": "chain/keeper/module.go", "function": "Handle", "lang": "go"},
            ])
            result = cpb.build_plane(ws)
            go_frames = set(cmb._inscope_impact_frames_for_lang(
                "go", cmb._MECHANISM_LIBRARY_SEED))
            self.assertGreaterEqual(len(go_frames), 1)
            frames_in_plane = {r["frame"] for r in result["rows"]}
            self.assertEqual(frames_in_plane, go_frames)
            self.assertTrue(all(r["lang"] == "go" for r in result["rows"]))
            self.assertTrue(all(r["asset"] for r in result["rows"]),
                             "asset key must resolve without a src/<repo> prefix")


class WriteArtifactTest(unittest.TestCase):
    """The tool writes a real durable jsonl + summary artifact (the actual fix under
    test: vault_coverage_plane has no file-based sibling today)."""

    def test_write_plane_creates_jsonl_and_summary(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inscope(ws, [
                {"file": "chain/moduleA.sol", "function": "f", "lang": "solidity"},
            ])
            result = cpb.build_plane(ws)
            plane_path, summary_path = cpb.write_plane(ws, result)
            self.assertTrue(plane_path.is_file())
            self.assertTrue(summary_path.is_file())
            lines = plane_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), len(_SOLIDITY_FRAMES))
            for line in lines:
                row = json.loads(line)
                self.assertEqual(row["schema"], cpb.SCHEMA)
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["cells_total"], len(_SOLIDITY_FRAMES))
            self.assertEqual(plane_path.name, "coverage_plane.jsonl")
            self.assertEqual(summary_path.name, "coverage_plane_summary.json")


class CliStrictGatingTest(unittest.TestCase):
    """(f): --check without STRICT never fails merely because the workspace is
    empty; STRICT opt-in (env or --strict) makes it fail closed."""

    def test_check_without_strict_passes_on_empty_workspace(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir(parents=True)
            rc = cpb.main(["--workspace", str(ws), "--check"])
            self.assertEqual(rc, 0)

    def test_check_with_strict_fails_on_empty_workspace(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir(parents=True)
            rc = cpb.main(["--workspace", str(ws), "--check", "--strict"])
            self.assertEqual(rc, 1)

    def test_check_with_strict_env_fails_on_empty_workspace(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir(parents=True)
            old = os.environ.get("AUDITOOOR_COVERAGE_PLANE_STRICT")
            os.environ["AUDITOOOR_COVERAGE_PLANE_STRICT"] = "1"
            try:
                rc = cpb.main(["--workspace", str(ws), "--check"])
            finally:
                if old is None:
                    os.environ.pop("AUDITOOOR_COVERAGE_PLANE_STRICT", None)
                else:
                    os.environ["AUDITOOOR_COVERAGE_PLANE_STRICT"] = old
            self.assertEqual(rc, 1)

    def test_check_passes_on_populated_workspace_without_strict(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inscope(ws, [
                {"file": "chain/moduleA.sol", "function": "f", "lang": "solidity"},
            ])
            rc = cpb.main(["--workspace", str(ws), "--check"])
            self.assertEqual(rc, 0)

    def test_missing_workspace_dir_fails(self):
        rc = cpb.main(["--workspace", "/nonexistent/path/for/coverage-plane-test"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
