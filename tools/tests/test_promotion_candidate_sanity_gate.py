#!/usr/bin/env python3
"""Tests for tools/promotion-candidate-sanity-gate.py (Wave O-E, Gap #5).

Stdlib-only, hermetic. Covers:
  1. Candidate citing non-existent path → killed_step_1_path_missing
  2. Candidate citing existing in-scope path → survived_to_full_gate
  3. Candidate citing OOS path → killed_step_3_oos
  4. Candidate where path exists but is OOS → killed_step_3
  5. Multi-row mix: survivors + kills → correct output schema
  6. --fast-fail exits 1 when zero survivors
  7. --fast-fail exits 0 when at least one survives
  8. Output JSON schema validation (required top-level keys)
  9. survivors_inline contains only passed rows (not killed rows)
 10. Empty candidate file → empty pass (rc=0)
 11. Missing workspace → rc=2
 12. Invalid JSON candidate → rc=2
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "promotion-candidate-sanity-gate.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("promotion_candidate_sanity_gate", TOOL)
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["promotion_candidate_sanity_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_module()

_DEFAULT_SCOPE_MD = """\
# Scope

## In-scope
- `crates/consensus/`
- `crates/execution/`
- `crates/proof/`

## Out-of-scope
- **OP Stack code**: `op-node`, `op-geth`, `op-batcher`, `op-reth`.
- **ZK prover internals** (SP1 guest programs).
- **Op-Succinct core** (only Base's changes to it are in-scope).
"""


def _mk_workspace(
    ws: Path,
    *,
    scope_md: str = _DEFAULT_SCOPE_MD,
    asset: str = "base",
    files: dict[str, str] | None = None,
) -> Path:
    """Create a minimal workspace fixture at ``ws``."""
    ws.mkdir(parents=True, exist_ok=True)
    ext = ws / "external" / asset
    ext.mkdir(parents=True, exist_ok=True)
    (ws / "SCOPE.md").write_text(scope_md, encoding="utf-8")
    if files:
        for rel_path, content in files.items():
            fp = ext / rel_path
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")
    return ws


def _run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def _write_candidates(path: Path, rows: list[dict]) -> Path:
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Test 1: Non-existent path → killed_step_1
# ---------------------------------------------------------------------------

class TestKilledAtStep1(unittest.TestCase):
    def test_missing_path_killed_step1(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            out = Path(tmp) / "out.json"
            cand = _write_candidates(Path(tmp) / "cand.json", [
                {"production_path": "external/base/crates/nonexistent/foo.rs"},
            ])
            rc = _MOD.run(ws, cand, out, print_json=False, fast_fail=False)
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["killed_at_step_1_count"], 1)
            self.assertEqual(data["survived_row_count"], 0)
            self.assertEqual(data["rows"][0]["verdict"], "killed_step_1_path_missing")


# ---------------------------------------------------------------------------
# Test 2: Existing in-scope path → survived
# ---------------------------------------------------------------------------

class TestSurvivedToFullGate(unittest.TestCase):
    def test_existing_inscope_path_survives(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={"crates/consensus/src/lib.rs": "pub fn foo() {}"},
            )
            out = Path(tmp) / "out.json"
            cand = _write_candidates(Path(tmp) / "cand.json", [
                {"production_path": "external/base/crates/consensus/src/lib.rs"},
            ])
            rc = _MOD.run(ws, cand, out)
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["survived_row_count"], 1)
            self.assertEqual(data["killed_at_step_1_count"], 0)
            self.assertEqual(data["killed_at_step_3_count"], 0)
            self.assertEqual(data["rows"][0]["verdict"], "survived_to_full_gate")


# ---------------------------------------------------------------------------
# Test 3: OOS path that does NOT exist → killed at step 1 (step 3 skipped)
# ---------------------------------------------------------------------------

class TestOOSPathMissing(unittest.TestCase):
    def test_oos_path_missing_killed_step1(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            out = Path(tmp) / "out.json"
            # op-succinct is OOS and the file doesn't exist
            cand = _write_candidates(Path(tmp) / "cand.json", [
                {"production_path": "external/op-succinct/crates/foo/src/lib.rs"},
            ])
            rc = _MOD.run(ws, cand, out)
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            # Step 1 fires first (path missing)
            self.assertEqual(data["rows"][0]["verdict"], "killed_step_1_path_missing")


# ---------------------------------------------------------------------------
# Test 4: Path EXISTS but is OOS → killed at step 3
# ---------------------------------------------------------------------------

class TestOOSPathExists(unittest.TestCase):
    def test_existing_oos_path_killed_step3(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Create the file so step 1 passes, but mark path as OOS
            ws = _mk_workspace(
                Path(tmp) / "ws",
                asset="op-succinct",
                files={"crates/foo/src/lib.rs": "// oos code"},
            )
            out = Path(tmp) / "out.json"
            # The path segment op-succinct triggers OOS
            cand = _write_candidates(Path(tmp) / "cand.json", [
                {"production_path": "external/op-succinct/crates/foo/src/lib.rs"},
            ])
            rc = _MOD.run(ws, cand, out)
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["rows"][0]["step_1_audit_tree_exists"], True)
            self.assertEqual(data["rows"][0]["step_3_scope_status"], "oos")
            self.assertEqual(data["rows"][0]["verdict"], "killed_step_3_oos")
            self.assertEqual(data["killed_at_step_3_count"], 1)


# ---------------------------------------------------------------------------
# Test 5: Multi-row mix — correct schema and counts
# ---------------------------------------------------------------------------

class TestMultiRowMix(unittest.TestCase):
    def test_mixed_rows_correct_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={
                    "crates/execution/src/engine.rs": "// real code",
                    "crates/proof/src/verify.rs": "// real code",
                },
            )
            out = Path(tmp) / "out.json"
            rows = [
                # Survivor
                {"production_path": "external/base/crates/execution/src/engine.rs"},
                # Killed at step 1
                {"production_path": "external/base/crates/ghost/missing.rs"},
                # Another survivor
                {"production_path": "external/base/crates/proof/src/verify.rs"},
                # Killed at step 1 (different missing)
                {"production_path": "external/base/crates/also_missing/lib.rs"},
            ]
            cand = _write_candidates(Path(tmp) / "cand.json", rows)
            rc = _MOD.run(ws, cand, out)
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["input_row_count"], 4)
            self.assertEqual(data["survived_row_count"], 2)
            self.assertEqual(data["killed_at_step_1_count"], 2)
            self.assertEqual(data["killed_at_step_3_count"], 0)
            self.assertEqual(data["passed_to_full_gate_count"], 2)
            self.assertEqual(len(data["rows"]), 4)
            self.assertEqual(len(data["survivors_inline"]), 2)


# ---------------------------------------------------------------------------
# Test 6: --fast-fail exits 1 when zero survivors
# ---------------------------------------------------------------------------

class TestFastFailZeroSurvivors(unittest.TestCase):
    def test_fast_fail_zero_survivors_exit1(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")  # no files created
            out = Path(tmp) / "out.json"
            cand = _write_candidates(Path(tmp) / "cand.json", [
                {"production_path": "external/base/crates/noexist/foo.rs"},
                {"production_path": "external/base/crates/ghost/bar.rs"},
            ])
            rc = _MOD.run(ws, cand, out, fast_fail=True)
            self.assertEqual(rc, 1)


# ---------------------------------------------------------------------------
# Test 7: --fast-fail exits 0 when at least one survives
# ---------------------------------------------------------------------------

class TestFastFailOneSurvivor(unittest.TestCase):
    def test_fast_fail_one_survivor_exit0(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={"crates/consensus/gossip.rs": "// ok"},
            )
            out = Path(tmp) / "out.json"
            cand = _write_candidates(Path(tmp) / "cand.json", [
                {"production_path": "external/base/crates/consensus/gossip.rs"},
                {"production_path": "external/base/crates/noexist/foo.rs"},
            ])
            rc = _MOD.run(ws, cand, out, fast_fail=True)
            self.assertEqual(rc, 0)


# ---------------------------------------------------------------------------
# Test 8: Output JSON schema validation
# ---------------------------------------------------------------------------

class TestOutputSchema(unittest.TestCase):
    REQUIRED_TOP_LEVEL_KEYS = {
        "schema_version",
        "input_candidate_file",
        "input_row_count",
        "survived_row_count",
        "killed_at_step_1_count",
        "killed_at_step_3_count",
        "passed_to_full_gate_count",
        "rows",
        "survivors_inline",
    }
    REQUIRED_ROW_KEYS = {
        "row_index",
        "production_path",
        "step_1_audit_tree_exists",
        "step_3_scope_status",
        "verdict",
        "reason",
    }

    def test_output_schema_keys_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            out = Path(tmp) / "out.json"
            cand = _write_candidates(Path(tmp) / "cand.json", [
                {"production_path": "external/base/crates/foo/bar.rs"},
            ])
            _MOD.run(ws, cand, out)
            data = json.loads(out.read_text())
            self.assertTrue(self.REQUIRED_TOP_LEVEL_KEYS.issubset(data.keys()))
            for row in data["rows"]:
                self.assertTrue(self.REQUIRED_ROW_KEYS.issubset(row.keys()))

    def test_schema_version_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            out = Path(tmp) / "out.json"
            cand = _write_candidates(Path(tmp) / "cand.json", [])
            _MOD.run(ws, cand, out)
            data = json.loads(out.read_text())
            self.assertEqual(
                data["schema_version"],
                "auditooor.promotion_candidate_sanity_gate.v1",
            )


# ---------------------------------------------------------------------------
# Test 9: survivors_inline contains only passed rows
# ---------------------------------------------------------------------------

class TestSurvivorsInlineContent(unittest.TestCase):
    def test_survivors_inline_matches_passed_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={"crates/proof/src/kzg.rs": "// kzg"},
            )
            out = Path(tmp) / "out.json"
            survivor_row = {
                "production_path": "external/base/crates/proof/src/kzg.rs",
                "my_custom_field": "preserved",
            }
            killed_row = {
                "production_path": "external/base/crates/dead/missing.rs",
                "my_custom_field": "not_in_survivors",
            }
            cand = _write_candidates(Path(tmp) / "cand.json", [survivor_row, killed_row])
            _MOD.run(ws, cand, out)
            data = json.loads(out.read_text())
            self.assertEqual(len(data["survivors_inline"]), 1)
            # The original row data is preserved intact
            self.assertEqual(
                data["survivors_inline"][0]["my_custom_field"], "preserved"
            )
            self.assertEqual(
                data["survivors_inline"][0]["production_path"],
                "external/base/crates/proof/src/kzg.rs",
            )


# ---------------------------------------------------------------------------
# Test 10: Empty candidate file → empty pass (rc=0)
# ---------------------------------------------------------------------------

class TestEmptyCandidateFile(unittest.TestCase):
    def test_empty_list_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            out = Path(tmp) / "out.json"
            cand = _write_candidates(Path(tmp) / "cand.json", [])
            rc = _MOD.run(ws, cand, out)
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["input_row_count"], 0)
            self.assertEqual(data["survived_row_count"], 0)

    def test_empty_dict_with_candidates_key_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            out = Path(tmp) / "out.json"
            cand = Path(tmp) / "cand.json"
            cand.write_text(json.dumps({"candidates": []}), encoding="utf-8")
            rc = _MOD.run(ws, cand, out)
            self.assertEqual(rc, 0)


# ---------------------------------------------------------------------------
# Test 11: Missing workspace → rc=2
# ---------------------------------------------------------------------------

class TestMissingWorkspace(unittest.TestCase):
    def test_missing_workspace_rc2(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            cand = _write_candidates(Path(tmp) / "cand.json", [])
            result = _run_cli([
                "--workspace", "/nonexistent/path/to/ws",
                "--candidate", str(cand),
                "--output", str(out),
            ])
            self.assertEqual(result.returncode, 2)


# ---------------------------------------------------------------------------
# Test 12: Invalid JSON → rc=2
# ---------------------------------------------------------------------------

class TestInvalidJSON(unittest.TestCase):
    def test_invalid_json_rc2(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            out = Path(tmp) / "out.json"
            cand = Path(tmp) / "cand.json"
            cand.write_text("{not valid json!!!", encoding="utf-8")
            result = _run_cli([
                "--workspace", str(ws),
                "--candidate", str(cand),
                "--output", str(out),
            ])
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
