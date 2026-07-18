"""Guard tests for the scope-filter fix in tools/per-function-invariant-gen.py.

Two scenarios:
  (a) inscope_units.jsonl names ONE in-scope .sol file + an OOS file exists ->
      OOS functions are dropped, in-scope functions are kept.
  (b) no inscope_units.jsonl manifest -> no filter (legacy behavior preserved).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Load the module under test directly (no package install needed)
# ---------------------------------------------------------------------------
_TOOL_PATH = Path(__file__).resolve().parent.parent / "per-function-invariant-gen.py"
_MOD_NAME = "per_function_invariant_gen_scopetest"


def _load_module():
    spec = importlib.util.spec_from_file_location(_MOD_NAME, _TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so dataclass __module__ resolution works.
    sys.modules[_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


_mod = _load_module()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_INSCOPE_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
contract InScope {
    function deposit(uint256 amount) external {
        // in-scope
    }
}
"""

_OOS_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
contract OutOfScope {
    function withdraw(uint256 amount) external {
        // out-of-scope
    }
}
"""


def _make_workspace(tmp_path: Path, write_inscope_manifest: bool) -> tuple[Path, Path, Path]:
    """Return (workspace, inscope_sol_path, oos_sol_path)."""
    ws = tmp_path / "ws"
    src = ws / "src"
    src.mkdir(parents=True)
    oos_dir = ws / "contracts" / "vendor"
    oos_dir.mkdir(parents=True)

    inscope_sol = src / "InScope.sol"
    oos_sol = oos_dir / "OutOfScope.sol"
    inscope_sol.write_text(_INSCOPE_SOL, encoding="utf-8")
    oos_sol.write_text(_OOS_SOL, encoding="utf-8")

    auditooor_dir = ws / ".auditooor"
    auditooor_dir.mkdir(parents=True)

    if write_inscope_manifest:
        manifest_lines = [
            json.dumps({"file": "src/InScope.sol"}),
        ]
        (auditooor_dir / "inscope_units.jsonl").write_text(
            "\n".join(manifest_lines) + "\n", encoding="utf-8"
        )

    return ws, inscope_sol, oos_sol


# ---------------------------------------------------------------------------
# (a) inscope manifest present: OOS dropped, in-scope kept
# ---------------------------------------------------------------------------

def test_scope_filter_drops_oos_keeps_inscope(tmp_path, monkeypatch):
    """When inscope_units.jsonl names InScope.sol only, OutOfScope.sol functions
    must be dropped from the parsed list before harness generation."""
    ws, inscope_sol, oos_sol = _make_workspace(tmp_path, write_inscope_manifest=True)

    # Confirm both files are discovered without filtering
    all_files = _mod.discover_solidity_files(ws, None)
    assert any("InScope.sol" in str(f) for f in all_files), "InScope.sol must be discovered"
    assert any("OutOfScope.sol" in str(f) for f in all_files), "OutOfScope.sol must be discovered"

    # Parse all functions from discovered files
    all_functions = _mod.parse_functions(ws, all_files, include_internal=False, function_filter=None)
    fn_names = [f.function_name for f in all_functions]
    assert "deposit" in fn_names, "deposit (in-scope) must be parsed"
    assert "withdraw" in fn_names, "withdraw (OOS) must be parsed before filter"

    # Apply scope filter (the same logic main() now uses)
    inscope_set = _mod._load_inscope_file_set(ws)
    assert inscope_set is not None, "inscope_units.jsonl must produce a non-None set"
    assert "src/InScope.sol" in inscope_set, "InScope.sol must be in the set"

    def _norm(p):
        return _mod._norm_inscope_path(p)

    filtered = [f for f in all_functions if _norm(f.relative_file) in inscope_set]
    filtered_names = [f.function_name for f in filtered]

    assert "deposit" in filtered_names, "deposit (in-scope) must survive the filter"
    assert "withdraw" not in filtered_names, "withdraw (OOS) must be dropped by the filter"

    # Verify the scope_filter object emitted in the JSON manifest via main()
    output_dir = tmp_path / "out"
    argv = [
        "--workspace", str(ws),
        "--dry-run",
        "--json",
    ]
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = _mod.main(argv)
    assert rc == 0, f"main() must exit 0, got {rc}"
    manifest = json.loads(buf.getvalue())

    sf = manifest.get("scope_filter", {})
    assert sf.get("applied") is True, "scope_filter.applied must be True"
    assert sf.get("in_scope_files") == 1, "scope_filter.in_scope_files must be 1"
    assert sf.get("out_of_scope_dropped", 0) >= 1, "at least 1 OOS function must be reported dropped"

    # The manifest functions list must contain only in-scope functions
    manifest_fn_names = [row["function"] for row in manifest.get("functions", [])]
    assert "deposit" in manifest_fn_names, "deposit must appear in manifest"
    assert "withdraw" not in manifest_fn_names, "withdraw must NOT appear in manifest"


# ---------------------------------------------------------------------------
# (b) no inscope manifest -> no filter (legacy behavior preserved)
# ---------------------------------------------------------------------------

def test_no_scope_filter_when_manifest_absent(tmp_path):
    """When inscope_units.jsonl is absent, _load_inscope_file_set returns None
    and ALL discovered functions are kept (legacy behavior)."""
    ws, inscope_sol, oos_sol = _make_workspace(tmp_path, write_inscope_manifest=False)

    inscope_set = _mod._load_inscope_file_set(ws)
    assert inscope_set is None, "_load_inscope_file_set must return None when manifest is absent"

    all_files = _mod.discover_solidity_files(ws, None)
    all_functions = _mod.parse_functions(ws, all_files, include_internal=False, function_filter=None)
    fn_names = [f.function_name for f in all_functions]

    # Without a manifest, both functions must be present (no filtering).
    assert "deposit" in fn_names, "deposit must be present with no manifest"
    assert "withdraw" in fn_names, "withdraw must be present with no manifest (legacy)"

    # scope_filter.applied must be False in the manifest
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = _mod.main(["--workspace", str(ws), "--dry-run", "--json"])
    assert rc == 0
    manifest = json.loads(buf.getvalue())
    sf = manifest.get("scope_filter", {})
    assert sf.get("applied") is False, "scope_filter.applied must be False when no manifest"
    assert sf.get("out_of_scope_dropped") == 0, "out_of_scope_dropped must be 0 when no manifest"


# ---------------------------------------------------------------------------
# (c) P1-e non-empty-spec assertion (taxonomy mode 18): an empty render must NOT
#     write a 0-byte file; the unit is skipped (status=skipped-empty-render).
# ---------------------------------------------------------------------------

def test_empty_render_skips_unit_and_writes_no_zero_byte_file(tmp_path, monkeypatch):
    """When render_harness collapses to an empty body, the generator must
    fail-closed: skip the unit (status=skipped-empty-render) and write NO file.
    """
    ws, inscope_sol, oos_sol = _make_workspace(tmp_path, write_inscope_manifest=False)

    # Force every render to collapse to empty (simulate a missing pre-flight pack
    # / degraded render that produced nothing).
    monkeypatch.setattr(_mod, "render_harness", lambda *a, **k: "   \n  ")

    out_dir = tmp_path / "out"
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = _mod.main([
            "--workspace", str(ws),
            "--output-dir", str(out_dir),
            "--json",
        ])
    assert rc == 0, f"main() must exit 0, got {rc}"
    manifest = json.loads(buf.getvalue())

    statuses = {row["status"] for row in manifest.get("functions", [])}
    assert statuses == {"skipped-empty-render"}, (
        f"every empty-render unit must be skipped, got statuses={statuses}"
    )
    # No harness file may have been written, and none may be 0 bytes.
    for row in manifest.get("functions", []):
        hp = Path(row["harness_path"])
        assert not hp.exists(), f"empty-render unit must NOT write a file: {hp}"
    if out_dir.exists():
        for f in out_dir.rglob("*.t.sol"):
            assert f.stat().st_size > 0, f"no 0-byte spec may be written: {f}"
