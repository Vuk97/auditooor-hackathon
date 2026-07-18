"""Guard test for the scope-filter fix in economic-invariant-detectors.py.

Two scenarios:
  (a) Manifest present: OOS file dropped, in-scope file kept.
  (b) No manifest: no filtering (legacy behavior preserved).
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Load the tool under test without executing main()
# ---------------------------------------------------------------------------
_TOOL_PATH = Path(__file__).resolve().parent.parent / "economic-invariant-detectors.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("eid", _TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Minimal Solidity snippets that reliably hit DET-1 (debt write, no floor)
# ---------------------------------------------------------------------------
_INSCOPE_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract InScope {
    struct Position { uint256 debt; }
    mapping(address => Position) public positions;
    function borrow(address user, uint256 amount) external {
        positions[user].debt += amount;
    }
}
"""

_OOS_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract OutOfScope {
    struct Position { uint256 debt; }
    mapping(address => Position) public positions;
    function borrow(address user, uint256 amount) external {
        positions[user].debt += amount;
    }
}
"""


def _make_ws(tmp_path: Path, *, with_manifest: bool) -> tuple[Path, Path, Path]:
    """Create a minimal workspace with one in-scope and one OOS source file.

    Returns (ws, in_scope_file, oos_file).
    """
    src = tmp_path / "src"
    src.mkdir()
    oos_dir = tmp_path / "oos_pkg"
    oos_dir.mkdir()

    inscope_file = src / "InScope.sol"
    inscope_file.write_text(_INSCOPE_SOL, encoding="utf-8")

    oos_file = oos_dir / "OutOfScope.sol"
    oos_file.write_text(_OOS_SOL, encoding="utf-8")

    auditooor_dir = tmp_path / ".auditooor"
    auditooor_dir.mkdir()

    if with_manifest:
        manifest = auditooor_dir / "inscope_units.jsonl"
        # Only the in-scope file is listed (ws-relative posix path).
        manifest.write_text(
            json.dumps({"file": "src/InScope.sol"}) + "\n",
            encoding="utf-8",
        )

    return tmp_path, inscope_file, oos_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect(mod, ws: Path) -> dict:
    """Call the tool's internal _detect() directly."""
    return mod._detect(ws)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestScopeFilterApplied:
    """When inscope_units.jsonl is present, OOS files must be dropped."""

    def setup_method(self, _method):
        # Ensure the env bypass is NOT set for these tests.
        os.environ.pop("AUDITOOOR_FCC_NO_SCOPE_FILTER", None)

    def test_oos_file_dropped_and_inscope_kept(self, tmp_path):
        mod = _load_tool()
        ws, inscope_file, oos_file = _make_ws(tmp_path, with_manifest=True)
        result = _detect(mod, ws)

        sf = result.get("scope_filter", {})
        assert sf.get("applied") is True, "scope_filter.applied must be True when manifest present"
        assert sf.get("source") == ".auditooor/inscope_units.jsonl"
        assert sf.get("in_scope_files") == 1

        # OOS file must have been dropped (out_of_scope_dropped >= 1).
        assert sf.get("out_of_scope_dropped", 0) >= 1, (
            "Expected at least one OOS file dropped, got scope_filter=%r" % sf
        )

        # Any hits that surfaced must come from the in-scope file only.
        hits = result.get("hits", [])
        oos_rel = str(oos_file.relative_to(ws)).replace("\\", "/")
        for h in hits:
            fl = h.get("file_line", "")
            assert not fl.startswith(oos_rel), (
                f"Hit from OOS file leaked through scope filter: {fl}"
            )

    def test_scope_filter_key_present_in_result(self, tmp_path):
        mod = _load_tool()
        ws, _, _ = _make_ws(tmp_path, with_manifest=True)
        result = _detect(mod, ws)
        assert "scope_filter" in result, "scope_filter key must be present in result dict"
        sf = result["scope_filter"]
        for key in ("applied", "source", "in_scope_files", "out_of_scope_dropped"):
            assert key in sf, f"scope_filter must contain key '{key}'"


class TestScopeFilterAbsent:
    """When no manifest exists, no filtering should occur (legacy)."""

    def setup_method(self, _method):
        os.environ.pop("AUDITOOOR_FCC_NO_SCOPE_FILTER", None)

    def test_no_manifest_no_filter(self, tmp_path):
        mod = _load_tool()
        ws, _, _ = _make_ws(tmp_path, with_manifest=False)
        result = _detect(mod, ws)

        sf = result.get("scope_filter", {})
        assert sf.get("applied") is False, (
            "scope_filter.applied must be False when manifest is absent"
        )
        assert sf.get("out_of_scope_dropped", 0) == 0

    def test_both_files_scanned_without_manifest(self, tmp_path):
        """Without a manifest both files (in-scope + OOS) are scanned."""
        mod = _load_tool()
        ws, _, _ = _make_ws(tmp_path, with_manifest=False)
        result = _detect(mod, ws)
        # Both files have DET-1 borrow() patterns - at least 2 hits expected.
        hits = result.get("hits", [])
        assert len(hits) >= 2, (
            "Without a manifest both source files should produce hits; got %d" % len(hits)
        )


class TestEnvBypass:
    """AUDITOOOR_FCC_NO_SCOPE_FILTER=1 disables filtering even when manifest present."""

    def test_env_bypass_disables_filter(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AUDITOOOR_FCC_NO_SCOPE_FILTER", "1")
        mod = _load_tool()
        ws, _, _ = _make_ws(tmp_path, with_manifest=True)
        result = _detect(mod, ws)
        sf = result.get("scope_filter", {})
        assert sf.get("applied") is False, (
            "Env bypass AUDITOOOR_FCC_NO_SCOPE_FILTER=1 must disable scope filtering"
        )
