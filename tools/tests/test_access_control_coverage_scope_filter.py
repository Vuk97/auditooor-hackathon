"""Guard test: access-control-coverage scope-filter (inscope_units.jsonl manifest).

Tests:
  (a) With manifest present: OOS file records are dropped, in-scope records kept.
  (b) Without manifest: no filter applied (legacy behavior preserved).
  (c) AUDITOOOR_FCC_NO_SCOPE_FILTER=1: bypass filter even when manifest exists.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Load the module under test by path (avoids sys.path manipulation games).
# ---------------------------------------------------------------------------
_TOOL = Path(__file__).resolve().parent.parent / "access-control-coverage.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("acc_cov", str(_TOOL))
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# We import once at module level; the module itself is side-effect-free.
acc_cov = _load_module()


# ---------------------------------------------------------------------------
# Helpers to build a minimal tmp workspace.
# ---------------------------------------------------------------------------
def _make_ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".auditooor").mkdir()
    return ws


def _write_inscope(ws: Path, files: list[str]) -> None:
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    with manifest.open("w") as fh:
        for f in files:
            fh.write(json.dumps({"file": f}) + "\n")


def _write_sol(ws: Path, rel: str, body: str = "") -> Path:
    """Create a .sol file under ws at rel path."""
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body or "// empty\n", encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Tests for _load_inscope_file_set
# ---------------------------------------------------------------------------
class TestLoadInscopeFileSet:
    def test_absent_manifest_returns_none(self, tmp_path):
        ws = _make_ws(tmp_path)
        # No manifest created
        result = acc_cov._load_inscope_file_set(ws)
        assert result is None

    def test_empty_manifest_returns_none(self, tmp_path):
        ws = _make_ws(tmp_path)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text("", encoding="utf-8")
        result = acc_cov._load_inscope_file_set(ws)
        assert result is None

    def test_populated_manifest_returns_set(self, tmp_path):
        ws = _make_ws(tmp_path)
        _write_inscope(ws, ["src/Foo.sol", "src/Bar.sol"])
        result = acc_cov._load_inscope_file_set(ws)
        assert result is not None
        assert "src/Foo.sol" in result
        assert "src/Bar.sol" in result

    def test_env_bypass_returns_none(self, tmp_path, monkeypatch):
        ws = _make_ws(tmp_path)
        _write_inscope(ws, ["src/Foo.sol"])
        monkeypatch.setenv("AUDITOOOR_FCC_NO_SCOPE_FILTER", "1")
        result = acc_cov._load_inscope_file_set(ws)
        assert result is None

    def test_path_normalization(self, tmp_path):
        """Leading './' and backslashes are stripped before insertion."""
        ws = _make_ws(tmp_path)
        manifest = ws / ".auditooor" / "inscope_units.jsonl"
        manifest.write_text(
            json.dumps({"file": "./src/Foo.sol"}) + "\n" +
            json.dumps({"file": "src\\Bar.sol"}) + "\n",
            encoding="utf-8",
        )
        result = acc_cov._load_inscope_file_set(ws)
        assert result is not None
        assert "src/Foo.sol" in result
        assert "src/Bar.sol" in result


# ---------------------------------------------------------------------------
# Integration test (a): manifest present - OOS dropped, in-scope kept.
# ---------------------------------------------------------------------------
class TestRunScopeFilter:
    def _make_minimal_ws(self, tmp_path: Path) -> Path:
        """Build a ws with one in-scope .sol and one OOS .sol."""
        ws = _make_ws(tmp_path)

        # In-scope file: simple admin-class function without a guard.
        _write_sol(
            ws,
            "src/InScope.sol",
            body=(
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity ^0.8.0;\n"
                "contract InScope {\n"
                "    function setOwner(address o) public {\n"
                "        owner = o;\n"
                "    }\n"
                "    address public owner;\n"
                "}\n"
            ),
        )

        # OOS file: same pattern but NOT in the manifest.
        _write_sol(
            ws,
            "oos/OutOfScope.sol",
            body=(
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity ^0.8.0;\n"
                "contract OOS {\n"
                "    function setAdmin(address a) public {\n"
                "        admin = a;\n"
                "    }\n"
                "    address public admin;\n"
                "}\n"
            ),
        )

        # Manifest: only in-scope file.
        _write_inscope(ws, ["src/InScope.sol"])
        return ws

    def test_oos_dropped_inscope_kept(self, tmp_path, monkeypatch):
        """The OOS file record must be dropped; the in-scope record must survive."""
        ws = self._make_minimal_ws(tmp_path)
        out = ws / ".auditooor" / "access_control_hypotheses.jsonl"

        # Patch _run_solidity_arm to return controlled hits for both files so we
        # exercise the scope-filter layer without needing Slither.
        def _fake_sol_arm(ws_path):
            return [
                {
                    "file": str(ws_path / "src" / "InScope.sol"),
                    "function": "setOwner",
                    "language": "solidity",
                    "admin_action": "InScope.setOwner writes owner",
                    "guard_check": "UNGUARDED",
                    "guard_reason": "no modifier",
                },
                {
                    "file": str(ws_path / "oos" / "OutOfScope.sol"),
                    "function": "setAdmin",
                    "language": "solidity",
                    "admin_action": "OOS.setAdmin writes admin",
                    "guard_check": "UNGUARDED",
                    "guard_reason": "no modifier",
                },
            ], None

        monkeypatch.setattr(acc_cov, "_run_solidity_arm", _fake_sol_arm)
        monkeypatch.setattr(acc_cov, "_run_go_arm", lambda ws: ([], None))
        monkeypatch.setattr(acc_cov, "_run_rust_arm", lambda ws: ([], None))
        monkeypatch.setattr(acc_cov, "_has_language",
                            lambda ws, suffixes: suffixes == acc_cov._SOL_SUFFIXES)

        summary = acc_cov.run(ws, out)

        # Summary reflects the filter.
        sf = summary["scope_filter"]
        assert sf["applied"] is True, "scope_filter must be applied when manifest exists"
        assert sf["out_of_scope_dropped"] == 1, (
            f"Expected 1 OOS record dropped, got {sf['out_of_scope_dropped']}"
        )

        # Sidecar should only contain the in-scope record.
        records = [
            json.loads(line)
            for line in out.read_text(encoding="utf-8").splitlines()
            if line.strip() and not json.loads(line).get("_acl_skip")
        ]
        assert len(records) == 1, f"Expected 1 in-scope record, got {len(records)}: {records}"
        assert "InScope.sol" in records[0]["file"], (
            f"Expected InScope.sol record, got: {records[0]['file']}"
        )

    def test_no_manifest_no_filter_legacy(self, tmp_path, monkeypatch):
        """Without a manifest, no filter is applied - both records survive (legacy)."""
        ws = _make_ws(tmp_path)
        # No inscope_units.jsonl written.

        _write_sol(ws, "src/A.sol")
        _write_sol(ws, "oos/B.sol")
        out = ws / ".auditooor" / "access_control_hypotheses.jsonl"

        def _fake_sol_arm(ws_path):
            return [
                {
                    "file": str(ws_path / "src" / "A.sol"),
                    "function": "setOwner",
                    "language": "solidity",
                    "admin_action": "A.setOwner",
                    "guard_check": "UNGUARDED",
                    "guard_reason": "no modifier",
                },
                {
                    "file": str(ws_path / "oos" / "B.sol"),
                    "function": "setAdmin",
                    "language": "solidity",
                    "admin_action": "B.setAdmin",
                    "guard_check": "UNGUARDED",
                    "guard_reason": "no modifier",
                },
            ], None

        monkeypatch.setattr(acc_cov, "_run_solidity_arm", _fake_sol_arm)
        monkeypatch.setattr(acc_cov, "_run_go_arm", lambda ws: ([], None))
        monkeypatch.setattr(acc_cov, "_run_rust_arm", lambda ws: ([], None))
        monkeypatch.setattr(acc_cov, "_has_language",
                            lambda ws, suffixes: suffixes == acc_cov._SOL_SUFFIXES)

        summary = acc_cov.run(ws, out)

        sf = summary["scope_filter"]
        assert sf["applied"] is False, "scope_filter must not be applied without manifest"
        assert sf["out_of_scope_dropped"] == 0

        records = [
            json.loads(line)
            for line in out.read_text(encoding="utf-8").splitlines()
            if line.strip() and not json.loads(line).get("_acl_skip")
        ]
        assert len(records) == 2, (
            f"Legacy mode: expected both records to survive, got {len(records)}"
        )
