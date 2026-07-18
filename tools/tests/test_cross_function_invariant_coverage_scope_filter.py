"""Guard test: scope-filter for cross-function-invariant-coverage.py.

Mirrors the equivalent test for function-coverage-completeness.py.
Tests:
  (a) OOS source files are dropped when inscope_units.jsonl is present and
      only names the in-scope file; in-scope file's functions are kept.
  (b) No manifest -> no filter (legacy behavior preserved).
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Load the module under test by path (no package install needed).
# ---------------------------------------------------------------------------
_TOOL = Path(__file__).resolve().parents[1] / "cross-function-invariant-coverage.py"


_MODULE_NAME = "_xfi_cov_scope_test"


def _load_module():
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, str(_TOOL))
    mod = importlib.util.module_from_spec(spec)
    # Must register in sys.modules BEFORE exec_module: Python 3.14 dataclass
    # decorator does a sys.modules lookup for cls.__module__ during class body
    # execution, so if the module isn't yet registered it raises AttributeError.
    sys.modules[_MODULE_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Minimal Solidity fixtures for sibling-pair detection:
# deposit + withdraw in one file => at least one cross-function requirement.
# ---------------------------------------------------------------------------
_INSCOPE_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
    }
}
"""

_OOS_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OosVault {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
    }
}
"""


def _make_ws(tmp_path: Path, *, with_manifest: bool) -> Path:
    """Set up a minimal workspace."""
    ws = tmp_path / "ws"
    ws.mkdir()
    audit_dir = ws / ".auditooor"
    audit_dir.mkdir()

    src = ws / "src"
    src.mkdir()

    # In-scope file
    inscope_file = src / "Vault.sol"
    inscope_file.write_text(_INSCOPE_SOL, encoding="utf-8")

    # Out-of-scope file (same dir - only the manifest distinguishes it)
    oos_dir = src / "oos"
    oos_dir.mkdir()
    oos_file = oos_dir / "OosVault.sol"
    oos_file.write_text(_OOS_SOL, encoding="utf-8")

    if with_manifest:
        # Only the in-scope file is listed
        manifest = audit_dir / "inscope_units.jsonl"
        manifest.write_text(
            json.dumps({"file": "src/Vault.sol"}) + "\n",
            encoding="utf-8",
        )

    return ws


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestScopeFilter:
    def test_oos_dropped_inscope_kept(self, tmp_path, monkeypatch):
        """With manifest: OOS file's functions are excluded from requirements."""
        monkeypatch.delenv("AUDITOOOR_FCC_NO_SCOPE_FILTER", raising=False)
        monkeypatch.delenv("AUDITOOOR_XFI_NO_SCOPE_FILTER", raising=False)
        mod = _load_module()
        ws = _make_ws(tmp_path, with_manifest=True)

        fn_defs, any_source, scope_filter_info = mod._collect_fn_defs(ws)

        # Only in-scope file's functions should remain
        files_seen = {f.file.replace("\\", "/").lstrip("./") for f in fn_defs}
        assert "src/Vault.sol" in files_seen, f"in-scope file missing; got {files_seen}"
        assert not any(
            "oos" in f for f in files_seen
        ), f"OOS file leaked into fn_defs: {files_seen}"

        # Scope filter info should reflect filtering was applied
        assert scope_filter_info["applied"] is True
        assert scope_filter_info["out_of_scope_dropped"] > 0
        assert scope_filter_info["in_scope_files"] == 1

    def test_no_manifest_no_filter(self, tmp_path, monkeypatch):
        """Without manifest: all source files are enumerated (legacy behavior)."""
        monkeypatch.delenv("AUDITOOOR_FCC_NO_SCOPE_FILTER", raising=False)
        monkeypatch.delenv("AUDITOOOR_XFI_NO_SCOPE_FILTER", raising=False)
        mod = _load_module()
        ws = _make_ws(tmp_path, with_manifest=False)

        fn_defs, any_source, scope_filter_info = mod._collect_fn_defs(ws)

        files_seen = {f.file.replace("\\", "/").lstrip("./") for f in fn_defs}
        # Both files should be present (no filter applied)
        assert "src/Vault.sol" in files_seen, f"in-scope file missing; got {files_seen}"
        assert any("oos" in f for f in files_seen), (
            f"OOS file should be present without manifest; got {files_seen}"
        )

        assert scope_filter_info["applied"] is False
        assert scope_filter_info["out_of_scope_dropped"] == 0
        assert scope_filter_info["in_scope_files"] is None

    def test_evaluate_scope_filter_key_present(self, tmp_path, monkeypatch):
        """evaluate() result always carries a 'scope_filter' key."""
        monkeypatch.delenv("AUDITOOOR_FCC_NO_SCOPE_FILTER", raising=False)
        monkeypatch.delenv("AUDITOOOR_XFI_NO_SCOPE_FILTER", raising=False)
        mod = _load_module()
        ws = _make_ws(tmp_path, with_manifest=True)

        result = mod.evaluate(ws)
        assert "scope_filter" in result, f"scope_filter key missing from result: {list(result)}"
        sf = result["scope_filter"]
        assert "applied" in sf
        assert "out_of_scope_dropped" in sf

    def test_env_bypass_disables_filter(self, tmp_path, monkeypatch):
        """AUDITOOOR_XFI_NO_SCOPE_FILTER=1 disables the filter even with manifest."""
        monkeypatch.setenv("AUDITOOOR_XFI_NO_SCOPE_FILTER", "1")
        mod = _load_module()
        ws = _make_ws(tmp_path, with_manifest=True)

        fn_defs, any_source, scope_filter_info = mod._collect_fn_defs(ws)

        files_seen = {f.file.replace("\\", "/").lstrip("./") for f in fn_defs}
        # OOS file should still be present when filter is bypassed
        assert any("oos" in f for f in files_seen), (
            f"env bypass should disable filter; got {files_seen}"
        )
        assert scope_filter_info["applied"] is False
