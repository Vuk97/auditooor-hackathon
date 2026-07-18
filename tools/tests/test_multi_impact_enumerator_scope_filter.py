"""Guard test for the scope-filter fix in multi-impact-enumerator.py.

Verifies:
  (a) When inscope_units.jsonl names ONE in-scope .sol file and an OOS file is
      referenced, the OOS file produces 0 rows and in-scope file keeps rows.
  (b) No manifest -> no filter (legacy behavior: rows produced for any file).
"""
import argparse
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

# Load the hyphenated-filename module via importlib (not importable as an
# identifier due to the dashes in the filename).
_TOOLS = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "multi_impact_enumerator",
    _TOOLS / "multi-impact-enumerator.py",
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
mie = _mod


def _make_ws(tmp: Path, inscope_files: list | None = None) -> Path:
    """Create a minimal workspace with optional inscope_units.jsonl."""
    ws = tmp / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    dot = ws / ".auditooor"
    dot.mkdir(exist_ok=True)

    # Write a real in-scope .sol source file.
    src = ws / "src"
    src.mkdir(exist_ok=True)
    (src / "Vault.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    function deposit(uint amount) external {\n"
        "        // body\n"
        "    }\n"
        "}\n"
    )
    # Out-of-scope file (simulates a kona/cannon crate on OP Stack).
    oos = ws / "oos"
    oos.mkdir(exist_ok=True)
    (oos / "Cannon.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract Cannon {\n"
        "    function fire() external {}\n"
        "}\n"
    )

    if inscope_files is not None:
        lines = [json.dumps({"file": f}) for f in inscope_files]
        (dot / "inscope_units.jsonl").write_text("\n".join(lines) + "\n")

    return ws


def _run(ws: Path, file_line: str, pattern: str = "reentrancy") -> dict:
    """Run mie.run() with --pattern + --file-line on the given workspace."""
    args = argparse.Namespace(
        workspace=ws,
        pattern=pattern,
        function="",
        file_line=file_line,
        candidate=None,
        finding_file=None,
        json=True,
    )
    rc, payload = mie.run(args)
    return payload


class TestScopeFilterApplied:
    """Manifest present: OOS file dropped, in-scope file kept."""

    def setup_method(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        # Only src/Vault.sol is in scope; oos/Cannon.sol is OOS.
        self.ws = _make_ws(self.tmp, inscope_files=["src/Vault.sol"])

    def teardown_method(self):
        self._tmp.cleanup()

    def test_oos_file_produces_zero_rows(self):
        payload = _run(self.ws, "oos/Cannon.sol:4")
        assert payload["rows"] == [], (
            f"Expected 0 rows for OOS file, got {len(payload['rows'])}: {payload}"
        )
        sf = payload.get("scope_filter", {})
        assert sf.get("applied") is True, f"scope_filter.applied should be True: {sf}"
        assert sf.get("out_of_scope_dropped") == 1, (
            f"Expected out_of_scope_dropped=1: {sf}"
        )

    def test_inscope_file_produces_rows(self):
        payload = _run(self.ws, "src/Vault.sol:4")
        rows = payload.get("rows", [])
        assert len(rows) > 0, (
            f"Expected >0 rows for in-scope file, got 0: {payload}"
        )
        sf = payload.get("scope_filter", {})
        assert sf.get("applied") is True, f"scope_filter.applied should be True: {sf}"
        assert sf.get("out_of_scope_dropped") == 0, (
            f"Expected out_of_scope_dropped=0 for in-scope file: {sf}"
        )

    def test_scope_filter_object_present_on_oos(self):
        payload = _run(self.ws, "oos/Cannon.sol:4")
        assert "scope_filter" in payload, "scope_filter key missing from payload"
        sf = payload["scope_filter"]
        assert sf.get("source") == ".auditooor/inscope_units.jsonl"
        assert sf.get("in_scope_files") == 1

    def test_scope_filter_object_present_on_inscope(self):
        payload = _run(self.ws, "src/Vault.sol:4")
        assert "scope_filter" in payload, "scope_filter key missing from payload"
        sf = payload["scope_filter"]
        assert sf.get("source") == ".auditooor/inscope_units.jsonl"
        assert sf.get("in_scope_files") == 1


class TestNoManifestLegacyBehavior:
    """No manifest -> no filter (rows produced for any file)."""

    def setup_method(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        # No inscope_files -> no manifest written.
        self.ws = _make_ws(self.tmp, inscope_files=None)

    def teardown_method(self):
        self._tmp.cleanup()

    def test_no_manifest_no_filter_inscope_file(self):
        payload = _run(self.ws, "src/Vault.sol:4")
        assert len(payload.get("rows", [])) > 0, (
            f"Expected rows with no manifest: {payload}"
        )
        sf = payload.get("scope_filter", {})
        assert sf.get("applied") is False

    def test_no_manifest_no_filter_oos_file(self):
        """Without a manifest, even the OOS file gets rows (legacy)."""
        payload = _run(self.ws, "oos/Cannon.sol:4")
        assert len(payload.get("rows", [])) > 0, (
            f"Expected rows for OOS file when no manifest: {payload}"
        )
        sf = payload.get("scope_filter", {})
        assert sf.get("applied") is False


class TestEnvBypassFlag:
    """AUDITOOOR_FCC_NO_SCOPE_FILTER bypasses filtering."""

    def setup_method(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_ws(self.tmp, inscope_files=["src/Vault.sol"])

    def teardown_method(self):
        self._tmp.cleanup()
        os.environ.pop("AUDITOOOR_FCC_NO_SCOPE_FILTER", None)

    def test_env_bypass_allows_oos(self):
        os.environ["AUDITOOOR_FCC_NO_SCOPE_FILTER"] = "1"
        payload = _run(self.ws, "oos/Cannon.sol:4")
        assert len(payload.get("rows", [])) > 0, (
            f"Expected rows when env bypass set: {payload}"
        )
        sf = payload.get("scope_filter", {})
        assert sf.get("applied") is False
