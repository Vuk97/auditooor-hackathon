#!/usr/bin/env python3
"""Guard test: _detect_language() must correctly detect Solidity/Go/Rust
workspaces when the target is a directory (the --all code path), not just when
the target is a file path with an explicit extension.

Bug pinned: _detect_language('/path/to/morpho') returned 'other' because:
  - the path string did not end with .sol/.rs/.go
  - the heuristic ("src" in t or "contracts" in t) checked the PATH STRING,
    not the directory contents - so a workspace named 'morpho' (with a src/
    SUBDIRECTORY) correctly returned 'other'

This caused all 24 depth tool invocations under --all to be skipped with
"detected language=other" on every Solidity workspace whose root name did not
literally contain the word "src" or "contracts".

The fix: _detect_language() now delegates to _detect_language_from_dir() for
directory targets. The helper checks the inscope manifest first, then falls
back to a bounded tree walk of the canonical source subdirectories.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOL_PATH = _REPO_ROOT / "tools" / "depth-tools-orchestrator.py"


def _import_tool():
    spec = importlib.util.spec_from_file_location("depth_tools_orchestrator", _TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


DTO = _import_tool()


# ---------------------------------------------------------------------------
# Fixtures: build minimal fake workspaces on disk
# ---------------------------------------------------------------------------

def _make_solidity_workspace(tmp: Path, name: str = "morpho") -> Path:
    """Create a workspace whose source is under src/ and whose name alone
    gives no language hint - simulates the morpho bug exactly."""
    ws = tmp / name
    (ws / "src" / "contracts").mkdir(parents=True)
    (ws / "src" / "contracts" / "Token.sol").write_text(
        "// SPDX-License-Identifier: MIT\ncontract Token {}\n"
    )
    (ws / "src" / "contracts" / "Vault.sol").write_text(
        "// SPDX-License-Identifier: MIT\ncontract Vault {}\n"
    )
    (ws / "README.md").write_text("# morpho\n")
    return ws


def _make_rust_workspace(tmp: Path) -> Path:
    ws = tmp / "myprotocol"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "lib.rs").write_text("// Rust lib\n")
    (ws / "src" / "main.rs").write_text("fn main() {}\n")
    (ws / "Cargo.toml").write_text("[package]\nname = \"myprotocol\"\n")
    return ws


def _make_go_workspace(tmp: Path) -> Path:
    ws = tmp / "goproto"
    (ws / "internal" / "keeper").mkdir(parents=True)
    (ws / "internal" / "keeper" / "keeper.go").write_text("package keeper\n")
    (ws / "internal" / "keeper" / "msg_server.go").write_text("package keeper\n")
    (ws / "go.mod").write_text("module example.com/goproto\n")
    return ws


def _make_mixed_workspace_solidity_dominant(tmp: Path) -> Path:
    """Go test harness + Solidity contracts: Solidity files should win."""
    ws = tmp / "mixed"
    (ws / "contracts").mkdir(parents=True)
    for i in range(5):
        (ws / "contracts" / f"Contract{i}.sol").write_text(
            f"// SPDX-License-Identifier: MIT\ncontract C{i} {{}}\n"
        )
    (ws / "test").mkdir()
    (ws / "test" / "foo_test.go").write_text("package test\n")
    return ws


def _write_inscope_manifest(ws: Path, files: list[str]) -> Path:
    manifest_dir = ws / ".auditooor"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / "inscope_units.jsonl"
    with manifest_path.open("w") as fh:
        for f in files:
            fh.write(json.dumps({"file": f}) + "\n")
    return manifest_path


# ---------------------------------------------------------------------------
# Tests: _detect_language() with directory targets
# ---------------------------------------------------------------------------

class TestDetectLanguageDirectoryTarget(unittest.TestCase):
    """Pin the fixed behavior: directory targets return the correct language."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.tmp = Path(self._tmpdir)

    # ------------------------------------------------------------------
    # Positive cases: workspace name gives NO language hint by itself
    # ------------------------------------------------------------------

    def test_solidity_workspace_dir_returns_solidity(self):
        """Core regression: morpho-style workspace - name='morpho', .sol under src/."""
        ws = _make_solidity_workspace(self.tmp, name="morpho")
        result = DTO._detect_language(str(ws))
        self.assertEqual(
            result, "solidity",
            f"Solidity workspace dir must return 'solidity', got {result!r}. "
            "This is the morpho bug: workspace name 'morpho' has no .sol suffix so "
            "the old heuristic returned 'other'."
        )

    def test_rust_workspace_dir_returns_rust(self):
        ws = _make_rust_workspace(self.tmp)
        result = DTO._detect_language(str(ws))
        self.assertEqual(result, "rust",
                         f"Rust workspace dir must return 'rust', got {result!r}")

    def test_go_workspace_dir_returns_go(self):
        ws = _make_go_workspace(self.tmp)
        result = DTO._detect_language(str(ws))
        self.assertEqual(result, "go",
                         f"Go workspace dir must return 'go', got {result!r}")

    def test_empty_dir_returns_other(self):
        ws = self.tmp / "empty_ws"
        ws.mkdir()
        result = DTO._detect_language(str(ws))
        self.assertEqual(result, "other",
                         f"Empty workspace dir must return 'other', got {result!r}")

    # ------------------------------------------------------------------
    # Inscope manifest path: MANIFEST-AUTHORITATIVE when present
    # ------------------------------------------------------------------

    def test_manifest_authoritative_for_solidity_workspace(self):
        """When inscope_units.jsonl lists .sol files, manifest detection fires first."""
        ws = self.tmp / "manifest_ws"
        ws.mkdir()
        _write_inscope_manifest(ws, [
            "src/Foo.sol", "src/Bar.sol", "src/Baz.sol",
        ])
        result = DTO._detect_language(str(ws))
        self.assertEqual(result, "solidity",
                         f"Manifest-based detection must return 'solidity', got {result!r}")

    def test_manifest_authoritative_for_rust_workspace(self):
        ws = self.tmp / "manifest_rust"
        ws.mkdir()
        _write_inscope_manifest(ws, [
            "src/lib.rs", "src/main.rs", "crates/foo/src/lib.rs",
        ])
        result = DTO._detect_language(str(ws))
        self.assertEqual(result, "rust",
                         f"Manifest-based Rust detection must return 'rust', got {result!r}")

    def test_manifest_mixed_dominant_language_wins(self):
        """Three .sol entries beats two .go entries: manifest dominant = solidity."""
        ws = self.tmp / "manifest_mixed"
        ws.mkdir()
        _write_inscope_manifest(ws, [
            "src/Foo.sol", "src/Bar.sol", "src/Baz.sol",
            "test/harness.go", "test/setup.go",
        ])
        result = DTO._detect_language(str(ws))
        self.assertEqual(result, "solidity",
                         f"Dominant language in manifest must win, got {result!r}")

    # ------------------------------------------------------------------
    # Fallback tree walk: no manifest present
    # ------------------------------------------------------------------

    def test_no_manifest_fallback_walk_solidity(self):
        """Without manifest, tree walk under src/ still finds .sol."""
        ws = _make_solidity_workspace(self.tmp, name="nomanifest")
        # confirm no manifest was created by the fixture
        self.assertFalse((ws / ".auditooor" / "inscope_units.jsonl").exists())
        result = DTO._detect_language(str(ws))
        self.assertEqual(result, "solidity",
                         f"Fallback walk must find .sol and return 'solidity', got {result!r}")

    def test_fallback_prefers_src_subdir_over_root_walk(self):
        """Fallback picks src/ as the scan root, not the whole workspace tree."""
        ws = self.tmp / "prefersrc"
        ws.mkdir()
        # .sol files under src/
        (ws / "src").mkdir()
        (ws / "src" / "Foo.sol").write_text("contract Foo {}\n")
        # .go files at root (scripts/build harness, not protocol source)
        (ws / "build.go").write_text("package main\n")
        result = DTO._detect_language(str(ws))
        # src/ is the preferred scan root; src/Foo.sol dominates over root build.go
        self.assertEqual(result, "solidity",
                         f"Must prefer src/ scan root and return 'solidity', got {result!r}")

    # ------------------------------------------------------------------
    # Negative cases: file targets still use extension-based detection
    # ------------------------------------------------------------------

    def test_file_target_sol_still_works(self):
        """File targets with explicit extension must NOT hit the directory path."""
        result = DTO._detect_language("contracts/Foo.sol")
        self.assertEqual(result, "solidity")

    def test_file_target_rs_still_works(self):
        result = DTO._detect_language("src/lib.rs")
        self.assertEqual(result, "rust")

    def test_file_target_go_still_works(self):
        result = DTO._detect_language("internal/keeper.go")
        self.assertEqual(result, "go")

    def test_nonexistent_dir_returns_other(self):
        """A path that looks like a dir but does not exist: fall through to other."""
        result = DTO._detect_language("/nonexistent/path/that/has/no/extension")
        self.assertEqual(result, "other")

    def test_empty_string_returns_other(self):
        result = DTO._detect_language("")
        self.assertEqual(result, "other")


# ---------------------------------------------------------------------------
# Tests: _detect_language_from_dir() directly
# ---------------------------------------------------------------------------

class TestDetectLanguageFromDir(unittest.TestCase):
    """Pin _detect_language_from_dir() behavior in isolation."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.tmp = Path(self._tmpdir)

    def test_manifest_key_variants(self):
        """Manifest rows with 'file', 'path', or 'rel_path' keys are all accepted."""
        ws = self.tmp / "keyvar"
        ws.mkdir()
        manifest_dir = ws / ".auditooor"
        manifest_dir.mkdir()
        manifest_path = manifest_dir / "inscope_units.jsonl"
        manifest_path.write_text(
            json.dumps({"file": "src/A.sol"}) + "\n"
            + json.dumps({"path": "src/B.sol"}) + "\n"
            + json.dumps({"rel_path": "src/C.sol"}) + "\n"
        )
        result = DTO._detect_language_from_dir(ws)
        self.assertEqual(result, "solidity")

    def test_empty_manifest_falls_back_to_walk(self):
        """An empty manifest must fall back to tree walk."""
        ws = self.tmp / "emptymanifest"
        ws.mkdir()
        (ws / ".auditooor").mkdir()
        (ws / ".auditooor" / "inscope_units.jsonl").write_text("")
        # Plant a .sol file so the walk can find it.
        (ws / "src").mkdir()
        (ws / "src" / "Foo.sol").write_text("contract Foo {}\n")
        result = DTO._detect_language_from_dir(ws)
        self.assertEqual(result, "solidity")

    def test_skip_parts_not_counted(self):
        """Files under excluded dirs (test/, vendor/, .auditooor/, etc.) are ignored."""
        ws = self.tmp / "skipparts"
        ws.mkdir()
        # Solidity file in src/ (in-scope)
        (ws / "src").mkdir()
        (ws / "src" / "Real.sol").write_text("contract Real {}\n")
        # Go files in test/, vendor/, node_modules/ (should be excluded)
        (ws / "test").mkdir()
        (ws / "test" / "harness.go").write_text("package test\n")
        for d in ("vendor", "node_modules"):
            (ws / d).mkdir()
            for i in range(10):
                (ws / d / f"dep{i}.go").write_text("package dep\n")
        result = DTO._detect_language_from_dir(ws)
        # src/Real.sol should dominate after excluded .go files are filtered
        self.assertEqual(result, "solidity",
                         f"Excluded dirs must not inflate .go count; got {result!r}")

    def test_no_source_files_returns_other(self):
        ws = self.tmp / "nosrc"
        ws.mkdir()
        (ws / "README.md").write_text("# README\n")
        result = DTO._detect_language_from_dir(ws)
        self.assertEqual(result, "other")

    def test_move_files_detected(self):
        ws = self.tmp / "moveproto"
        ws.mkdir()
        (ws / "src").mkdir()
        (ws / "src" / "token.move").write_text("module 0x1::Token {}\n")
        result = DTO._detect_language_from_dir(ws)
        self.assertEqual(result, "move")


if __name__ == "__main__":
    unittest.main()
