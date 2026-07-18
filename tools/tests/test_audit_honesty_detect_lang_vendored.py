#!/usr/bin/env python3
"""L11 regression: _detect_lang must ignore VENDORED .rs/.go files.

BUG (MED): _detect_lang probed the workspace with bare globs like
ws.glob("src/**/*.rs") / *.go, which match vendored dependency files under
lib/, node_modules/, dependencies/, etc. A pure-Solidity workspace (e.g.
strata, whose only .rs files live in src/contracts/node_modules/.../edr/src/*.rs)
therefore mis-detected rust/mixed and skewed the honesty checks.

FIX: prefer the in-scope manifest's dominant language; else use a filesystem walk
that excludes vendored/dependency/build/test directory segments.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_TOOL = _REPO / "tools" / "audit-honesty-check.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("ahc_detectlang", _TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


_M = _load_mod()


def _mkdir_file(p: Path, content: str = "// x\n") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class DetectLangVendoredTest(unittest.TestCase):
    def _ws(self) -> Path:
        return Path(tempfile.mkdtemp(prefix="ahc_detectlang_"))

    def test_vendored_rust_under_node_modules_does_not_flip_solidity(self):
        """Only .rs files are vendored (node_modules); real in-scope is .sol ->
        must detect solidity, NOT rust/mixed."""
        ws = self._ws()
        # real in-scope solidity source
        _mkdir_file(ws / "src" / "contracts" / "Vault.sol", "contract V {}\n")
        # vendored rust that the old bare glob would have matched
        _mkdir_file(ws / "src" / "contracts" / "node_modules" / "@x" / "edr" / "src" / "logger.rs")
        _mkdir_file(ws / "lib" / "somedep" / "src" / "lib.rs")
        self.assertEqual(_M._detect_lang(ws), "solidity")

    def test_vendored_go_under_lib_does_not_flip_solidity(self):
        ws = self._ws()
        _mkdir_file(ws / "src" / "Token.sol", "contract T {}\n")
        _mkdir_file(ws / "lib" / "dep" / "main.go", "package dep\n")
        _mkdir_file(ws / "dependencies" / "x" / "go.mod", "module x\n")
        self.assertEqual(_M._detect_lang(ws), "solidity")

    def test_inscope_manifest_solidity_wins_over_vendored_rust(self):
        """When inscope_units.jsonl marks units solidity, prefer it even though a
        vendored .rs is present."""
        ws = self._ws()
        _mkdir_file(ws / "src" / "contracts" / "node_modules" / "edr" / "src" / "x.rs")
        man = ws / ".auditooor" / "inscope_units.jsonl"
        man.parent.mkdir(parents=True, exist_ok=True)
        man.write_text(
            json.dumps({"file": "src/contracts/Vault.sol", "function": "deposit",
                        "lang": "solidity"}) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(_M._detect_lang(ws), "solidity")

    def test_genuine_rust_still_detected(self):
        """A real rust workspace (non-vendored .rs under src/) still returns rust."""
        ws = self._ws()
        _mkdir_file(ws / "src" / "program" / "lib.rs", "pub fn x() {}\n")
        _mkdir_file(ws / "src" / "Cargo.toml", "[package]\nname='p'\n")
        self.assertEqual(_M._detect_lang(ws), "rust")

    def test_genuine_rust_via_manifest(self):
        ws = self._ws()
        man = ws / ".auditooor" / "inscope_units.jsonl"
        man.parent.mkdir(parents=True, exist_ok=True)
        man.write_text(
            json.dumps({"unit": "src/lib.rs::transfer", "lang": "rust"}) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(_M._detect_lang(ws), "rust")


if __name__ == "__main__":
    unittest.main()
