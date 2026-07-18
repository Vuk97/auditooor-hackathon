#!/usr/bin/env python3
"""Guard test: tools/mimo-harness-batch-gen.py::_detect_workspace_language must pick the
target language by PREVALENCE of the workspace's OWN in-scope source - NOT first-match on
a stray vendored manifest.

Bug pinned (NUVA 2026-06-30): a 512-`.sol` + go.mod liquid-staking workspace was detected
as "rust" because `_detect_workspace_language` did `if any(root.rglob("Cargo.toml")):
return "rust"` FIRST, and node_modules/@nomicfoundation/edr/Cargo.toml (Nomic Foundation's
Rust hardhat tooling) matched. The whole step-3 hunt was then fed rust+crypto hypotheses,
starving the Solidity nvPrime EVM core ($4.6M) of the right methodology.

Fix: detection is prevalence-based - authoritative from .auditooor/inscope_units.jsonl
when present (every in-scope language is hunted, comma-joined for mixed), else a
vendor-pruned source-file count. _language_fit handles a comma-joined target set.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOL_PATH = _REPO_ROOT / "tools" / "mimo-harness-batch-gen.py"


def _import_tool():
    sys.argv = ["mimo-harness-batch-gen.py"]  # module parses no args at import
    spec = importlib.util.spec_from_file_location("mimo_harness_batch_gen", _TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


M = _import_tool()


def _write_units(ws: Path, rows: list[dict]) -> None:
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    (d / "inscope_units.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )


class TestMimoLanguageDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mimo_lang_"))

    # -- the NUVA regression: a vendored Rust Cargo.toml must NOT win -------------
    def test_node_modules_cargo_toml_does_not_misroute_solidity_ws(self):
        ws = self.tmp / "nuva"
        # in-scope units: solidity-dominant + go (mirrors NUVA 162 sol / 43 go)
        _write_units(ws, [{"file": f"src/C{i}.sol", "language": "solidity"} for i in range(162)]
                     + [{"file": f"x/k{i}.go", "language": "go"} for i in range(43)])
        # plant the exact vendored Rust tooling manifest that caused the bug
        nm = ws / "src" / "nuva-evm-contracts" / "node_modules" / "@nomicfoundation" / "edr"
        nm.mkdir(parents=True)
        (nm / "Cargo.toml").write_text("[package]\nname = \"edr\"\n")
        result = M._detect_workspace_language(str(ws))
        self.assertNotIn("rust", result.split(","),
                         f"vendored node_modules Cargo.toml must NOT route to rust; got {result!r}")
        self.assertIn("solidity", result.split(","))
        self.assertIn("go", result.split(","), "the 26% go cosmos vault is in-scope and must be hunted")

    def test_manifest_authoritative_single_language(self):
        ws = self.tmp / "solo"
        _write_units(ws, [{"file": f"src/A{i}.sol", "language": "solidity"} for i in range(10)])
        self.assertEqual(M._detect_workspace_language(str(ws)), "solidity")

    def test_manifest_infers_language_from_extension_when_field_absent(self):
        ws = self.tmp / "nolangfield"
        _write_units(ws, [{"file": "src/A.sol"}, {"file": "src/B.sol"}, {"file": "x/k.go"}])
        result = M._detect_workspace_language(str(ws)).split(",")
        self.assertIn("solidity", result)

    def test_minor_language_below_floor_dropped(self):
        ws = self.tmp / "minor"
        # 100 sol + 2 go (2% < 15% floor) -> go dropped
        _write_units(ws, [{"language": "solidity"} for _ in range(100)]
                     + [{"language": "go"} for _ in range(2)])
        self.assertEqual(M._detect_workspace_language(str(ws)), "solidity")

    # -- fallback file-count path (no manifest) prunes vendored dirs --------------
    def test_filecount_fallback_prunes_node_modules(self):
        ws = self.tmp / "nomanifest"
        (ws / "src").mkdir(parents=True)
        for i in range(8):
            (ws / "src" / f"C{i}.sol").write_text("contract C {}\n")
        nm = ws / "src" / "node_modules" / "dep"
        nm.mkdir(parents=True)
        for i in range(50):
            (nm / f"r{i}.rs").write_text("fn main() {}\n")
        result = M._detect_workspace_language(str(ws))
        self.assertEqual(result, "solidity",
                         f"vendored .rs under node_modules must not win; got {result!r}")

    def test_unknown_workspace_returns_empty(self):
        ws = self.tmp / "empty"
        ws.mkdir()
        self.assertEqual(M._detect_workspace_language(str(ws)), "")

    # -- _language_fit handles comma-joined target sets --------------------------
    def test_language_fit_comma_target(self):
        f = M._language_fit
        self.assertEqual(f("solidity", "solidity,go"), 3)
        self.assertEqual(f("go", "solidity,go"), 3)
        self.assertEqual(f("rust", "solidity,go"), -3)
        self.assertEqual(f("", "solidity,go"), 1)         # agnostic
        self.assertEqual(f("crypto", "solidity,rust"), 3)  # crypto fits rust
        self.assertEqual(f("crypto", "solidity,go"), 1)    # crypto weak-fits non-rust

    def test_dominant_languages_floor(self):
        self.assertEqual(M._dominant_languages({"solidity": 162, "go": 43}, 0.15), "solidity,go")
        self.assertEqual(M._dominant_languages({"solidity": 162, "go": 43}, 0.30), "solidity")
        self.assertEqual(M._dominant_languages({"solidity": 512, "rust": 1}), "solidity")
        self.assertEqual(M._dominant_languages({}), "")


if __name__ == "__main__":
    unittest.main()
