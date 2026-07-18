#!/usr/bin/env python3
"""Guard test for asymmetry-context-extract cross-language sibling filter.

Regression: the sibling-path-guard-diff pairs functions by naming convention,
which on a mixed Go/Solidity/Rust monorepo (OP Stack) produced overwhelmingly
CROSS-LANGUAGE false pairs - a Go ABI binding `.go` paired with a Solidity `.sol`
function, a Go config `Check()` paired with a Solidity drippie `check()`, etc.
Measured: 240/240 probed asymmetry pairs were false, dominated by these. A Go
function and a Solidity function are never variant-arms of the same on-chain
invariant; the extractor must drop such pairs mechanically (183 dropped on
optimism: 645 -> 462).
"""
import importlib.util
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "asymmetry-context-extract.py"
_spec = importlib.util.spec_from_file_location("ace", _TOOL)
ace = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ace)


class LangClassifyTest(unittest.TestCase):
    def test_extensions(self):
        self.assertEqual(ace._lang("src/op-node/bindings/optimismportal.go"), "go")
        self.assertEqual(ace._lang("src/packages/contracts-bedrock/src/L1/OptimismPortal2.sol"), "solidity")
        self.assertEqual(ace._lang("a/b/Vault.vy"), "solidity")
        self.assertEqual(ace._lang("src/rust/op-reth/crates/node/src/engine.rs"), "rust")
        self.assertEqual(ace._lang("x/y/m.move"), "move")
        self.assertEqual(ace._lang(None), "")
        self.assertEqual(ace._lang("README"), "")

    def test_cross_language_pair_is_dropped(self):
        import json, tempfile
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        rows = [
            # cross-language: Go binding vs Solidity -> DROP
            {"candidate_gap_id": "g1", "pair_kind": "variant-arm",
             "path_a": "src/op-node/bindings/optimismportal.go:700",
             "path_b": "src/packages/contracts-bedrock/src/L1/OptimismPortal2.sol:368",
             "file_lines": ["a", "b"],
             "guard_on_a_missing_on_b": ["X"], "guard_on_b_missing_on_a": []},
            # same-language Solidity pair with a real asymmetry -> KEEP
            {"candidate_gap_id": "g2", "pair_kind": "variant-arm",
             "path_a": "src/packages/contracts-bedrock/src/L1/A.sol:10",
             "path_b": "src/packages/contracts-bedrock/src/L1/B.sol:20",
             "file_lines": ["a", "b"],
             "guard_on_a_missing_on_b": ["onlyOwner"], "guard_on_b_missing_on_a": []},
        ]
        (ws / ".auditooor" / "sibling_guard_asymmetries.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        res = ace.extract(ws, ws, window=40, keep_cross_module=True)
        # Exactly the go-vs-solidity pair (g1) is dropped as cross_language; the
        # same-language pair (g2) is NOT in that bucket (count==1 proves it). g2
        # not emitting a packet here is only because its fake source files do not
        # exist in the tempdir - that is the source-resolution path, not the
        # cross-language filter under test.
        self.assertEqual(res["dropped"]["cross_language"], 1,
                         "exactly the cross-language pair must be dropped, not the same-language one")


if __name__ == "__main__":
    unittest.main()
