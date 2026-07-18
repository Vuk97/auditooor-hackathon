#!/usr/bin/env python3
"""Guard tests for brain-prime's CURRENT-pin extraction and production-source
scope filter.

Regression context (optimism, 2026-06-18):
  * The receipt stayed pinned to the STALE commit 7338e072 after SCOPE.md was
    re-pinned to 56975322, because `_extract_audit_pin` fell back to the FIRST
    bare 40-hex run in the file and a history note / prior layout surfaced the
    old SHA first. Fix: prefer the canonical ``PINNED COMMIT:`` token.
  * The ranked lanes targeted `*/examples/`, `*-test-engine/`,
    `.semgrep/tests/*.t.sol`, `*/testdata/` -- non-production scope the hunt
    then burned budget on. Fix: a generic production-source filter in
    `iter_scope_files` (`_is_production_source`).

These tests are FAST (no ranker / sig-extractor / MCP import path is exercised
beyond loading the module), so they run in the focused suite.
"""
import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BRAIN_PRIME = REPO_ROOT / "tools" / "brain-prime.py"


def _load_bp():
    spec = importlib.util.spec_from_file_location("bp_under_test", BRAIN_PRIME)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bp = _load_bp()


class TestExtractAuditPin(unittest.TestCase):
    def _ws(self, scope_text: str) -> Path:
        import tempfile
        d = Path(tempfile.mkdtemp())
        (d / "SCOPE.md").write_text(scope_text, encoding="utf-8")
        return d

    def test_pinned_commit_token_wins_over_history_note(self):
        # The live re-pin format, with a stale-SHA history note that the old
        # bare-SHA fallback would have grabbed first.
        scope = (
            "## Audit pins\n"
            "- PINNED COMMIT: `56975322abd1d582b09db83ddb85f16bc00078ee`\n"
            "  (was 7338e07273d0e510544661cac2c6a5200ae66fbd -> ...)\n"
        )
        ws = self._ws(scope)
        self.assertEqual(
            bp._extract_audit_pin(ws),
            "56975322abd1d582b09db83ddb85f16bc00078ee",
        )

    def test_history_note_above_pin_does_not_win(self):
        # Stale full SHA textually ABOVE the canonical PINNED COMMIT line.
        scope = (
            "Re-pinned 2026-06-17 (was 7338e07273d0e510544661cac2c6a5200ae66fbd).\n"
            "PINNED COMMIT: `56975322abd1d582b09db83ddb85f16bc00078ee`\n"
        )
        ws = self._ws(scope)
        self.assertEqual(
            bp._extract_audit_pin(ws),
            "56975322abd1d582b09db83ddb85f16bc00078ee",
        )

    def test_explicit_audit_pin_label_still_works(self):
        scope = "audit-pin: deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
        ws = self._ws(scope)
        self.assertEqual(
            bp._extract_audit_pin(ws),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )

    def test_bare_sha_fallback_when_no_label(self):
        scope = "Repo @ cafebabecafebabecafebabecafebabecafebabe\n"
        ws = self._ws(scope)
        self.assertEqual(
            bp._extract_audit_pin(ws),
            "cafebabecafebabecafebabecafebabecafebabe",
        )

    def test_no_pin_returns_empty(self):
        ws = self._ws("no commit here\n")
        self.assertEqual(bp._extract_audit_pin(ws), "")


class TestProductionSourceFilter(unittest.TestCase):
    # (path_parts, file_name, expected_is_production)
    DROP_CASES = [
        (("src", "rust", "op-reth", "examples", "custom-node", "src", "lib.rs"), "lib.rs"),
        (("src", "rust", "op-reth-test-engine", "src", "x.rs"), "x.rs"),
        (("src", ".semgrep", "tests", "a.t.sol"), "a.t.sol"),
        (("src", "op-chain-ops", "foundry", "testdata", "s", "S.sol"), "S.sol"),
        (("src", "op-node", "foo_test.go"), "foo_test.go"),
        (("src", "op-node", "script", "x.s.sol"), "x.s.sol"),
        (("src", "pkg", "mocks", "m.go"), "m.go"),
        (("src", "pkg", "fixtures", "f.go"), "f.go"),
        (("src", "x", "vendor", "y", "v.go"), "v.go"),
    ]
    # Production paths that must SURVIVE (false-positive guards).
    KEEP_CASES = [
        (("src", "op-node", "node", "sequencer.go"), "sequencer.go"),
        (("src", "rust", "op-reth", "src", "pool.rs"), "pool.rs"),
        (("src", "packages", "contracts-bedrock", "src", "L1", "P.sol"), "P.sol"),
        (("src", "op-node", "rollup", "attestation.go"), "attestation.go"),
        (("src", "x", "manifest.go"), "manifest.go"),
        (("src", "x", "latest.rs"), "latest.rs"),
        (("src", "op-batcher", "contest", "run.go"), "run.go"),
    ]

    def test_non_production_paths_dropped(self):
        for parts, name in self.DROP_CASES:
            with self.subTest(path="/".join(parts)):
                self.assertFalse(
                    bp._is_production_source(parts, name),
                    f"{'/'.join(parts)} should be dropped",
                )

    def test_production_paths_kept(self):
        for parts, name in self.KEEP_CASES:
            with self.subTest(path="/".join(parts)):
                self.assertTrue(
                    bp._is_production_source(parts, name),
                    f"{'/'.join(parts)} should be kept",
                )

    def test_iter_scope_files_filters_tree(self):
        import tempfile
        ws = Path(tempfile.mkdtemp())
        prod = ws / "src" / "op-node" / "node"
        prod.mkdir(parents=True)
        (prod / "sequencer.go").write_text("package node\n", encoding="utf-8")
        ex = ws / "src" / "op-reth" / "examples" / "custom"
        ex.mkdir(parents=True)
        (ex / "lib.rs").write_text("fn main(){}\n", encoding="utf-8")
        td = ws / "src" / "op-chain-ops" / "testdata"
        td.mkdir(parents=True)
        (td / "S.sol").write_text("contract S{}\n", encoding="utf-8")
        files = bp.iter_scope_files(ws, "**/*.go,**/*.rs,**/*.sol", "mixed")
        names = {p.name for p in files}
        self.assertIn("sequencer.go", names)
        self.assertNotIn("lib.rs", names)
        self.assertNotIn("S.sol", names)


if __name__ == "__main__":
    unittest.main()
