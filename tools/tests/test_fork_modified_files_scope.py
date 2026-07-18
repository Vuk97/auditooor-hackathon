from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "fork-modified-files-scope.py"


def _load():
    spec = importlib.util.spec_from_file_location("fork_modified_files_scope", TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = _load()


class ForkModifiedFilesScopeTest(unittest.TestCase):
    def test_tree_diff_identifies_modified_and_added(self):
        with tempfile.TemporaryDirectory() as tmp:
            up = Path(tmp) / "up"
            fork = Path(tmp) / "fork"
            for d in (up, fork):
                (d / "core").mkdir(parents=True)
            # unchanged file (identical content) - OOS upstream
            (up / "core" / "chain.go").write_text("package core\n// same\n")
            (fork / "core" / "chain.go").write_text("package core\n// same\n")
            # modified file - Polygon-changed
            (up / "core" / "vm.go").write_text("package core\n// upstream\n")
            (fork / "core" / "vm.go").write_text("package core\n// POLYGON change\n")
            # added file (fork only) - Polygon-added
            (fork / "consensus" / "bor").mkdir(parents=True)
            (fork / "consensus" / "bor" / "bor.go").write_text("package bor\n")
            mod = M.compute_modified_files(fork, up)
            self.assertIn("core/vm.go", mod)
            self.assertIn("consensus/bor/bor.go", mod)
            self.assertNotIn("core/chain.go", mod, "identical upstream file must be OOS")

    def test_whitespace_only_diff_is_not_modified(self):
        # A fork file differing from upstream ONLY in line endings, trailing
        # whitespace, or blank-line insertions is NOT a semantic Polygon mod and
        # must be treated as OOS upstream (else bor over-scopes ~200 files).
        with tempfile.TemporaryDirectory() as tmp:
            up = Path(tmp) / "up"; fork = Path(tmp) / "fork"
            for d in (up, fork):
                (d / "rlp").mkdir(parents=True)
            (up / "rlp" / "decode.go").write_bytes(b"package rlp\nfunc A() {}\n")
            # CRLF + trailing spaces + extra blank lines, same code
            (fork / "rlp" / "decode.go").write_bytes(
                b"package rlp\r\n\r\nfunc A() {}   \r\n\r\n")
            mod = M.compute_modified_files(fork, up)
            self.assertNotIn("rlp/decode.go", mod,
                             "whitespace-only diff must NOT count as modified")

    def test_real_token_change_still_modified_after_normalization(self):
        # normalization must not under-scope: a real code edit is still modified.
        with tempfile.TemporaryDirectory() as tmp:
            up = Path(tmp) / "up"; fork = Path(tmp) / "fork"
            for d in (up, fork):
                (d / "core").mkdir(parents=True)
            (up / "core" / "vm.go").write_bytes(b"package core\nfunc A() int { return 1 }\n")
            (fork / "core" / "vm.go").write_bytes(b"package core\nfunc A() int { return 2 }\n")
            mod = M.compute_modified_files(fork, up)
            self.assertIn("core/vm.go", mod, "a real token change must stay modified")

    def test_filter_manifest_drops_oos_keeps_modified_and_passthrough(self):
        with tempfile.TemporaryDirectory() as tmp:
            mani = Path(tmp) / "inscope_units.jsonl"
            rows = [
                {"file": "src/bor/core/vm.go", "lang": "go"},        # modified -> keep
                {"file": "src/bor/core/chain.go", "lang": "go"},     # OOS upstream -> drop
                {"file": "src/bor/consensus/bor/bor.go", "lang": "go"},  # added -> keep
                {"file": "src/agglayer-contracts/contracts/X.sol", "lang": "solidity"},  # other repo -> passthrough
            ]
            mani.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
            out = Path(tmp) / "scoped.jsonl"
            modified = {"core/vm.go", "consensus/bor/bor.go"}
            stats = M.filter_manifest(mani, out, "bor", modified)
            self.assertEqual(stats["kept_in_repo"], 2)
            self.assertEqual(stats["dropped_in_repo_oos_upstream"], 1)
            self.assertEqual(stats["passthrough_other"], 1)
            kept = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            files = {r["file"] for r in kept}
            self.assertIn("src/bor/core/vm.go", files)
            self.assertIn("src/agglayer-contracts/contracts/X.sol", files)
            self.assertNotIn("src/bor/core/chain.go", files)

    def test_unresolved_upstream_keeps_all_repo_units_completeness_safe(self):
        # modified_files=None (upstream unresolved) must KEEP every repo unit.
        with tempfile.TemporaryDirectory() as tmp:
            mani = Path(tmp) / "inscope_units.jsonl"
            rows = [
                {"file": "src/bor/a.go", "lang": "go"},
                {"file": "src/bor/b.go", "lang": "go"},
            ]
            mani.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
            out = Path(tmp) / "scoped.jsonl"
            stats = M.filter_manifest(mani, out, "bor", None)
            self.assertEqual(stats["kept_in_repo"], 2)
            self.assertEqual(stats["dropped_in_repo_oos_upstream"], 0)


if __name__ == "__main__":
    unittest.main()
