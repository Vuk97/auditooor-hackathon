"""vault_known_dead_ends group_by histogram (Wave 3 W3c).

group_by in {drop_class, rule_cited} returns an operator-auditable histogram over
matched rows; default (no group_by) leaves the flat dead_ends output unchanged.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("vault_mcp_server", str(_TOOLS / "vault-mcp-server.py"))
_mod = importlib.util.module_from_spec(_spec)
# Register BEFORE exec so the module's dataclasses can resolve their own field
# types (importlib-loaded dataclass modules fail _is_type otherwise).
sys.modules["vault_mcp_server"] = _mod
_spec.loader.exec_module(_mod)


def _server():
    repo = _TOOLS.parent
    vault_dir = repo / "obsidian-vault"
    return _mod.VaultQuery(vault_dir, repo_root=repo)


def _kde_file(rows):
    # .resolve() so macOS /tmp -> /private/tmp symlink doesn't trip the handler's
    # _path_has_symlink guard (which would skip the read -> 0 rows).
    d = Path(tempfile.mkdtemp()).resolve()
    p = d / "known_dead_ends.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return p


_ROWS = [
    {"workspace": "polygon", "file_line": "src/bor/a.go:1", "drop_class": "oos-unmodified-upstream", "reason": "unmodified upstream"},
    {"workspace": "polygon", "file_line": "src/bor/b.go:2", "reason": "unmodified upstream go-ethereum"},  # no drop_class -> classified
    {"workspace": "polygon", "file_line": "src/X.sol:3", "drop_class": "privileged-only-R24", "rule_cited": ["R24"], "reason": "onlyOwner"},
]


class TestKnownDeadEndsGroupBy(unittest.TestCase):
    def setUp(self):
        self.srv = _server()
        self.path = _kde_file(_ROWS)

    def test_group_by_drop_class_histogram(self):
        res = self.srv.vault_known_dead_ends(dead_ends_path=str(self.path),
                                             workspace="polygon", group_by="drop_class")
        hist = res.get("group_histogram")
        self.assertIsInstance(hist, dict)
        # row 1 (explicit) + row 2 (classified from "unmodified upstream") -> 2
        self.assertEqual(hist.get("oos-unmodified-upstream", {}).get("count"), 2)
        self.assertEqual(hist.get("privileged-only-R24", {}).get("count"), 1)
        self.assertIn("src/bor/a.go:1", hist["oos-unmodified-upstream"]["samples"])

    def test_group_by_rule_cited_histogram(self):
        res = self.srv.vault_known_dead_ends(dead_ends_path=str(self.path),
                                             workspace="polygon", group_by="rule_cited")
        hist = res.get("group_histogram")
        self.assertIsInstance(hist, dict)
        self.assertEqual(hist.get("R24", {}).get("count"), 1)

    def test_no_group_by_is_unchanged_flat_output(self):
        res = self.srv.vault_known_dead_ends(dead_ends_path=str(self.path), workspace="polygon")
        self.assertIsNone(res.get("group_histogram"))
        self.assertIsNone(res.get("group_by"))
        self.assertEqual(res.get("matching_records"), 3)
        self.assertEqual(len(res.get("dead_ends", [])), 3)

    def test_empty_store_empty_histogram(self):
        empty = _kde_file([])
        res = self.srv.vault_known_dead_ends(dead_ends_path=str(empty), group_by="drop_class")
        self.assertEqual(res.get("group_histogram"), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
