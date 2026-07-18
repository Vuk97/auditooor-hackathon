"""Tests for vault_corpus_mining_state MCP callable.

Lane M-I — verifies the corpus mining inventory + freshness ledger
surface exposed via vault-mcp-server.py.
"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_corpus", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()


def _make_vault(tmp_root: Path) -> object:
    """Return a VaultQuery bound to a minimal vault under tmp_root."""
    vault_dir = tmp_root / "obsidian-vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_mcp_server.VaultQuery(vault_dir, REPO_ROOT)


class TestVaultCorpusMiningStateSchema(unittest.TestCase):
    """Test 1: callable returns correct schema and required top-level keys."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-corpus-state-")
        self.vault = _make_vault(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_schema_field_present(self):
        result = self.vault.vault_corpus_mining_state()
        self.assertEqual(result["schema"], vault_mcp_server.CORPUS_MINING_STATE_SCHEMA)

    def test_required_keys_present(self):
        result = self.vault.vault_corpus_mining_state()
        for key in ("schema", "kind", "snapshot", "freshness_days_by_corpus", "gaps", "gap_count",
                    "context_pack_id", "context_pack_hash"):
            self.assertIn(key, result, f"Missing required key: {key}")

    def test_kind_field(self):
        result = self.vault.vault_corpus_mining_state()
        self.assertEqual(result["kind"], "corpus_mining_state")


class TestVaultCorpusMiningStatePackId(unittest.TestCase):
    """Test 2: context_pack_id format and hash properties."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-corpus-pack-")
        self.vault = _make_vault(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_pack_id_starts_with_schema(self):
        result = self.vault.vault_corpus_mining_state()
        self.assertTrue(
            result["context_pack_id"].startswith(vault_mcp_server.CORPUS_MINING_STATE_SCHEMA + ":"),
            f"pack_id={result['context_pack_id']!r} does not start with expected schema prefix",
        )

    def test_pack_id_contains_corpus_mining_slug(self):
        result = self.vault.vault_corpus_mining_state()
        self.assertIn("corpus_mining", result["context_pack_id"])

    def test_pack_hash_is_64_hex_chars(self):
        result = self.vault.vault_corpus_mining_state()
        self.assertEqual(len(result["context_pack_hash"]), 64)
        int(result["context_pack_hash"], 16)  # must be valid hex

    def test_pack_hash_deterministic_for_same_input(self):
        """Same repo filesystem state must produce same hash on two consecutive calls."""
        first = self.vault.vault_corpus_mining_state()
        second = self.vault.vault_corpus_mining_state()
        self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])
        self.assertEqual(first["context_pack_id"], second["context_pack_id"])


class TestVaultCorpusMiningStateSnapshotContent(unittest.TestCase):
    """Test 3: snapshot content from corpus-mining-state-snapshot.py."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-corpus-snap-")
        self.vault = _make_vault(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_snapshot_has_corpora_list(self):
        result = self.vault.vault_corpus_mining_state()
        snap = result["snapshot"]
        # If snapshot imported successfully, corpora must be a list.
        if "error" not in snap:
            self.assertIsInstance(snap.get("corpora"), list)
            self.assertGreater(len(snap["corpora"]), 0)

    def test_freshness_days_by_corpus_is_dict(self):
        result = self.vault.vault_corpus_mining_state()
        self.assertIsInstance(result["freshness_days_by_corpus"], dict)

    def test_gaps_is_list(self):
        result = self.vault.vault_corpus_mining_state()
        self.assertIsInstance(result["gaps"], list)

    def test_gap_count_matches_gaps_list_length(self):
        result = self.vault.vault_corpus_mining_state()
        self.assertEqual(result["gap_count"], len(result["gaps"]))

    def test_known_corpus_names_present_when_snapshot_ok(self):
        """If snapshot ran successfully, expected corpus names should appear."""
        result = self.vault.vault_corpus_mining_state()
        snap = result["snapshot"]
        if "error" in snap:
            self.skipTest("Snapshot import error; cannot verify corpus names")
        corpus_names = {c["corpus"] for c in snap["corpora"]}
        expected = {"defimon", "solodit", "audit_pdfs", "defihacklabs_catalog",
                    "big_loss_templates", "case_studies"}
        for name in expected:
            self.assertIn(name, corpus_names, f"Corpus '{name}' missing from snapshot")


class TestVaultCorpusMiningStateWorkspacePath(unittest.TestCase):
    """Test 4: workspace_path kwarg is optional and threaded through correctly."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-corpus-ws-")
        self.vault = _make_vault(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_without_workspace_path(self):
        """Callable must succeed without workspace_path argument."""
        result = self.vault.vault_corpus_mining_state()
        self.assertNotIn("error", result)

    def test_with_workspace_path_kwarg(self):
        """workspace_path is accepted but not echoed as a local path."""
        result = self.vault.vault_corpus_mining_state(workspace_path="/tmp/test_ws")
        self.assertNotIn("workspace_path", result)
        self.assertNotIn("/tmp/test_ws", json.dumps(result, sort_keys=True))

    def test_pack_id_present_with_and_without_workspace(self):
        r1 = self.vault.vault_corpus_mining_state()
        r2 = self.vault.vault_corpus_mining_state(workspace_path="/tmp/dummy")
        self.assertIn("context_pack_id", r1)
        self.assertIn("context_pack_id", r2)
        self.assertEqual(r1["context_pack_id"], r2["context_pack_id"])


class TestVaultCorpusMiningStateDispatch(unittest.TestCase):
    """Test 5: call() dispatcher routes vault_corpus_mining_state correctly."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-corpus-disp-")
        self.vault = _make_vault(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_dispatch_routes_correctly(self):
        result = self.vault.call("vault_corpus_mining_state", {})
        self.assertIn("context_pack_id", result)
        self.assertNotIn("error", result)

    def test_tool_schema_registered(self):
        """vault_corpus_mining_state must appear in TOOL_SCHEMAS."""
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_corpus_mining_state", names)

    def test_schema_constant_defined(self):
        """CORPUS_MINING_STATE_SCHEMA constant must be defined."""
        self.assertTrue(hasattr(vault_mcp_server, "CORPUS_MINING_STATE_SCHEMA"))
        self.assertIn("corpus_mining_state", vault_mcp_server.CORPUS_MINING_STATE_SCHEMA)


if __name__ == "__main__":
    unittest.main()
