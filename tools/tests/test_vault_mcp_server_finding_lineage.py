import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_lin", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()


class VaultFindingLineageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-lin-")
        self.audits_root = Path(self.tmp.name) / "audits"
        self.audits_root.mkdir()
        spark_pr = self.audits_root / "spark" / "submissions" / "paste_ready"
        spark_pr.mkdir(parents=True)
        spark_st = self.audits_root / "spark" / "submissions" / "staging"
        spark_st.mkdir(parents=True)
        # File 1: paste_ready, internal LEAD 1, mentions L1/L12/L18, Worker-AAA/AAB
        (spark_pr / "lead-1-CRITICAL.md").write_text(
            "# Lead 1 chain-watcher bypass\n"
            "Status: SUBMITTED 2026-05-06 + ESCALATED BY TRIAGER 2026-05-07\n"
            "Internal name: LEAD 1\n"
            "Severity: Critical\n"
            "Surfaced by: Worker-AAA L1 detector seed\n"
            "\n"
            "Memory note Worker-AAB L12: M14-trap caught a fake claim.\n"
            "Memory note Worker-AAA L18: regtest harness shipped; another M14-trap discovered.\n",
            encoding="utf-8",
        )
        # File 2: staging, same internal LEAD 1, mentions L18 only
        (spark_st / "lead-1-CRITICAL.md").write_text(
            "# Lead 1 chain-watcher bypass\n"
            "Status: SUBMITTED\n"
            "Internal name: LEAD 1\n"
            "Severity: Critical\n"
            "Memory note Worker-AAC L18: staging copy.\n",
            encoding="utf-8",
        )
        # File 3: separate finding (LEAD H-D) — should not match LEAD 1 query
        (spark_pr / "lead-hd-CRITICAL.md").write_text(
            "# Lead H-D claim path\n"
            "Status: paste-ready\n"
            "Internal name: LEAD H-D\n"
            "Severity: Critical\n"
            "Memory note Worker-AAD L13.\n",
            encoding="utf-8",
        )
        # Engagement B: morpho, with a different finding
        morpho = self.audits_root / "morpho" / "submissions" / "staging"
        morpho.mkdir(parents=True)
        (morpho / "morpho-something.md").write_text(
            "# Morpho something\nStatus: paid\nInternal name: LEAD M1\n",
            encoding="utf-8",
        )

        self.vault = vault_mcp_server.VaultQuery(
            REPO_ROOT / "obsidian-vault" if (REPO_ROOT / "obsidian-vault").exists() else Path(self.tmp.name) / "vault",
            REPO_ROOT,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_finding_lineage_matches_two_files_and_aggregates_loops(self):
        result = self.vault.vault_finding_lineage(
            audits_root=str(self.audits_root), finding_name="LEAD 1"
        )
        self.assertEqual(result["schema"], vault_mcp_server.FINDING_LINEAGE_SCHEMA)
        self.assertEqual(result["finding_name"], "LEAD 1")
        # Should match the two LEAD 1 files but NOT lead-hd or morpho
        names = {m["filename"] for m in result["matches"]}
        self.assertEqual(names, {"lead-1-CRITICAL.md"})  # both have same name
        self.assertEqual(result["summary"]["matches"], 2)
        # paste_ready should sort first
        self.assertEqual(result["matches"][0]["lane"], "paste_ready")
        # Loop aggregation
        loops = {row["loop"] for row in result["aggregate"]["loops"]}
        self.assertIn("L1", loops)
        self.assertIn("L12", loops)
        self.assertIn("L18", loops)
        # Workers
        workers = {row["worker"] for row in result["aggregate"]["workers"]}
        self.assertIn("Worker-AAA", workers)
        self.assertIn("Worker-AAB", workers)
        self.assertIn("Worker-AAC", workers)
        # M14-trap counted (at least 2 across files)
        self.assertGreaterEqual(result["summary"]["total_m14_trap_mentions"], 2)
        # Privacy
        blob = json.dumps(result)
        self.assertNotIn(str(self.audits_root), blob)
        # Stable hash
        again = self.vault.vault_finding_lineage(
            audits_root=str(self.audits_root), finding_name="LEAD 1"
        )
        self.assertEqual(result["context_pack_hash"], again["context_pack_hash"])

    def test_finding_lineage_engagement_filter_scopes_match(self):
        result = self.vault.vault_finding_lineage(
            audits_root=str(self.audits_root),
            finding_name="LEAD",
            engagement="morpho",
        )
        self.assertEqual(result["summary"]["matches"], 1)
        self.assertEqual(result["matches"][0]["engagement"], "morpho")
        self.assertEqual(result["matches"][0]["status_class"], "paid")

    def test_finding_lineage_missing_or_no_match(self):
        missing = self.vault.vault_finding_lineage()
        self.assertEqual(missing["error"], "missing_finding_name")

        none = self.vault.vault_finding_lineage(
            audits_root=str(self.audits_root), finding_name="NOT_A_REAL_LEAD"
        )
        self.assertEqual(none["summary"]["matches"], 0)
        self.assertEqual(none["matches"], [])

    def test_finding_lineage_routes_through_call(self):
        result = self.vault.call(
            "vault_finding_lineage",
            {"audits_root": str(self.audits_root), "finding_name": "LEAD H-D"},
        )
        self.assertEqual(result["summary"]["matches"], 1)
        self.assertEqual(result["matches"][0]["internal_name"], "LEAD H-D")


if __name__ == "__main__":
    unittest.main()
