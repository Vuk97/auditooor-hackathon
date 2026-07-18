import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_eng", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()


def _write_finding(path: Path, *, title: str, status: str, internal: str | None = None,
                   severity: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = [f"# {title}", "", f"Status: **{status}**"]
    if internal:
        body.append(f"Internal name: {internal}")
    if severity:
        body.append(f"Severity: {severity}")
    body.append("")
    body.append("Body content omitted to keep header bounded.")
    path.write_text("\n".join(body) + "\n", encoding="utf-8")


class VaultEngagementStatusTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-eng-status-")
        self.audits_root = Path(self.tmp.name) / "audits"
        self.audits_root.mkdir()
        # Engagement A: spark — paste_ready + staging + dropped names + a candidate.
        spark = self.audits_root / "spark" / "submissions"
        _write_finding(
            spark / "paste_ready" / "lead-1-CRITICAL.md",
            title="Lead 1 chain-watcher bypass",
            status="SUBMITTED 2026-05-06 + ESCALATED BY TRIAGER 2026-05-07",
            internal="LEAD 1",
            severity="Critical",
        )
        _write_finding(
            spark / "staging" / "lead-commit-resume-CANDIDATE.md",
            title="Coordinator restart freeze",
            status="DROPPED 2026-05-08 — NOT FILEABLE under Spark Immunefi rubric",
            internal="LEAD COMMIT-RESUME",
        )
        _write_finding(
            spark / "packaged" / "lead-1-CRITICAL.md",
            title="Lead 1 chain-watcher bypass",
            status="SUBMITTED",
            severity="Critical",
        )
        # backup file should be skipped
        (spark / "staging" / "lead-1.md.bak").write_text("# bak\n", encoding="utf-8")
        # dotfile should be skipped
        (spark / "staging" / ".hidden.md").write_text("# hidden\n", encoding="utf-8")

        # Engagement B: morpho — only one staging file.
        morpho = self.audits_root / "morpho" / "submissions"
        _write_finding(
            morpho / "staging" / "R89-Blue-consolidated.notes.md",
            title="R89 Blue consolidated notes",
            status="paid 2026-04-15",
            severity="Medium",
        )
        # Engagement C: empty (no submissions/) — should be skipped silently.
        (self.audits_root / "empty-eng").mkdir()

        # vault dir is irrelevant for this callable; reuse repo root
        self.vault = vault_mcp_server.VaultQuery(
            REPO_ROOT / "obsidian-vault" if (REPO_ROOT / "obsidian-vault").exists() else Path(self.tmp.name) / "vault",
            REPO_ROOT,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_engagement_status_aggregates_per_engagement_with_lane_counts(self):
        result = self.vault.vault_engagement_status(audits_root=str(self.audits_root))
        self.assertEqual(result["schema"], vault_mcp_server.ENGAGEMENT_STATUS_SCHEMA)
        self.assertEqual(result["kind"], "engagement_status")
        # Both engagements (spark, morpho) returned; empty-eng skipped.
        names = {e["engagement"] for e in result["engagements"]}
        self.assertIn("spark", names)
        self.assertIn("morpho", names)
        self.assertNotIn("empty-eng", names)
        self.assertEqual(result["summary"]["engagements_with_submissions"], 2)
        spark = next(e for e in result["engagements"] if e["engagement"] == "spark")
        # 3 files (paste_ready/lead-1, staging/candidate, packaged/lead-1) — bak + dotfile skipped
        self.assertEqual(spark["file_count"], 3)
        self.assertEqual(spark["lane_counts"]["paste_ready"], 1)
        self.assertEqual(spark["lane_counts"]["staging_candidate"], 1)
        self.assertEqual(spark["lane_counts"]["packaged"], 1)
        # Status classification — use (lane, filename) since same filename can appear in two lanes.
        statuses = {(f["lane"], f["filename"]): f["status_class"] for f in spark["files"]}
        self.assertEqual(statuses[("paste_ready", "lead-1-CRITICAL.md")], "escalated")
        self.assertEqual(statuses[("packaged", "lead-1-CRITICAL.md")], "submitted")
        self.assertEqual(
            statuses[("staging_candidate", "lead-commit-resume-CANDIDATE.md")], "dropped"
        )
        # Privacy: no absolute paths leak
        blob = json.dumps(result)
        self.assertNotIn(str(self.audits_root), blob)
        # source_refs are audits-root-relative
        for ref in result["source_refs"]:
            self.assertFalse(Path(ref).is_absolute())

    def test_engagement_status_default_scope_filters_terminal_only_engagements(self):
        old_default = vault_mcp_server.DEFAULT_AUDITS_ROOT
        vault_mcp_server.DEFAULT_AUDITS_ROOT = self.audits_root
        try:
            result = self.vault.vault_engagement_status()
        finally:
            vault_mcp_server.DEFAULT_AUDITS_ROOT = old_default

        names = {e["engagement"] for e in result["engagements"]}
        self.assertIn("spark", names)
        self.assertNotIn("morpho", names)
        self.assertTrue(result["filters"]["default_scoped"])
        self.assertGreaterEqual(result["summary"]["default_scope_filtered_engagements"], 1)
        blob = json.dumps(result)
        self.assertNotIn(str(self.audits_root), blob)

    def test_engagement_status_default_scope_caps_active_engagements(self):
        for idx in range(vault_mcp_server.MAX_DEFAULT_ENGAGEMENT_STATUS_ENGAGEMENTS + 2):
            submissions = self.audits_root / f"active-{idx:02d}" / "submissions" / "staging"
            _write_finding(
                submissions / f"lead-{idx:02d}-CANDIDATE.md",
                title=f"Active candidate {idx:02d}",
                status="CANDIDATE",
            )

        old_default = vault_mcp_server.DEFAULT_AUDITS_ROOT
        vault_mcp_server.DEFAULT_AUDITS_ROOT = self.audits_root
        try:
            result = self.vault.vault_engagement_status()
        finally:
            vault_mcp_server.DEFAULT_AUDITS_ROOT = old_default

        self.assertLessEqual(
            len(result["engagements"]),
            vault_mcp_server.MAX_DEFAULT_ENGAGEMENT_STATUS_ENGAGEMENTS,
        )
        self.assertEqual(
            result["summary"]["engagements_returned"],
            len(result["engagements"]),
        )

    def test_engagement_status_explicit_engagement_path_scopes_to_one(self):
        result = self.vault.vault_engagement_status(
            audits_root=str(self.audits_root),
            engagement_path=str(self.audits_root / "morpho"),
        )
        self.assertEqual(len(result["engagements"]), 1)
        self.assertEqual(result["engagements"][0]["engagement"], "morpho")
        self.assertEqual(result["engagements"][0]["file_count"], 1)
        self.assertEqual(
            result["engagements"][0]["files"][0]["status_class"], "paid"
        )

    def test_engagement_status_filters_and_stable_hash(self):
        first = self.vault.vault_engagement_status(
            audits_root=str(self.audits_root), engagement="spark"
        )
        second = self.vault.vault_engagement_status(
            audits_root=str(self.audits_root), engagement="spark"
        )
        self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])
        self.assertEqual(first["context_pack_id"], second["context_pack_id"])
        self.assertEqual(len(first["engagements"]), 1)
        self.assertEqual(first["engagements"][0]["engagement"], "spark")
        self.assertEqual(first["filters"]["engagement"], "spark")

    def test_engagement_status_missing_audits_root_returns_error(self):
        bogus = Path(self.tmp.name) / "does_not_exist"
        result = self.vault.vault_engagement_status(audits_root=str(bogus))
        self.assertEqual(result["error"], "audits_root_not_found")

    def test_engagement_status_engagement_path_escape_rejected(self):
        # path outside audits_root should fail-closed
        result = self.vault.vault_engagement_status(
            audits_root=str(self.audits_root),
            engagement_path=str(Path(self.tmp.name)),
        )
        self.assertEqual(result["error"], "engagement_path_escapes_audits_root")

    def test_engagement_status_secret_files_dropped(self):
        spark = self.audits_root / "spark" / "submissions" / "paste_ready"
        secret = spark / "leaky-CRITICAL.md"
        secret.write_text(
            "# Leaky\n\nStatus: SUBMITTED\nprivate_key: 0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n",
            encoding="utf-8",
        )
        result = self.vault.vault_engagement_status(
            audits_root=str(self.audits_root), engagement="spark"
        )
        spark_eng = next(e for e in result["engagements"] if e["engagement"] == "spark")
        names = {f["filename"] for f in spark_eng["files"]}
        self.assertNotIn("leaky-CRITICAL.md", names)


# r36-rebuttal: bugfix-inventory-claude-20260610 registered in agent_pathspec.json
class EngagementStatusClassifyWordBoundaryTest(unittest.TestCase):
    """Unit tests for _engagement_status_classify substring false-positives (bug-inventory-claude-20260610 Bugs 2+3)."""

    def test_de_escalated_is_not_classified_as_escalated(self):
        # Bug 2: 'escalat' is a substring of 'de-escalated' - negative lookbehind required
        result = vault_mcp_server._engagement_status_classify("de-escalated from High")
        self.assertNotEqual(result, "escalated", "de-escalated should NOT classify as escalated")
        self.assertEqual(result, "unknown")

    def test_de_escalation_is_not_classified_as_escalated(self):
        result = vault_mcp_server._engagement_status_classify("de-escalation notice")
        self.assertNotEqual(result, "escalated", "de-escalation should NOT classify as escalated")

    def test_escalated_alone_still_classified_as_escalated(self):
        result = vault_mcp_server._engagement_status_classify("escalated")
        self.assertEqual(result, "escalated")

    def test_escalated_by_triager_still_classified_as_escalated(self):
        result = vault_mcp_server._engagement_status_classify("ESCALATED BY TRIAGER 2026-05-07")
        self.assertEqual(result, "escalated")

    def test_profiled_is_not_classified_as_submitted(self):
        # Bug 3: 'filed' is a substring of 'profiled' - word-boundary required
        result = vault_mcp_server._engagement_status_classify("profiled")
        self.assertNotEqual(result, "submitted", "profiled should NOT classify as submitted")
        self.assertEqual(result, "unknown")

    def test_defiled_is_not_classified_as_submitted(self):
        result = vault_mcp_server._engagement_status_classify("defiled")
        self.assertNotEqual(result, "submitted", "defiled should NOT classify as submitted")

    def test_refiled_is_not_classified_as_submitted(self):
        result = vault_mcp_server._engagement_status_classify("refiled")
        self.assertNotEqual(result, "submitted", "refiled should NOT classify as submitted")

    def test_filed_alone_still_classified_as_submitted(self):
        result = vault_mcp_server._engagement_status_classify("filed")
        self.assertEqual(result, "submitted")

    def test_submitted_still_classified_as_submitted(self):
        result = vault_mcp_server._engagement_status_classify("submitted")
        self.assertEqual(result, "submitted")

    def test_submitted_with_date_still_classified_as_submitted(self):
        result = vault_mcp_server._engagement_status_classify("SUBMITTED 2026-05-06 + ESCALATED BY TRIAGER 2026-05-07")
        self.assertEqual(result, "escalated")


class EngagementStatusDeEscalatedIntegrationTest(unittest.TestCase):
    """Integration test: de-escalated finding should not appear as escalated in vault_engagement_status output."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-eng-deescalate-")
        self.audits_root = Path(self.tmp.name) / "audits"
        self.audits_root.mkdir()
        spark = self.audits_root / "spark" / "submissions"
        _write_finding(
            spark / "staging" / "lead-deescalated.md",
            title="De-escalated finding",
            status="de-escalated from High",
            severity="Medium",
        )
        self.vault = vault_mcp_server.VaultQuery(
            Path(self.tmp.name) / "vault",
            Path(__file__).resolve().parents[2],
        )
        (Path(self.tmp.name) / "vault").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_de_escalated_finding_status_class_is_not_escalated(self):
        result = self.vault.vault_engagement_status(
            audits_root=str(self.audits_root), engagement="spark"
        )
        spark_eng = next(e for e in result["engagements"] if e["engagement"] == "spark")
        deesc = next(f for f in spark_eng["files"] if f["filename"] == "lead-deescalated.md")
        self.assertNotEqual(
            deesc["status_class"], "escalated",
            "de-escalated finding must not be classified as escalated"
        )


if __name__ == "__main__":
    unittest.main()
