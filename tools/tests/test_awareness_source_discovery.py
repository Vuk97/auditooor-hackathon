from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "awareness-source-discovery.py"
SPEC = importlib.util.spec_from_file_location("awareness_source_discovery", TOOL)
DISCOVERY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(DISCOVERY)


PIN = "a" * 40


class AwarenessSourceDiscoveryTests(unittest.TestCase):
    def workspace(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "prior_audits").mkdir()
        (root / "prior_audits" / "report.md").write_text("prior finding", encoding="utf-8")
        (root / "prior_audits" / "known_issues.jsonl").write_text('{"id":"known-1"}\n', encoding="utf-8")
        audit = root / ".auditooor"
        audit.mkdir()
        (audit / "source_comment_reconciliation.json").write_text(json.dumps({"comments": [{"comment_id":"comment-1", "source_file":"src/Vault.sol", "line":7}]}), encoding="utf-8")
        (audit / "git_commits_mining_test.json").write_text(json.dumps({
            "schema":"auditooor.git_commits_mining.v1", "audit_pin_sha": PIN,
            "upstream_repo":"acme/vault",
            "commit_inventory":[{"sha":"b" * 40, "url":"https://github/acme/vault/commit/b"}],
            "shaped_commits_index":[],
        }), encoding="utf-8")
        github = audit / "github_awareness_history_acme_vault.json"
        github.write_text(json.dumps({
            "schema":"auditooor.github_awareness_history.v1", "audit_pin":PIN,
            "coverage":{kind:{"status":"complete"} for kind in ("pull_request","issue","discussion","review_comment")},
            "sources":[
                {"source_id":"github:acme/vault:pull_request:1","source_kind":"pull_request","source_ref":"https://github/pull/1"},
                {"source_id":"github:acme/vault:issue:2","source_kind":"issue","source_ref":"https://github/issue/2"},
                {"source_id":"github:acme/vault:discussion:issue-comment-3","source_kind":"discussion","source_ref":"https://github/issue/2#comment"},
                {"source_id":"github:acme/vault:review_comment:review-4","source_kind":"review_comment","source_ref":"https://github/pull/1#review"},
            ],
        }), encoding="utf-8")
        return temporary, root, github

    def test_composes_every_canonical_source_kind(self) -> None:
        temporary, root, github = self.workspace()
        self.addCleanup(temporary.cleanup)
        payload = DISCOVERY.discover(root, PIN, [github])
        self.assertEqual(payload["schema"], DISCOVERY.SCHEMA)
        self.assertEqual(set(payload["coverage"]), DISCOVERY.SOURCE_KINDS)
        self.assertEqual({row["source_kind"] for row in payload["sources"]}, DISCOVERY.SOURCE_KINDS)
        self.assertTrue(all(row["pin_binding"] == PIN for row in payload["sources"]))

    def test_missing_github_snapshot_blocks_discovery(self) -> None:
        temporary, root, _ = self.workspace()
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(DISCOVERY.DiscoveryError, "github_awareness_history_missing"):
            DISCOVERY.discover(root, PIN, [])

    def test_empty_local_stream_is_explicit_review_receipt(self) -> None:
        temporary, root, github = self.workspace()
        self.addCleanup(temporary.cleanup)
        (root / ".auditooor" / "source_comment_reconciliation.json").write_text(json.dumps({"comments": []}), encoding="utf-8")
        payload = DISCOVERY.discover(root, PIN, [github])
        self.assertIn("inventory-empty:source_comment", {row["source_id"] for row in payload["sources"]})

    def test_same_commit_sha_from_distinct_repositories_has_distinct_source_identity(self) -> None:
        temporary, root, github = self.workspace()
        self.addCleanup(temporary.cleanup)
        audit = root / ".auditooor"
        (audit / "git_commits_mining_second.json").write_text(json.dumps({
            "schema": "auditooor.git_commits_mining.v1",
            "audit_pin_sha": PIN,
            "upstream_repo": "acme/second",
            "commit_inventory": [{"sha": "b" * 40, "url": "https://github/acme/second/commit/b"}],
            "shaped_commits_index": [],
        }), encoding="utf-8")

        payload = DISCOVERY.discover(root, PIN, [github])
        commit_ids = {row["source_id"] for row in payload["sources"] if row["source_kind"] == "commit"}
        self.assertEqual(
            commit_ids,
            {f"commit:acme/vault:{'b' * 40}", f"commit:acme/second:{'b' * 40}"},
        )

    def test_commit_report_without_repository_identity_fails_closed(self) -> None:
        temporary, root, github = self.workspace()
        self.addCleanup(temporary.cleanup)
        path = root / ".auditooor" / "git_commits_mining_test.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload.pop("upstream_repo")
        path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(DISCOVERY.DiscoveryError, "commit_mining_repository_invalid"):
            DISCOVERY.discover(root, PIN, [github])


if __name__ == "__main__":
    unittest.main()
