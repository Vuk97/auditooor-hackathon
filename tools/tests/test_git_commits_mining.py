"""test_git_commits_mining — schema check for the Tier-6 git-commits mining report.

Worker-KK loop-8 POC: validates reports/git_commits_mining_centrifuge-v3_2026-05-06.json
against the auditooor.git_commits_mining.v1 schema. Stdlib-only.

Worker-XX loop-10 extends with two v1.1 tests covering the additive
``schema_version`` field and per-pattern ``impact_contract_preflight``
annotations (SS L10 Patch C, route="exploit-memory", advisory-only).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock


REPO = pathlib.Path(__file__).resolve().parents[2]
REPORT = REPO / "reports" / "git_commits_mining_centrifuge-v3_2026-05-06.json"
MINER = REPO / "tools" / "git-commits-mining.py"


def _load_miner_module():
    spec = importlib.util.spec_from_file_location("git_commits_mining_v1_1", MINER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load miner module: {MINER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GitCommitsMiningSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.assertReportExists = REPORT.exists()
        if cls.assertReportExists:
            cls.report = json.loads(REPORT.read_text())

    def test_report_file_exists(self) -> None:
        self.assertTrue(REPORT.exists(), f"missing report: {REPORT}")

    def test_schema_id(self) -> None:
        self.assertEqual(self.report.get("schema"), "auditooor.git_commits_mining.v1")

    def test_required_top_level_fields(self) -> None:
        required = (
            "workspace",
            "upstream_repo",
            "audit_pin_sha",
            "since_date",
            "commits_scanned",
            "security_fix_count",
            "commits",
        )
        for f in required:
            self.assertIn(f, self.report, f"missing top-level field: {f}")

    def test_commits_scanned_positive(self) -> None:
        self.assertIsInstance(self.report["commits_scanned"], int)
        self.assertGreater(self.report["commits_scanned"], 0)

    def test_commits_array_shape(self) -> None:
        commits = self.report["commits"]
        self.assertIsInstance(commits, list)
        self.assertGreaterEqual(len(commits), 1, "commits[] must have at least 1 entry")
        for c in commits:
            for k in ("sha", "url", "classification", "summary", "derivable_pattern"):
                self.assertIn(k, c, f"commit missing field: {k}")
            self.assertIn(
                c["classification"],
                ("security_fix", "code_quality", "feature", "unclear"),
            )
            self.assertIn(c["derivable_pattern"], ("yes", "no", "maybe"))
            self.assertTrue(c["url"].startswith("https://github.com/"))


class GitCommitsMiningV1_1ImpactContractTest(unittest.TestCase):
    """Worker-XX loop-10: v1.1 schema + per-pattern impact-contract preflight.

    These tests exercise the integration unit in isolation (no GH calls)
    by invoking the miner module's helpers directly on a synthetic
    commits[] structure that mirrors KK's reviewer-curated shape.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.miner = _load_miner_module()

    def test_v1_1_schema_version_emitted(self) -> None:
        """The miner module exposes the additive inventory schema bump."""
        self.assertEqual(getattr(self.miner, "SCHEMA_VERSION", None), "1.3")

    def test_impact_contract_preflight_attached_per_pattern(self) -> None:
        """Each commits[].patterns[] row gains an impact_contract_preflight key.

        Advisory-only: the decision can be `planning-artifact-advisory-bypass`,
        `unmapped`, or `impact-contract-explicit`; ``blocked`` must always be
        False (mining never fail-closes).
        """
        synthetic = [
            {
                "sha": "deadbeef" * 5,
                "subject": "fix: synthetic test commit",
                "classification": "security_fix",
                "patterns": [
                    {
                        "id": "synthetic-pattern-1",
                        "language": "Solidity",
                        "shape": "missing-eip150",
                        "confidence": "medium",
                    },
                    {
                        "id": "synthetic-pattern-2",
                        "language": "Solidity",
                        "shape": "unreachable-revert",
                        "confidence": "low",
                    },
                ],
            }
        ]
        counters = self.miner._attach_pattern_preflights(synthetic)

        self.assertEqual(counters["patterns_seen"], 2)
        # Either the loader landed and emitted packets, or the loader was
        # unavailable and emitted unmapped advisories — both are acceptable
        # advisory-only outcomes.
        self.assertEqual(
            counters["packets_attached"] + counters["loader_unavailable"],
            counters["patterns_seen"],
        )

        for pattern in synthetic[0]["patterns"]:
            self.assertIn("impact_contract_preflight", pattern)
            packet = pattern["impact_contract_preflight"]
            self.assertIsInstance(packet, dict)
            self.assertEqual(packet.get("route"), "exploit-memory")
            decision = packet.get("decision", {})
            # Advisory-only contract: never blocks the mining flow.
            self.assertFalse(decision.get("blocked", False))
            self.assertIn(
                decision.get("code"),
                (
                    "impact-contract-explicit",
                    "planning-artifact-advisory-bypass",
                    "impact-contract-missing",
                    "unmapped",
                ),
                f"unexpected decision code: {decision.get('code')!r}",
            )


class GitCommitsMiningAuthBehaviorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.miner = _load_miner_module()

    def test_gh_env_copies_github_token_and_disables_prompts(self) -> None:
        env = self.miner._gh_env({"GITHUB_TOKEN": "tok_123"})

        self.assertEqual(env["GH_TOKEN"], "tok_123")
        self.assertEqual(env["GH_PROMPT_DISABLED"], "1")
        self.assertEqual(env["GH_NO_BROWSER"], "1")
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")

    def test_gh_auth_ok_uses_status_not_login(self) -> None:
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with (
            mock.patch.object(self.miner, "_has_gh_token", return_value=False),
            mock.patch("subprocess.run", side_effect=fake_run),
        ):
            self.assertTrue(self.miner.gh_auth_ok())

        self.assertEqual(calls[0][0], ["gh", "auth", "status", "--hostname", "github.com"])
        self.assertNotIn("login", calls[0][0])
        self.assertEqual(calls[0][1]["timeout"], self.miner.GH_TIMEOUT_SECONDS)
        self.assertEqual(calls[0][1]["env"]["GH_PROMPT_DISABLED"], "1")
        self.assertEqual(calls[0][1]["env"]["GH_NO_BROWSER"], "1")

    def test_gh_auth_ok_with_token_skips_status_probe(self) -> None:
        with (
            mock.patch.object(self.miner, "_has_gh_token", return_value=True),
            mock.patch("subprocess.run") as run,
        ):
            self.assertTrue(self.miner.gh_auth_ok())

        run.assert_not_called()

    def test_gh_api_calls_use_noninteractive_env_and_timeout(self) -> None:
        expected = {
            "sha": "abc123",
            "date": "2026-05-27T00:00:00Z",
            "message": "fix: auth hang",
        }
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=json.dumps(expected) + "\n",
                stderr="",
            )

        with (
            mock.patch.dict("os.environ", {"GITHUB_TOKEN": "tok_456"}, clear=True),
            mock.patch("subprocess.run", side_effect=fake_run),
        ):
            commits = self.miner.gh_commits_since("org/repo", "2026-05-01T00:00:00Z")

        self.assertEqual(commits, [expected])
        cmd, kwargs = calls[0]
        self.assertEqual(cmd[0:2], ["gh", "api"])
        self.assertNotIn("auth", cmd)
        self.assertEqual(kwargs["timeout"], self.miner.GH_TIMEOUT_SECONDS)
        self.assertEqual(kwargs["env"]["GH_TOKEN"], "tok_456")
        self.assertEqual(kwargs["env"]["GH_PROMPT_DISABLED"], "1")
        self.assertEqual(kwargs["env"]["GH_NO_BROWSER"], "1")

    def test_main_falls_back_to_local_git_only_when_no_auth(self) -> None:
        commit = {
            "sha": "feedface",
            "date": "2026-05-27T00:00:00Z",
            "message": "fix: local fallback auth path",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = pathlib.Path(tmpdir) / "report.json"
            local_repo = pathlib.Path(tmpdir) / "repo"
            argv = [
                "git-commits-mining.py",
                "--workspace",
                "demo",
                "--upstream",
                "org/repo",
                "--since",
                "2026-05-01",
                "--local-repo",
                str(local_repo),
                "--out",
                str(out_path),
            ]
            with (
                mock.patch.object(self.miner, "gh_auth_ok", return_value=False),
                mock.patch.object(self.miner, "resolve_local_repo", return_value=local_repo),
                mock.patch.object(self.miner, "collect_local_commits", return_value=[commit]),
                mock.patch.object(self.miner, "gh_commits_since") as gh_since,
                mock.patch.object(self.miner, "_attach_pattern_preflights", return_value={"patterns_seen": 0}),
                mock.patch("sys.argv", argv),
            ):
                rc = self.miner.main()

            self.assertEqual(rc, 0)
            gh_since.assert_not_called()
            report = json.loads(out_path.read_text())
            self.assertTrue(report["fallback_used"])
            self.assertEqual(report["fallback_mode"], "local-git-only")
            self.assertEqual(report["security_fix_count"], 1)
            self.assertEqual(report["commit_inventory"], [{
                "sha": "feedface",
                "date": "2026-05-27T00:00:00Z",
                "subject": "fix: local fallback auth path",
                "url": "https://github.com/org/repo/commit/feedface",
            }])
            self.assertEqual(report["discussion_metadata"]["status"], "not_applicable")
            self.assertEqual(report["discussion_evidence"], [])

    def test_main_exits_three_when_no_auth_and_no_local_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = pathlib.Path(tmpdir) / "report.json"
            argv = [
                "git-commits-mining.py",
                "--workspace",
                "demo",
                "--upstream",
                "org/repo",
                "--since",
                "2026-05-01",
                "--out",
                str(out_path),
            ]
            with (
                mock.patch.object(self.miner, "gh_auth_ok", return_value=False),
                mock.patch.object(self.miner, "resolve_local_repo", return_value=None),
                mock.patch("sys.argv", argv),
            ):
                rc = self.miner.main()

            self.assertEqual(rc, self.miner.LOCAL_GIT_ONLY_EXIT_CODE)
            self.assertFalse(out_path.exists())


class ClassifyCommitSubjectTest(unittest.TestCase):
    def setUp(self):
        self.m = _load_miner_module()

    def test_housekeeping_commits_are_noise(self):
        for s in ("chore: fix lint", "fix: fmt", "core: fix typo", "chore: fix storage gap",
                  "bump deps", "docs: update readme", "ci: fix workflow"):
            c = self.m.classify_commit_subject(s)
            self.assertTrue(c["is_noise"], f"{s!r} should be noise")
            self.assertIsNone(c["bug_class"])
            self.assertEqual(c["classification"], "code_quality")

    def test_security_commits_get_bug_class_not_noise(self):
        cases = {
            "fix: move check internally to cover for dethroneAndUnstake": "staking",
            "fix: disable slashing on validatorshare": "staking",
            "consensus: fix milestone-mismatch rewind deadlock (#2246)": "dos",
            "fix(blocksync): prevent maxPeerHeight poisoning": "dos",
            "fix: add missing reentrancy guard": "reentrancy",
            "fix: onlyOwner check on claim": "access-control",
        }
        for s, expect in cases.items():
            c = self.m.classify_commit_subject(s)
            self.assertFalse(c["is_noise"], f"{s!r} must not be noise")
            self.assertEqual(c["bug_class"], expect, f"{s!r} -> {c['bug_class']}")
            self.assertEqual(c["classification"], "security_fix")

    def test_shaped_entry_always_carries_class_fields(self):
        entry = self.m.build_shaped_commit_entry(
            {"sha": "a" * 40, "date": "2026-01-01", "message": "fix: lint\n\nbody"},
            "0xPolygon/bor", "go")
        for k in ("bug_class", "is_noise", "classification"):
            self.assertIn(k, entry, f"shaped entry missing {k}")

    def test_commit_inventory_entry_carries_no_heuristic_classification(self):
        entry = self.m.build_commit_inventory_entry(
            {"sha": "b" * 40, "date": "2026-01-01T00:00:00Z", "message": "chore: wire a guard"},
            "acme/vault",
        )
        self.assertEqual(entry["subject"], "chore: wire a guard")
        self.assertNotIn("classification", entry)
        self.assertNotIn("bug_class", entry)


class DiscussionMetadataTest(unittest.TestCase):
    def setUp(self):
        self.m = _load_miner_module()

    def test_discussion_language_classifies_statuses(self):
        cases = [
            ({"state": "open", "title": "Security fix discussion"}, "open"),
            ({"state": "closed", "title": "Tracked issue"}, "closed"),
            ({"state": "open", "title": "Accepted security report"}, "accepted"),
            ({"state": "closed", "title": "Not planned"}, "wont-fix"),
            ({"state": "closed", "merged_at": "2026-06-01T00:00:00Z", "title": "Patch"}, "fixed"),
            ({"title": "Security team review"}, "team-aware"),
            ({"title": "Unclear maintenance note"}, "unknown"),
        ]
        for pr, expected in cases:
            actual = self.m.classify_discussion_language(pr, [], [])
            # Reviews are optional; the helper accepts an empty list in normal use.
            self.assertEqual(actual["classification"], expected, pr)

    def test_collector_emits_reconciliation_evidence_for_associated_pr(self):
        responses = {
            "repos/o/r/commits/abc/pulls?per_page=100": [{
                "number": 7,
                "html_url": "https://github.com/o/r/pull/7",
                "title": "Fix auth bypass",
                "body": "Resolved by the security team.",
                "state": "closed",
                "merged_at": "2026-06-01T00:00:00Z",
                "labels": [{"name": "security"}],
            }],
            "repos/o/r/issues/7/comments?per_page=100": [{"id": 1, "body": "fixed", "html_url": "https://x/c"}],
            "repos/o/r/pulls/7/reviews?per_page=100": [],
        }

        def api_get(path):
            return responses.get(path)

        records = self.m.collect_github_discussion_evidence(
            "o/r", [{"sha": "abc", "message": "fix: auth", "date": "2026-06-01"}], api_get
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["commit_sha"], "abc")
        self.assertEqual(records[0]["pull_request_number"], 7)
        self.assertEqual(records[0]["discussion_classification"], "fixed")
        self.assertEqual(records[0]["comments"][0]["body_excerpt"], "fixed")

    def test_missing_api_response_is_empty_and_does_not_invent_status(self):
        records = self.m.collect_github_discussion_evidence(
            "o/r", [{"sha": "abc", "message": "fix: auth", "date": "2026-06-01"}], lambda _path: None
        )
        self.assertEqual(records, [])


class TestNoLazyFetchOnPartialClone(unittest.TestCase):
    """Regression: commit-mining must NOT trigger per-commit on-demand blob
    fetches on a --filter=blob:none (blobless) clone - that turned an 18-repo
    Lido make-audit into minutes of network thrash. _git_env must set
    GIT_NO_LAZY_FETCH=1 so a blob-content `git show` fails fast locally instead
    of fetching; the caller already tolerates patch_text="" and --name-only
    (tree-level, no blobs) still resolves paths."""

    def setUp(self):
        self.m = _load_miner_module()

    def test_git_env_disables_lazy_fetch(self):
        env = self.m._git_env()
        self.assertEqual(env.get("GIT_NO_LAZY_FETCH"), "1")
        self.assertEqual(env.get("GIT_TERMINAL_PROMPT"), "0")

    def test_run_git_passes_no_lazy_fetch_into_subprocess(self):
        captured = {}

        def fake_run(args, **kwargs):
            captured["env"] = kwargs.get("env") or {}
            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            return R()

        with mock.patch.object(self.m.subprocess, "run", side_effect=fake_run):
            self.m.run_git(pathlib.Path("/tmp"), ["show", "-s", "--format=%cI", "a" * 40])
        self.assertEqual(captured["env"].get("GIT_NO_LAZY_FETCH"), "1")


class PublicApiForwardMineTest(unittest.TestCase):
    """Unauthenticated public-API tier: gh-auth-free remote forward+backward mine
    for PUBLIC repos, instead of degrading to local-git-only (which has no post-pin
    commits when the local clone is checked out at the audit pin)."""

    def setUp(self):
        self.m = _load_miner_module()

    def test_public_repo_accessible_true_for_public(self):
        with mock.patch.object(self.m, "_public_api_get",
                               return_value={"full_name": "lidofinance/core", "private": False}):
            self.assertTrue(self.m.public_repo_accessible("lidofinance/core"))

    def test_public_repo_accessible_false_for_private_or_missing(self):
        with mock.patch.object(self.m, "_public_api_get",
                               return_value={"full_name": "x/y", "private": True}):
            self.assertFalse(self.m.public_repo_accessible("x/y"))
        with mock.patch.object(self.m, "_public_api_get", return_value=None):
            self.assertFalse(self.m.public_repo_accessible("x/missing"))

    def test_collect_public_commits_dedup_forward_and_backward(self):
        fwd = [{"sha": "a" * 40, "date": "2026-05-01T00:00:00Z", "message": "fix: bug"}]
        bwd = [{"sha": "a" * 40, "date": "2026-04-01T00:00:00Z", "message": "dup"},
               {"sha": "b" * 40, "date": "2026-03-01T00:00:00Z", "message": "older"}]
        with mock.patch.object(self.m, "public_commits_since", return_value=fwd), \
             mock.patch.object(self.m, "public_commits_window", return_value=bwd):
            out = self.m.collect_public_commits("o/r", "2026-04-23T00:00:00Z",
                                                "b" * 40, "bidirectional", 50)
        shas = [c["sha"] for c in out]
        self.assertIn("a" * 40, shas)
        self.assertIn("b" * 40, shas)
        self.assertEqual(len(shas), len(set(shas)), "must dedup by sha")

    def test_report_marks_public_unauthenticated_api_not_local(self):
        # gh unavailable + public repo => report.fallback_mode == public-unauthenticated-api
        # (a real remote mine), NOT local-git-only (which would DEGRADE step-integrity).
        import argparse
        with tempfile.TemporaryDirectory() as ws:
            out = pathlib.Path(ws) / "cm.json"
            argv = ["--upstream", "o/pub", "--workspace", ws, "--audit-pin", "c" * 40,
                    "--lang", "solidity", "--mode", "bidirectional",
                    "--output", str(out)]
            with mock.patch.object(self.m, "gh_auth_ok", return_value=False), \
                 mock.patch.object(self.m, "public_repo_accessible", return_value=True), \
                 mock.patch.object(self.m, "public_commit_date", return_value="2026-04-23"), \
                 mock.patch.object(self.m, "public_commits_since",
                                   return_value=[{"sha": "a" * 40, "date": "2026-05-01T00:00:00Z",
                                                  "message": "fix: reentrancy"}]), \
                 mock.patch.object(self.m, "public_commits_window", return_value=[]), \
                 mock.patch.object(self.m, "public_commit_detail", return_value={}), \
                 mock.patch.object(self.m.sys, "argv", ["git-commits-mining.py"] + argv):
                rc = self.m.main()
            self.assertEqual(rc, 0)
            d = json.loads(out.read_text())
            self.assertEqual(d.get("fallback_mode"), "public-unauthenticated-api")
            self.assertTrue(d.get("remote_mine"))
            self.assertFalse(d.get("fallback_used"))


if __name__ == "__main__":
    unittest.main()
