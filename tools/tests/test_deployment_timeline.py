"""tests/test_deployment_timeline.py — unit tests for tools/deployment-timeline.py

Each test builds a minimal mock git repo + mock deployments directory so that
the tool exercises real subprocess.run(['git', '-C', ...]) calls without
touching any external network.
"""

import json
import os
import subprocess
import sys
import tempfile
import types
import unittest

# Make the tools/ directory importable.
TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, TOOLS_DIR)

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "deployment_timeline",
    os.path.join(TOOLS_DIR, "deployment-timeline.py"),
)
dt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dt)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_git_repo(tmp: str, commits: list[dict]) -> str:
    """
    Create a bare-minimum git repo under tmp/repo with the supplied commits.

    Each element of commits is a dict:
        {
          "date": "2026-04-20T12:00:00+00:00",   # GIT_AUTHOR_DATE / GIT_COMMITTER_DATE
          "message": "initial commit",
          "tags": ["v1.0.0"],                      # optional list of annotated tags
          "files": {"README.md": "hello"},          # optional files to touch
        }
    Returns the repo path.
    """
    repo = os.path.join(tmp, "repo")
    os.makedirs(repo)
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "Test"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "Test"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"

    subprocess.run(["git", "init", repo], check=True, capture_output=True)
    subprocess.run(["git", "-C", repo, "config", "commit.gpgsign", "false"],
                   check=True, capture_output=True)

    for i, commit in enumerate(commits):
        date = commit["date"]
        msg = commit.get("message", f"commit {i}")
        files = commit.get("files", {"dummy.txt": str(i)})
        for fname, content in files.items():
            fpath = os.path.join(repo, fname)
            with open(fpath, "w") as f:
                f.write(content)
        subprocess.run(["git", "-C", repo, "add", "."], check=True, capture_output=True)
        commit_env = env.copy()
        commit_env["GIT_AUTHOR_DATE"] = date
        commit_env["GIT_COMMITTER_DATE"] = date
        subprocess.run(
            ["git", "-C", repo, "commit", "-m", msg],
            check=True, capture_output=True, env=commit_env,
        )
        for tag in commit.get("tags", []):
            subprocess.run(
                ["git", "-C", repo, "tag", tag],
                check=True, capture_output=True,
            )

    return repo


def _make_deployments_dir(tmp: str, structure: dict) -> str:
    """
    Create a mock deployments directory.

    structure = {
        "sepolia": ["2026-04-15-foo", "2026-04-25-bar"],
        "mainnet": ["2026-03-01-deploy"],
    }
    """
    deploy = os.path.join(tmp, "deployments")
    for network, dirs in structure.items():
        for d in dirs:
            os.makedirs(os.path.join(deploy, network, d), exist_ok=True)
    return deploy


def _get_latest_sha(repo: str) -> str:
    result = subprocess.run(
        ["git", "-C", repo, "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParseIsoDate(unittest.TestCase):
    def test_utc_offset(self):
        d = dt.parse_iso_date("2026-04-23T17:29:32-07:00")
        self.assertEqual(d.year, 2026)
        self.assertEqual(d.month, 4)

    def test_z_suffix(self):
        d = dt.parse_iso_date("2026-04-23T17:29:32Z")
        self.assertEqual(d.year, 2026)

    def test_date_only_fallback(self):
        d = dt.parse_iso_date("2026-04-23")
        self.assertEqual(d.day, 23)


class TestParseDirDate(unittest.TestCase):
    def test_normal(self):
        d = dt.parse_dir_date("2026-04-20-activate-multiproof")
        self.assertIsNotNone(d)
        self.assertEqual(d.day, 20)

    def test_no_prefix(self):
        self.assertIsNone(dt.parse_dir_date("signatures"))

    def test_bare_date(self):
        d = dt.parse_dir_date("2026-01-01")
        self.assertIsNotNone(d)
        self.assertEqual(d.month, 1)


class TestPostCommitNoDeploymentYet(unittest.TestCase):
    """Commit dated 2026-04-20; only deployment dir is 2026-04-15 → bug never shipped."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(self.tmp, [
            {"date": "2026-04-20T12:00:00+00:00", "message": "bug commit"},
        ])
        self.sha = _get_latest_sha(self.repo)
        self.deploy = _make_deployments_dir(self.tmp, {
            "sepolia": ["2026-04-15-deploy"],
        })

    def test_verdict(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        self.assertEqual(report["verdict"], "post_commit_no_deployment_yet")

    def test_dirs_after_is_empty(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        self.assertEqual(report["networks"]["sepolia"]["dirs_at_or_after_commit"], [])


class TestPreCommitDeploymentExists(unittest.TestCase):
    """Commit dated 2026-04-20; only deployment dir is 2026-04-25 → bug may have shipped."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(self.tmp, [
            {"date": "2026-04-20T12:00:00+00:00", "message": "bug commit"},
        ])
        self.sha = _get_latest_sha(self.repo)
        self.deploy = _make_deployments_dir(self.tmp, {
            "sepolia": ["2026-04-25-upgrade"],
        })

    def test_verdict(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        self.assertEqual(report["verdict"], "pre_commit_deployment_exists")

    def test_dirs_before_is_empty(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        self.assertEqual(report["networks"]["sepolia"]["dirs_before_commit"], [])


class TestMixedDeployments(unittest.TestCase):
    """Commit dated 2026-04-20; deployments at both 2026-04-15 and 2026-04-25 → mixed."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(self.tmp, [
            {"date": "2026-04-20T12:00:00+00:00", "message": "bug commit"},
        ])
        self.sha = _get_latest_sha(self.repo)
        self.deploy = _make_deployments_dir(self.tmp, {
            "sepolia": ["2026-04-15-deploy", "2026-04-25-upgrade"],
        })

    def test_verdict(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        self.assertEqual(report["verdict"], "mixed")


class TestNetworkFilter(unittest.TestCase):
    """Only the requested network is considered in the verdict."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(self.tmp, [
            {"date": "2026-04-20T12:00:00+00:00", "message": "bug commit"},
        ])
        self.sha = _get_latest_sha(self.repo)
        # mainnet has a post-commit deployment; sepolia does not.
        self.deploy = _make_deployments_dir(self.tmp, {
            "sepolia": ["2026-04-15-deploy"],
            "mainnet": ["2026-04-25-upgrade"],
        })

    def test_sepolia_only(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        self.assertEqual(report["verdict"], "post_commit_no_deployment_yet")
        self.assertNotIn("mainnet", report["networks"])

    def test_mainnet_only(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["mainnet"])
        self.assertEqual(report["verdict"], "pre_commit_deployment_exists")
        self.assertNotIn("sepolia", report["networks"])

    def test_all_networks_mixed(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=None)
        self.assertEqual(report["verdict"], "mixed")


class TestTagsContaining(unittest.TestCase):
    """Tags that contain the queried commit appear in per-network output."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(self.tmp, [
            {"date": "2026-04-20T12:00:00+00:00", "message": "tagged commit",
             "tags": ["v0.8.0-rc.26", "v0.8.0-rc.27"]},
        ])
        self.sha = _get_latest_sha(self.repo)
        self.deploy = _make_deployments_dir(self.tmp, {
            "sepolia": ["2026-04-15-deploy"],
        })

    def test_tags_present(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        tags = report["networks"]["sepolia"]["tags_containing_commit"]
        self.assertIn("v0.8.0-rc.26", tags)
        self.assertIn("v0.8.0-rc.27", tags)


class TestTagsNotContaining(unittest.TestCase):
    """Commits introduced AFTER a tag are NOT in that tag's history."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(self.tmp, [
            {"date": "2026-04-18T10:00:00+00:00", "message": "pre-bug",
             "tags": ["v0.8.0-rc.25"]},
            {"date": "2026-04-23T17:00:00+00:00", "message": "bug commit"},
        ])
        self.sha = _get_latest_sha(self.repo)
        self.deploy = _make_deployments_dir(self.tmp, {"sepolia": ["2026-04-15-deploy"]})

    def test_bug_commit_not_in_rc25(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        tags = report["networks"]["sepolia"]["tags_containing_commit"]
        self.assertNotIn("v0.8.0-rc.25", tags)


class TestJsonSchemaFields(unittest.TestCase):
    """All required top-level schema fields are present."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(self.tmp, [
            {"date": "2026-04-20T12:00:00+00:00", "message": "test commit"},
        ])
        self.sha = _get_latest_sha(self.repo)
        self.deploy = _make_deployments_dir(self.tmp, {"sepolia": ["2026-04-15-deploy"]})

    def test_required_keys(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        required = {
            "schema_version", "asset_repo", "asset_repo_head",
            "queried_commit", "queried_commit_author_date",
            "queried_commit_message", "networks", "verdict",
        }
        for key in required:
            self.assertIn(key, report, f"Missing key: {key}")

    def test_schema_version_value(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        self.assertEqual(report["schema_version"], "auditooor.deployment_timeline.v1")

    def test_json_serialisable(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        dumped = json.dumps(report)
        reloaded = json.loads(dumped)
        self.assertEqual(reloaded["verdict"], "post_commit_no_deployment_yet")


class TestNoDeployments(unittest.TestCase):
    """Network with no ISO-date-prefixed dirs yields no_deployments verdict."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(self.tmp, [
            {"date": "2026-04-20T12:00:00+00:00", "message": "test commit"},
        ])
        self.sha = _get_latest_sha(self.repo)
        # create a network dir with no date-prefixed subdirs
        deploy = os.path.join(self.tmp, "deployments")
        os.makedirs(os.path.join(deploy, "sepolia", "signatures"), exist_ok=True)
        self.deploy = deploy

    def test_no_deployments_verdict(self):
        report = dt.build_report(self.repo, self.deploy, self.sha, networks=["sepolia"])
        self.assertEqual(report["verdict"], "no_deployments")


if __name__ == "__main__":
    unittest.main()
