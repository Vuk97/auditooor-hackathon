#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.control.deployment_timeline import SCHEMA, collect_deployment_timeline


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", "-C", repo.as_posix(), *args],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return result.stdout.strip()


def _init_repo(repo: Path) -> None:
    repo.mkdir(parents=True)
    _git(repo, "init")
    _git(repo, "config", "user.email", "auditooor@example.invalid")
    _git(repo, "config", "user.name", "Auditooor Test")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _commit(repo: Path, relpath: str, text: str, message: str, when: str) -> str:
    _write(repo / relpath, text)
    _git(repo, "add", relpath)
    env = os.environ.copy()
    env["GIT_AUTHOR_DATE"] = when
    env["GIT_COMMITTER_DATE"] = when
    _git(repo, "commit", "-m", message, env=env)
    return _git(repo, "rev-parse", "HEAD")


def _deployment_json(commit: str, deployed_at: str) -> str:
    return json.dumps(
        {
            "contract": "BasePortal",
            "address": "0x1111111111111111111111111111111111111111",
            "commit": commit,
            "deployedAt": deployed_at,
        },
        indent=2,
        sort_keys=True,
    ) + "\n"


class ControlDeploymentTimelineTests(unittest.TestCase):
    def test_commit_before_deploy_opens_live_risk_window(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "asset"
            _init_repo(repo)
            _commit(repo, "src/BasePortal.sol", "contract BasePortal {}\n", "initial", "2026-01-01T00:00:00+00:00")
            bug = _commit(
                repo,
                "src/BasePortal.sol",
                "contract BasePortal { function unsafe() external {} }\n",
                "introduce bug",
                "2026-01-02T00:00:00+00:00",
            )
            head = _commit(
                repo,
                "deployments/base.json",
                _deployment_json(bug, "2026-01-03T12:00:00Z"),
                "record deployment",
                "2026-01-03T12:05:00+00:00",
            )

            payload = collect_deployment_timeline(
                repo,
                asset="BasePortal",
                bug_commit=bug,
                generated_at="2026-05-03T00:00:00Z",
            )

        self.assertEqual(payload["schema"], SCHEMA)
        self.assertEqual(payload["asset"]["pin"]["commit"], head)
        self.assertTrue(payload["risk_window"]["audit_pin_contains_bug"])
        self.assertEqual(payload["bug"]["introduced_commit"], bug)
        self.assertEqual(payload["deployment_evidence"]["status"], "found")
        self.assertEqual(payload["deployment_evidence"]["entries"][0]["source_commit"], bug)
        self.assertEqual(payload["risk_window"]["classification"], "bug_before_deployment")
        self.assertEqual(payload["risk_window"]["start"], "2026-01-03T12:00:00Z")
        self.assertEqual(payload["risk_window"]["end"], None)
        self.assertIn("risk_window_end_unverified", payload["uncertainty_flags"])
        command_ids = {row["id"] for row in payload["follow_up_commands"]}
        self.assertIn("live_state_check_1", command_ids)

    def test_commit_after_deploy_keeps_known_deployment_source_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "asset"
            _init_repo(repo)
            deployed_source = _commit(
                repo,
                "src/BasePortal.sol",
                "contract BasePortal { function safe() external {} }\n",
                "initial safe deployment source",
                "2026-01-01T00:00:00+00:00",
            )
            _commit(
                repo,
                "deployments/base.json",
                _deployment_json(deployed_source, "2026-01-02T12:00:00Z"),
                "record safe deployment",
                "2026-01-02T12:05:00+00:00",
            )
            bug = _commit(
                repo,
                "src/BasePortal.sol",
                "contract BasePortal { function unsafe() external {} }\n",
                "introduce post-deploy bug",
                "2026-01-03T00:00:00+00:00",
            )

            payload = collect_deployment_timeline(
                repo,
                asset="BasePortal",
                bug_commit=bug,
                generated_at="2026-05-03T00:00:00Z",
            )

        self.assertTrue(payload["risk_window"]["audit_pin_contains_bug"])
        self.assertEqual(payload["deployment_evidence"]["entries"][0]["source_commit"], deployed_source)
        self.assertEqual(payload["risk_window"]["classification"], "known_deployments_predate_bug")
        self.assertIsNone(payload["risk_window"]["start"])
        self.assertIn("no_known_live_deployment_includes_bug", payload["uncertainty_flags"])
        self.assertIn("live_deployment_refresh_needed", payload["uncertainty_flags"])
        command_ids = {row["id"] for row in payload["follow_up_commands"]}
        self.assertIn("refresh_deployment_lookup_with_rpc", command_ids)

    def test_missing_deployment_evidence_marks_live_window_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "asset"
            _init_repo(repo)
            _commit(repo, "src/BasePortal.sol", "contract BasePortal {}\n", "initial", "2026-01-01T00:00:00+00:00")
            bug = _commit(
                repo,
                "src/BasePortal.sol",
                "contract BasePortal { function unsafe() external {} }\n",
                "introduce bug",
                "2026-01-02T00:00:00+00:00",
            )

            payload = collect_deployment_timeline(
                repo,
                asset="BasePortal",
                bug_commit=bug,
                generated_at="2026-05-03T00:00:00Z",
            )

        self.assertEqual(payload["deployment_evidence"]["status"], "missing")
        self.assertEqual(payload["risk_window"]["classification"], "no_deployment_evidence")
        self.assertIsNone(payload["risk_window"]["start"])
        self.assertIn("no_deployment_evidence", payload["uncertainty_flags"])
        command_ids = {row["id"] for row in payload["follow_up_commands"]}
        self.assertIn("find_deployment_roots", command_ids)
        self.assertIn("deployment_lookup", command_ids)

    def test_unknown_bug_commit_blocks_timeline_ordering(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "asset"
            _init_repo(repo)
            source = _commit(repo, "src/BasePortal.sol", "contract BasePortal {}\n", "initial", "2026-01-01T00:00:00+00:00")
            _commit(
                repo,
                "deployments/base.json",
                _deployment_json(source, "2026-01-02T12:00:00Z"),
                "record deployment",
                "2026-01-02T12:05:00+00:00",
            )

            payload = collect_deployment_timeline(
                repo,
                asset="BasePortal",
                bug_commit="deadbeef",
                generated_at="2026-05-03T00:00:00Z",
            )

        self.assertEqual(payload["bug"]["status"], "unknown")
        self.assertEqual(payload["risk_window"]["classification"], "unknown_bug_commit")
        self.assertIn("bug_commit_unknown", payload["uncertainty_flags"])
        self.assertIn("cannot_order_bug_vs_deployment", payload["uncertainty_flags"])
        command_ids = {row["id"] for row in payload["follow_up_commands"]}
        self.assertIn("locate_bug_commit", command_ids)

    def test_explicit_broad_root_is_reduced_to_deployment_roots(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "asset"
            _init_repo(repo)
            bug = _commit(
                repo,
                "src/BasePortal.sol",
                "contract BasePortal { function unsafe() external {} }\n",
                "introduce bug",
                "2026-01-02T00:00:00+00:00",
            )
            _commit(
                repo,
                "deployments/base.json",
                _deployment_json(bug, "2026-01-03T12:00:00Z"),
                "record deployment",
                "2026-01-03T12:05:00+00:00",
            )
            for index in range(25):
                _write(repo / "external" / "borrowed" / f"noise-{index}.json", '{"commit":"deadbeef"}\n')

            payload = collect_deployment_timeline(
                repo,
                asset="BasePortal",
                bug_commit=bug,
                deployment_roots=[repo],
                generated_at="2026-05-03T00:00:00Z",
            )

        self.assertEqual(payload["deployment_evidence"]["status"], "found")
        self.assertEqual(payload["deployment_evidence"]["files_scanned"], 1)
        self.assertEqual(payload["deployment_evidence"]["entries"][0]["source_commit"], bug)
        self.assertTrue(
            payload["deployment_evidence"]["entries"][0]["path"].endswith("deployments/base.json")
        )


if __name__ == "__main__":
    unittest.main()
