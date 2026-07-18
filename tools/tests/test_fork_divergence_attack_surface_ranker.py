#!/usr/bin/env python3
"""Tests for tools/fork-divergence-attack-surface-ranker.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "fork-divergence-attack-surface-ranker.py"


def _run(args, expect_rc=0):
    proc = subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if expect_rc is not None:
        assert proc.returncode == expect_rc, (
            "rc=%s\nstdout=%s\nstderr=%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    return proc


def _write_json(tmp: str, name: str, doc: dict) -> Path:
    path = Path(tmp) / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


class TestForkDivergenceAttackSurfaceRanker(unittest.TestCase):
    def test_scoring_order_prioritizes_reachable_security_surface(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {
                "schema": "auditooor.fdasr.fixture.v1",
                "rows": [
                    {
                        "module": "docs-helper",
                        "ecosystem": "go",
                        "fork_repo": "github.com/example/docs-helper",
                        "fork_missing_status": "current",
                        "reachability": "not-reachable",
                        "changed_surface": "docs fixture",
                        "evidence": ["docs update only"],
                        "next_command": "echo low",
                    },
                    {
                        "module": "wallet-signer",
                        "ecosystem": "cargo",
                        "fork_repo": "github.com/example/wallet-signer",
                        "divergence": "forked",
                        "reachability": "unknown",
                        "changed_surface": "signature replay auth",
                        "evidence": ["git dep differs from upstream repository"],
                        "next_command": "echo medium",
                    },
                    {
                        "module": "github.com/cometbft/cometbft",
                        "ecosystem": "go",
                        "fork_repo": "github.com/dydxprotocol/cometbft",
                        "fork_missing_status": "lagging",
                        "reachability": "reachable",
                        "changed_surface": "blocksync consensus validator verification",
                        "evidence": ["GHSA-test", "fix(blocksync): validate peer state"],
                        "candidate_security_commits": [
                            {
                                "commit_sha": "deadbeefcafe",
                                "tag": "v0.38.22",
                                "subject": "fix(blocksync): validate peer state",
                            }
                        ],
                        "next_command": "echo high",
                    },
                ],
            }
            inp = _write_json(tmp, "manifest.json", manifest)
            out = json.loads(_run(["--input", str(inp)]).stdout)
            modules = [row["module_package"] for row in out["rows"]]
            self.assertEqual(
                modules,
                [
                    "github.com/cometbft/cometbft",
                    "wallet-signer",
                    "docs-helper",
                ],
            )
            self.assertGreater(out["rows"][0]["priority_score"], out["rows"][1]["priority_score"])
            self.assertEqual(out["rows"][0]["priority_band"], "urgent")
            self.assertTrue(out["advisory_only"])

    def test_missing_input_is_a_harness_error(self):
        proc = _run([], expect_rc=1)
        self.assertIn("at least one --input", proc.stderr)
        self.assertEqual(proc.stdout, "")

    def test_stable_schema_and_deterministic_output_for_gomod_ancestry(self):
        with tempfile.TemporaryDirectory() as tmp:
            ancestry = {
                "schema": "auditooor.gomod_fork_ancestry.v1",
                "forks": [
                    {
                        "replace": {
                            "from": "github.com/cometbft/cometbft",
                            "to": "github.com/dydxprotocol/cometbft",
                            "version": "v0.38.6-0.20260428184537-904204b11c9e",
                        },
                        "fork_sha": "904204b11c9e",
                        "base_version": "v0.38.6",
                        "not_in_fork": ["v0.38.22"],
                        "candidate_security_commits": [
                            {
                                "tag": "v0.38.22",
                                "commit_sha": "deadbeefcafe",
                                "subject": "fix(blocksync): validate commit before accepting block",
                            }
                        ],
                    }
                ],
            }
            inp = _write_json(tmp, "gomod.json", ancestry)
            first = json.loads(_run(["--input", str(inp)]).stdout)
            second = json.loads(_run(["--input", str(inp)]).stdout)
            self.assertEqual(first, second)
            self.assertEqual(first["schema"], "auditooor.fork_divergence_attack_surface_ranker.v1")
            self.assertEqual(first["tool"], "fork-divergence-attack-surface-ranker")
            self.assertEqual(first["summary"]["rows"], 1)
            row = first["rows"][0]
            self.assertEqual(
                set(row),
                {
                    "rank",
                    "priority_score",
                    "priority_band",
                    "module_package",
                    "ecosystem",
                    "fork_repo",
                    "pin",
                    "upstream_reference",
                    "classification",
                    "changed_surface",
                    "exploitability_hints",
                    "evidence",
                    "next_command",
                    "terms",
                    "source",
                    "advisory_only",
                },
            )
            self.assertEqual(row["module_package"], "github.com/cometbft/cometbft")
            self.assertIn("fork-divergence-prober.py", row["next_command"])
            self.assertIn("consensus/validator safety", row["changed_surface"])


if __name__ == "__main__":
    unittest.main()
