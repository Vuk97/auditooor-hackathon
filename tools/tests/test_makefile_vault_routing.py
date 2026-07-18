#!/usr/bin/env python3
"""Regression tests for VAULT-routed shared-memory Makefile targets."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
ACTIVE_VAULT = "/Users/wolf/Documents/Codex/auditooor/obsidian-vault"


def make_dry_run(target: str, *args: str) -> str:
    result = subprocess.run(
        ["make", "-n", target, *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"make dry-run failed for {target} with rc {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result.stdout


class MakefileVaultRoutingTest(unittest.TestCase):
    def test_vault_refresh_defaults_to_repo_local_vault(self) -> None:
        output = make_dry_run("vault-refresh")

        self.assertIn("--vault-dir obsidian-vault --deep", output)
        self.assertIn("--vault-dir obsidian-vault", output)
        self.assertIn("--vault obsidian-vault --whitelist reports/privacy_audit_whitelist.yaml", output)

    def test_vault_refresh_honors_active_vault_override(self) -> None:
        output = make_dry_run("vault-refresh", f"VAULT={ACTIVE_VAULT}")

        self.assertIn(f"--vault-dir {ACTIVE_VAULT} --deep", output)
        self.assertIn(f"--vault-dir {ACTIVE_VAULT}", output)
        self.assertIn(f"--vault {ACTIVE_VAULT} --whitelist reports/privacy_audit_whitelist.yaml", output)
        self.assertIn(
            f"Run: python3 tools/memory-privacy-audit.py --vault {ACTIVE_VAULT} --quarantine",
            output,
        )

    def test_vault_sync_and_status_honor_active_vault_override(self) -> None:
        sync_output = make_dry_run("vault-sync", f"VAULT={ACTIVE_VAULT}")
        status_output = make_dry_run("vault-status", f"VAULT={ACTIVE_VAULT}")

        self.assertIn(f"tools/obsidian-vault-sync.py --vault-dir {ACTIVE_VAULT}", sync_output)
        self.assertIn(f"tools/memory-deep-crawler.py --vault-dir {ACTIVE_VAULT}", sync_output)
        self.assertIn(f"tools/obsidian-vault-sync.py --vault-dir {ACTIVE_VAULT} --status", status_output)
        self.assertIn(f"tools/memory-deep-crawler.py --vault-dir {ACTIVE_VAULT} --status", status_output)

    def test_memory_gap_and_next_loop_honor_active_vault_override(self) -> None:
        gap_output = make_dry_run("memory-gap-analysis", f"VAULT={ACTIVE_VAULT}")
        next_output = make_dry_run("memory-next-loop", f"VAULT={ACTIVE_VAULT}")
        dry_run_output = make_dry_run("memory-next-loop-dry-run", f"VAULT={ACTIVE_VAULT}")

        self.assertIn(f"tools/memory-gap-analyzer.py --vault-dir {ACTIVE_VAULT}", gap_output)
        self.assertIn(f"tools/memory-gap-analyzer.py --vault-dir {ACTIVE_VAULT}", next_output)
        self.assertIn(f"tools/memory-next-loop-dispatcher.py --vault-dir {ACTIVE_VAULT}", next_output)
        self.assertIn(f"tools/memory-gap-analyzer.py --vault-dir {ACTIVE_VAULT}", dry_run_output)
        self.assertIn(
            f"tools/memory-next-loop-dispatcher.py --vault-dir {ACTIVE_VAULT} --dry-run",
            dry_run_output,
        )


if __name__ == "__main__":
    unittest.main()
