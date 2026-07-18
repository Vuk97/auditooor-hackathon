#!/usr/bin/env python3
"""Focused tests for tools/memory-deep-crawler.py dry-run behavior."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "memory-deep-crawler.py"


def load_module():
    spec = importlib.util.spec_from_file_location("memory_deep_crawler_for_test", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class MemoryDeepCrawlerDryRunTest(unittest.TestCase):
    def test_cli_dry_run_force_commits_writes_no_vault_files_or_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mdc-dry-run-") as tmp:
            root = Path(tmp)
            vault = root / "vault"
            cache_dir = root / "cache"
            cache_dir.mkdir()
            env = os.environ.copy()
            env["TMPDIR"] = str(cache_dir)

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--vault-dir",
                    str(vault),
                    "--dry-run",
                    "--force",
                    "--section",
                    "commits",
                ],
                cwd=REPO_ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(
                proc.returncode,
                0,
                f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
            )
            self.assertIn("Running section: commits", proc.stdout)
            self.assertIn("Dry-run: skipped vault writes and sync-state save", proc.stdout)
            self.assertFalse(vault.exists(), "dry-run must not create or mutate vault files")
            self.assertEqual(
                list(cache_dir.glob("auditooor-git-log-30d-*")),
                [],
                "dry-run --force must not refresh the commits cache",
            )

    def test_commits_dry_run_does_not_mutate_sync_state_or_vault(self) -> None:
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="mdc-commits-") as tmp:
            vault = Path(tmp) / "vault"
            mod.GIT_LOG_CACHE = Path(tmp) / "git-log-cache.txt"
            mod.VAULT_WRITES_ENABLED = False
            sync_state = {}
            byte_counter = [0]

            written = mod.crawl_commits(
                vault,
                byte_counter,
                force=True,
                sync_state=sync_state,
                cap=10,
                dry_run=True,
            )

            self.assertGreaterEqual(written, 0)
            self.assertGreaterEqual(byte_counter[0], 0)
            self.assertEqual(sync_state, {})
            self.assertFalse((vault / "commits").exists())
            self.assertFalse(mod.GIT_LOG_CACHE.exists())

    def test_git_log_cache_path_is_repo_scoped(self) -> None:
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="mdc-cache-a-") as a:
            with tempfile.TemporaryDirectory(prefix="mdc-cache-b-") as b:
                self.assertNotEqual(
                    mod._git_log_cache_path(Path(a)),
                    mod._git_log_cache_path(Path(b)),
                )


class MemoryDeepCrawlerW63SectionParityTest(unittest.TestCase):
    """W6-3 / Gap G1: every ALL_SECTIONS entry must reach the sync orchestrator."""

    def _load_sync_module(self):
        sync_tool = REPO_ROOT / "tools" / "obsidian-vault-sync.py"
        spec = importlib.util.spec_from_file_location(
            "obsidian_vault_sync_for_parity_test", sync_tool
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"could not load {sync_tool}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_all_nine_sections_present(self) -> None:
        mod = load_module()
        for section in ("claude-memory", "codex-memory", "routines", "commits",
                        "prs", "tools-api", "make-targets", "workspaces",
                        "errors"):
            self.assertIn(section, mod.ALL_SECTIONS)

    def test_every_all_section_registered_in_vault_sync(self) -> None:
        crawler = load_module()
        sync = self._load_sync_module()
        for section in crawler.ALL_SECTIONS:
            self.assertIn(
                section,
                sync.SECTION_SOURCES,
                f"{section} (ALL_SECTIONS) missing from SECTION_SOURCES",
            )
            self.assertIn(
                section,
                sync.DEEP_CRAWLER_SECTIONS,
                f"{section} (ALL_SECTIONS) missing from DEEP_CRAWLER_SECTIONS",
            )

    def test_git_backed_sections_subset_of_all_sections(self) -> None:
        crawler = load_module()
        sync = self._load_sync_module()
        self.assertTrue(
            sync.GIT_BACKED_SECTIONS.issubset(set(crawler.ALL_SECTIONS))
        )

    def test_section_choices_accept_five_w63_sections(self) -> None:
        """Crawler --section already accepts the 5 sections (no change needed)."""
        mod = load_module()
        for section in ("routines", "commits", "prs", "make-targets", "errors"):
            self.assertIn(section, mod.ALL_SECTIONS)


if __name__ == "__main__":
    unittest.main()
