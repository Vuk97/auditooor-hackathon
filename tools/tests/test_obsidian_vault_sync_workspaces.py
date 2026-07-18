#!/usr/bin/env python3
"""Focused tests for tools/obsidian-vault-sync.py workspace routing."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "obsidian-vault-sync.py"


def load_module():
    spec = importlib.util.spec_from_file_location("obsidian_vault_sync_for_test", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ObsidianVaultSyncWorkspacesTest(unittest.TestCase):
    def test_section_command_routes_workspaces_through_deep_crawler(self) -> None:
        mod = load_module()
        vault = Path("/tmp/test-vault")

        cmd = mod._section_command("workspaces", vault)

        self.assertEqual(cmd[0], sys.executable)
        self.assertEqual(Path(cmd[1]).name, "memory-deep-crawler.py")
        self.assertEqual(cmd[-2:], ["--section", "workspaces"])
        self.assertIn(str(vault), cmd)

    def test_section_command_routes_other_sections_through_static_emitter(self) -> None:
        mod = load_module()
        vault = Path("/tmp/test-vault")

        cmd = mod._section_command("patterns", vault)

        self.assertEqual(cmd[0], sys.executable)
        self.assertEqual(Path(cmd[1]).name, "obsidian-vault-emit.py")
        self.assertEqual(cmd[-2:], ["--section", "patterns"])
        self.assertIn(str(vault), cmd)

    def test_workspaces_staleness_tracks_dynamic_state_files(self) -> None:
        mod = load_module()
        original_sources = list(mod.SECTION_SOURCES["workspaces"])
        try:
            with tempfile.TemporaryDirectory(prefix="ovs-workspaces-") as tmp:
                root = Path(tmp)
                vault = root / "vault"
                vault.mkdir()
                audits_root = root / "audits"
                workspace = audits_root / "spark"
                workspace.mkdir(parents=True)
                state_file = workspace / ".auditooor-state.yaml"
                state_file.write_text("workspace: spark\nstatus: active\n", encoding="utf-8")

                mod.SECTION_SOURCES["workspaces"] = [str(audits_root / "*/.auditooor-state.yaml")]
                (vault / ".last_sync.json").write_text(
                    json.dumps({"generated": "2026-05-06T00:00Z"}),
                    encoding="utf-8",
                )

                stale = mod._stale_sections(vault, force=False)

                self.assertIn("workspaces", stale)
        finally:
            mod.SECTION_SOURCES["workspaces"] = original_sources

    def test_run_emit_invokes_deep_crawler_for_workspaces(self) -> None:
        mod = load_module()
        vault = Path("/tmp/test-vault")

        with mock.patch.object(mod.subprocess, "run") as run_mock:
            run_mock.return_value = mock.Mock(returncode=0, stdout="New/updated notes: 2\n", stderr="")

            written = mod._run_emit(["workspaces"], vault)

        self.assertEqual(written, 2)
        self.assertEqual(run_mock.call_count, 1)
        cmd = run_mock.call_args.args[0]
        self.assertEqual(Path(cmd[1]).name, "memory-deep-crawler.py")
        self.assertEqual(cmd[-2:], ["--section", "workspaces"])


if __name__ == "__main__":
    unittest.main()
