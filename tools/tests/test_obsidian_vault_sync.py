#!/usr/bin/env python3
"""Regression tests for tools/obsidian-vault-sync.py."""

from __future__ import annotations

import importlib.util
import json
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


class ObsidianVaultSyncTest(unittest.TestCase):
    def test_engagement_verdicts_section_is_not_tracked_for_sync(self) -> None:
        mod = load_module()
        self.assertNotIn("engagement-verdicts", mod.SECTION_SOURCES)

    def test_stale_sections_include_external_memory_sources(self) -> None:
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="ovs-stale-") as tmp:
            root = Path(tmp)
            vault = root / "vault"
            vault.mkdir()
            (vault / ".last_sync.json").write_text(
                json.dumps({"generated": "2026-05-01T00:00Z"}),
                encoding="utf-8",
            )

            claude_dir = root / "claude-memory"
            claude_dir.mkdir()
            (claude_dir / "feedback_alpha.md").write_text("# feedback\n", encoding="utf-8")

            codex_dir = root / "codex"
            rules_path = codex_dir / "rules" / "default.rules"
            rules_path.parent.mkdir(parents=True)
            rules_path.write_text("allow git status\n", encoding="utf-8")
            session_index = codex_dir / "session_index.jsonl"
            session_index.write_text(
                '{"id":"abc","thread_name":"sync","updated_at":"2026-05-06T23:21:47Z"}\n',
                encoding="utf-8",
            )

            mod.SECTION_SOURCES = {
                "claude-memory": [],
                "codex-memory": [],
            }
            mod.CLAUDE_MEMORY_DIR = claude_dir
            mod.CODEX_RULES_PATH = rules_path
            mod.CODEX_SESSION_INDEX_PATH = session_index

            stale = mod._stale_sections(vault, force=False)

            self.assertEqual(stale, ["claude-memory", "codex-memory"])

    def test_memory_path_list_parsing_normalizes_and_dedupes(self) -> None:
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="ovs-memory-paths-") as tmp:
            root = Path(tmp)
            first = root / "one" / "memory" / "MEMORY.md"
            second_dir = root / "two" / "memory"
            second = second_dir / "MEMORY.md"

            parsed = mod._configured_memory_paths(
                [f"{first}{mod.os.pathsep}{second_dir}", first.parent],
                environ={},
            )

            self.assertEqual(parsed, [first.resolve(), second.resolve()])

    def test_agent_memory_sources_aggregate_multiple_roots_without_duplicates(self) -> None:
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="ovs-agent-memory-") as tmp:
            root = Path(tmp)
            first = root / "one" / "memory" / "MEMORY.md"
            first.parent.mkdir(parents=True)
            first.write_text(
                "- [Alpha](alpha.md) - linked file\n"
                "- [Alpha again](alpha.md) - duplicate link\n",
                encoding="utf-8",
            )
            alpha = first.parent / "alpha.md"
            alpha.write_text("# alpha\n", encoding="utf-8")

            second = root / "two" / "memory" / "MEMORY.md"
            second.parent.mkdir(parents=True)
            second.write_text("# second\n", encoding="utf-8")

            missing = root / "missing" / "memory" / "MEMORY.md"

            sources = mod._agent_memory_source_paths(
                [first, second.parent, missing, first]
            )

            self.assertEqual(sources, [first.resolve(), alpha.resolve(), second.resolve()])

    def test_claude_memory_sources_include_each_configured_root_once(self) -> None:
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="ovs-claude-memory-") as tmp:
            root = Path(tmp)
            first = root / "one" / "memory" / "MEMORY.md"
            second = root / "two" / "memory" / "MEMORY.md"
            configured = mod._parse_memory_paths([first, second.parent, first.parent])
            original_configured = mod._CONFIGURED_MEMORY_PATHS
            try:
                mod._CONFIGURED_MEMORY_PATHS = configured

                sources = mod._section_sources("claude-memory")
            finally:
                mod._CONFIGURED_MEMORY_PATHS = original_configured

            self.assertEqual(
                sources,
                [
                    str(first.parent.resolve()),
                    str((first.parent / "*.md").resolve()),
                    str(second.parent.resolve()),
                    str((second.parent / "*.md").resolve()),
                ],
            )

    def test_claude_memory_staleness_checks_all_configured_roots(self) -> None:
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="ovs-claude-memory-stale-") as tmp:
            root = Path(tmp)
            vault = root / "vault"
            vault.mkdir()
            (vault / ".last_sync.json").write_text(
                json.dumps({"generated": "2026-05-01T00:00Z"}),
                encoding="utf-8",
            )

            stale_memory = root / "two" / "memory" / "MEMORY.md"
            stale_memory.parent.mkdir(parents=True)
            stale_memory.write_text("# new\n", encoding="utf-8")
            missing_memory = root / "missing" / "memory" / "MEMORY.md"

            original_sources = dict(mod.SECTION_SOURCES)
            original_configured = mod._CONFIGURED_MEMORY_PATHS
            try:
                mod.SECTION_SOURCES = {"claude-memory": []}
                mod._CONFIGURED_MEMORY_PATHS = mod._parse_memory_paths(
                    [missing_memory, stale_memory]
                )

                stale = mod._stale_sections(vault, force=False)
            finally:
                mod.SECTION_SOURCES = original_sources
                mod._CONFIGURED_MEMORY_PATHS = original_configured

            self.assertEqual(stale, ["claude-memory"])

    def test_external_memory_refresh_uses_selected_vault(self) -> None:
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="ovs-refresh-") as tmp:
            vault = Path(tmp) / "selected-vault"
            commands: list[list[str]] = []

            class Result:
                returncode = 0
                stdout = "Deep crawler complete:\n  New/updated notes: 2\n"
                stderr = ""

            original_run = mod.subprocess.run

            def fake_run(cmd, capture_output, text):
                commands.append(cmd)
                return Result()

            try:
                mod.subprocess.run = fake_run
                total_new = mod._run_emit(["claude-memory", "codex-memory"], vault)
            finally:
                mod.subprocess.run = original_run

            expected_script = str(REPO_ROOT / "tools" / "memory-deep-crawler.py")
            self.assertEqual(total_new, 4)
            self.assertEqual(
                commands,
                [
                    [
                        mod.sys.executable,
                        expected_script,
                        "--vault-dir",
                        str(vault),
                        "--section",
                        "claude-memory",
                    ],
                    [
                        mod.sys.executable,
                        expected_script,
                        "--vault-dir",
                        str(vault),
                        "--section",
                        "codex-memory",
                    ],
                ],
            )


class ObsidianVaultSyncToolsApiTest(unittest.TestCase):
    def test_tools_api_section_sources_resolve_to_tools_glob(self) -> None:
        mod = load_module()
        sources = mod._section_sources("tools-api")
        self.assertEqual(len(sources), 1)
        self.assertTrue(sources[0].endswith("/tools/*.py"))

    def test_tools_api_is_routed_through_deep_crawler(self) -> None:
        mod = load_module()
        self.assertIn("tools-api", mod.DEEP_CRAWLER_SECTIONS)
        cmd = mod._section_command("tools-api", Path("/tmp/test-vault"))
        self.assertEqual(Path(cmd[1]).name, "memory-deep-crawler.py")
        self.assertEqual(cmd[-2:], ["--section", "tools-api"])
        self.assertIn("/tmp/test-vault", cmd)

    def test_tools_api_marked_stale_when_tool_source_newer_than_stamp(self) -> None:
        mod = load_module()
        original_sources = dict(mod.SECTION_SOURCES)
        original_tools_dir = mod.TOOLS_DIR
        try:
            with tempfile.TemporaryDirectory(prefix="ovs-tools-api-") as tmp:
                root = Path(tmp)
                vault = root / "vault"
                vault.mkdir()
                tools_dir = root / "tools"
                tools_dir.mkdir()
                (tools_dir / "fresh-tool.py").write_text(
                    '"""docstring"""\n', encoding="utf-8"
                )
                (vault / ".last_sync.json").write_text(
                    json.dumps({"generated": "2026-05-01T00:00Z"}),
                    encoding="utf-8",
                )

                mod.SECTION_SOURCES = {"tools-api": []}
                mod.TOOLS_DIR = tools_dir

                stale = mod._stale_sections(vault, force=False)

                self.assertEqual(stale, ["tools-api"])
        finally:
            mod.SECTION_SOURCES = original_sources
            mod.TOOLS_DIR = original_tools_dir


class ObsidianVaultSyncRefreshRoutingTest(unittest.TestCase):
    def test_run_emit_never_dispatches_removed_engagement_verdicts_section(self) -> None:
        mod = load_module()
        vault = Path("/tmp/test-vault")

        with tempfile.TemporaryDirectory(prefix="ovs-routing-") as tmp:
            root = Path(tmp)
            audits_root = root / "audits"
            workspace = audits_root / "demo"
            held_dir = workspace / "submissions" / "held"
            held_dir.mkdir(parents=True)
            (held_dir / "HOLD_NOTE_001.md").write_text("# held\n", encoding="utf-8")

            (root / "tools").mkdir()
            (root / "tools" / "fresh-tool.py").write_text(
                '"""docstring"""\n', encoding="utf-8"
            )

            vault_local = root / "vault"
            vault_local.mkdir()
            (vault_local / ".last_sync.json").write_text(
                json.dumps({"generated": "2026-05-01T00:00Z"}),
                encoding="utf-8",
            )

            original_sources = dict(mod.SECTION_SOURCES)
            original_tools_dir = mod.TOOLS_DIR
            try:
                mod.SECTION_SOURCES = {"tools-api": []}
                mod.TOOLS_DIR = root / "tools"
                stale = mod._stale_sections(vault_local, force=False)
            finally:
                mod.SECTION_SOURCES = original_sources
                mod.TOOLS_DIR = original_tools_dir

        self.assertEqual(stale, ["tools-api"])

        class Result:
            returncode = 0
            stdout = "Deep crawler complete:\n  New/updated notes: 1\n"
            stderr = ""

        with mock.patch.object(mod.subprocess, "run", return_value=Result()) as run_mock:
            mod._run_emit(stale, vault)
            commands = [call.args[0] for call in run_mock.call_args_list]

        self.assertEqual(len(commands), 1)
        self.assertEqual(Path(commands[0][1]).name, "memory-deep-crawler.py")
        self.assertNotIn("engagement-verdicts", commands[0])


class ObsidianVaultSyncW63DeepCrawlerSectionsTest(unittest.TestCase):
    """W6-3 / Gap G1: the 5 previously-orphan deep-crawler sections."""

    W63_SECTIONS = ("routines", "commits", "prs", "make-targets", "errors")

    def test_five_sections_registered_in_section_sources(self) -> None:
        mod = load_module()
        for section in self.W63_SECTIONS:
            self.assertIn(
                section,
                mod.SECTION_SOURCES,
                f"{section} must be in SECTION_SOURCES",
            )

    def test_five_sections_registered_in_deep_crawler_sections(self) -> None:
        mod = load_module()
        for section in self.W63_SECTIONS:
            self.assertIn(
                section,
                mod.DEEP_CRAWLER_SECTIONS,
                f"{section} must be routed through memory-deep-crawler.py",
            )

    def test_five_sections_route_to_deep_crawler(self) -> None:
        mod = load_module()
        for section in self.W63_SECTIONS:
            cmd = mod._section_command(section, Path("/tmp/test-vault"))
            self.assertEqual(Path(cmd[1]).name, "memory-deep-crawler.py")
            self.assertEqual(cmd[-2:], ["--section", section])

    def test_git_backed_sections_are_commits_and_prs(self) -> None:
        mod = load_module()
        self.assertEqual(mod.GIT_BACKED_SECTIONS, {"commits", "prs"})

    def test_fast_path_does_not_mark_git_sections_stale_when_fresh(self) -> None:
        """Default sync must NOT flag commits/prs stale if recently refreshed.

        This is the behavioral guarantee that keeps `make docs-check` fast -
        no git/gh shell-out on a default run within the staleness window.
        """
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="ovs-w63-fast-") as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            # Both git-backed sections refreshed "now" - inside the window.
            now_iso = mod._now()
            (vault / ".last_sync.json").write_text(
                json.dumps(
                    {
                        "generated": "2026-05-01T00:00Z",
                        "git_section_refreshed": {
                            "commits": now_iso,
                            "prs": now_iso,
                        },
                    }
                ),
                encoding="utf-8",
            )
            original_sources = dict(mod.SECTION_SOURCES)
            try:
                mod.SECTION_SOURCES = {"commits": [], "prs": []}
                stale = mod._stale_sections(vault, force=False)
            finally:
                mod.SECTION_SOURCES = original_sources
            self.assertEqual(
                stale, [], "fresh git-backed sections must not be stale"
            )

    def test_git_sections_stale_once_past_window(self) -> None:
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="ovs-w63-stale-") as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            old_iso = (
                mod._dt.datetime.now(tz=mod._dt.timezone.utc)
                - mod._dt.timedelta(hours=mod.GIT_SECTION_STALE_HOURS + 1)
            ).strftime("%Y-%m-%dT%H:%MZ")
            (vault / ".last_sync.json").write_text(
                json.dumps(
                    {
                        "generated": "2026-05-01T00:00Z",
                        "git_section_refreshed": {
                            "commits": old_iso,
                            "prs": old_iso,
                        },
                    }
                ),
                encoding="utf-8",
            )
            original_sources = dict(mod.SECTION_SOURCES)
            try:
                mod.SECTION_SOURCES = {"commits": [], "prs": []}
                stale = mod._stale_sections(vault, force=False)
            finally:
                mod.SECTION_SOURCES = original_sources
            self.assertEqual(sorted(stale), ["commits", "prs"])

    def test_include_git_sections_flag_forces_refresh_even_when_fresh(self) -> None:
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="ovs-w63-optin-") as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            now_iso = mod._now()
            (vault / ".last_sync.json").write_text(
                json.dumps(
                    {
                        "generated": "2026-05-01T00:00Z",
                        "git_section_refreshed": {
                            "commits": now_iso,
                            "prs": now_iso,
                        },
                    }
                ),
                encoding="utf-8",
            )
            original_sources = dict(mod.SECTION_SOURCES)
            try:
                mod.SECTION_SOURCES = {"commits": [], "prs": []}
                stale = mod._stale_sections(
                    vault, force=False, include_git_sections=True
                )
            finally:
                mod.SECTION_SOURCES = original_sources
            self.assertEqual(sorted(stale), ["commits", "prs"])

    def test_git_section_never_refreshed_is_stale(self) -> None:
        mod = load_module()
        self.assertTrue(mod._git_section_is_stale("commits", {}))

    def test_make_targets_marked_stale_when_makefile_newer(self) -> None:
        """make-targets is filesystem-backed - cheap, refreshes every run."""
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="ovs-w63-mk-") as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            (vault / ".last_sync.json").write_text(
                json.dumps({"generated": "2026-05-01T00:00Z"}),
                encoding="utf-8",
            )
            original_sources = dict(mod.SECTION_SOURCES)
            try:
                # Makefile in the repo root is newer than the 2026-05-01 stamp.
                mod.SECTION_SOURCES = {"make-targets": ["Makefile"]}
                stale = mod._stale_sections(vault, force=False)
            finally:
                mod.SECTION_SOURCES = original_sources
            self.assertEqual(stale, ["make-targets"])


if __name__ == "__main__":
    unittest.main()
