from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GC_TOOL = ROOT / "tools" / "agent-outputs-gc.py"
PRE_COMMIT = ROOT / "tools" / "git-hooks" / "pre-commit"
INSTALL_HOOKS = ROOT / "tools" / "install-hooks.sh"

_GIT = next(
    (
        c
        for c in ("/usr/bin/git", "/opt/homebrew/bin/git", shutil.which("git"))
        if c and Path(c).exists()
    ),
    "git",
)
_GIT_DIR = str(Path(_GIT).parent)


def _load_gc_module():
    spec = importlib.util.spec_from_file_location("agent_outputs_gc", GC_TOOL)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class AgentOutputsNamespaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agent_outputs_ns_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel: str, content: str = "{}\n") -> Path:
        path = self.tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_gc_only_targets_old_namespaced_outputs(self) -> None:
        gc = _load_gc_module()
        old = self._write("agent_outputs/codex/llm-preflight/20260401T000000Z_preflight.json")
        fresh = self._write("agent_outputs/codex/llm-preflight/20260524T000000Z_preflight.json")
        legacy = self._write("agent_outputs/llm_preflight_20260401T000000Z.json")
        malformed = self._write("agent_outputs/codex/llm-preflight/not_a_stamp.json")

        report = gc.build_report(
            self.tmp,
            "30d",
            True,
            datetime(2026, 5, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(
            report["candidates"][0]["path"],
            "agent_outputs/codex/llm-preflight/20260401T000000Z_preflight.json",
        )
        self.assertTrue(old.exists())
        self.assertTrue(fresh.exists())
        self.assertTrue(legacy.exists())
        self.assertTrue(malformed.exists())

    def test_gc_deletes_only_matching_old_namespaced_outputs(self) -> None:
        gc = _load_gc_module()
        old = self._write("agent_outputs/codex/llm-preflight/20260401T000000Z_preflight.json")
        fresh = self._write("agent_outputs/codex/llm-preflight/20260524T000000Z_preflight.json")
        legacy = self._write("agent_outputs/llm_preflight_20260401T000000Z.json")

        report = gc.build_report(
            self.tmp,
            "30d",
            False,
            datetime(2026, 5, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(report["deleted_count"], 1)
        self.assertFalse(old.exists())
        self.assertTrue(fresh.exists())
        self.assertTrue(legacy.exists())

    def test_pre_commit_rejects_new_top_level_agent_output(self) -> None:
        self._init_repo()
        self._write("agent_outputs/bad.json")
        self._git("add", "agent_outputs/bad.json")

        result = self._run_pre_commit()

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("new top-level agent_outputs files are not allowed", result.stderr)
        self.assertIn("agent_outputs/bad.json", result.stderr)

    def test_pre_commit_allows_namespaced_agent_output(self) -> None:
        self._init_repo()
        self._write("agent_outputs/codex/llm-preflight/20260524T102101Z_preflight.json")
        self._git("add", "agent_outputs/codex/llm-preflight/20260524T102101Z_preflight.json")

        result = self._run_pre_commit()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_install_hooks_template_contains_agent_output_guard(self) -> None:
        text = INSTALL_HOOKS.read_text(encoding="utf-8")
        self.assertIn("new top-level agent_outputs files are not allowed", text)
        self.assertIn("agent_outputs/<owner>/<lane>/<YYYYMMDDTHHMMSSZ>_<phase>.json", text)

    def _init_repo(self) -> None:
        self._git("init", "-q")
        self._git("config", "user.email", "test@example.com")
        self._git("config", "user.name", "Test")
        self._write("seed.txt", "seed\n")
        self._git("add", "seed.txt")
        self._git("commit", "-q", "-m", "seed")

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [_GIT, *args],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            check=False,
        )

    def _run_pre_commit(self) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PATH"] = _GIT_DIR + os.pathsep + env.get("PATH", "")
        env["AUDITOOOR_WS_ROOT"] = str(self.tmp)
        env["AUDITOOOR_MCP_REQUIRED"] = "0"
        return subprocess.run(
            ["bash", str(PRE_COMMIT)],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )


if __name__ == "__main__":
    unittest.main()
