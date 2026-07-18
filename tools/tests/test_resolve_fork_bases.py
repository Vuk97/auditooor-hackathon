# <!-- r36-rebuttal: lane-K1-keystone-fork-scope-in-emit registered in .auditooor/agent_pathspec.json -->
"""Tests for tools/resolve-fork-bases.py.

Covers:
  - parsing a ``## Fork Bases`` section in SCOPE.md (the polygon truth:
    bor=ethereum/go-ethereum@v1.16.8, cosmos-sdk=cosmos/cosmos-sdk@v0.50.11,
    cometbft=cometbft/cometbft@v0.38.23),
  - falling back to git history (newest ``Merge tag 'vX.Y.Z'``) when SCOPE.md
    has no row, using a marker-file upstream owner/repo,
  - an unresolvable fork is OMITTED + a WARN is emitted (never silently kept
    in the sidecar without a base, so the emitter keeps-all),
  - the sidecar write is idempotent (same bytes on re-run),
  - the CLI exits 0 and writes <ws>/.auditooor/fork_bases.json.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "resolve-fork-bases.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("_resolve_fork_bases_under_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_resolve_fork_bases_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_mod()


import os

# Isolated git env: ignore the user's global/system config + any global hooks
# (the sandbox has a global pre-commit hook that rejects commits without an
# .auditooor recall marker) so the test's throwaway repo can commit.
_GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "HOME": "/nonexistent-test-home",
}


def _git(args, cwd):
    subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args],
                   cwd=str(cwd), check=True, capture_output=True, text=True,
                   env=_GIT_ENV)


def _init_fork_with_merge(fork_dir: Path, merge_subject: str) -> None:
    fork_dir.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q"], fork_dir)
    _git(["config", "user.email", "t@t.t"], fork_dir)
    _git(["config", "user.name", "t"], fork_dir)
    (fork_dir / "a.go").write_text("package main\n", encoding="utf-8")
    _git(["add", "-A"], fork_dir)
    _git(["commit", "-q", "-m", "base"], fork_dir)
    # an empty merge-shaped commit whose subject names the upstream tag
    (fork_dir / "b.go").write_text("package main\n// edit\n", encoding="utf-8")
    _git(["add", "-A"], fork_dir)
    _git(["commit", "-q", "-m", merge_subject], fork_dir)


class TestResolveForkBases(unittest.TestCase):
    def test_scope_md_section_parsed(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "polygon"
            (ws / "src" / "bor").mkdir(parents=True)
            (ws / "src" / "cosmos-sdk").mkdir(parents=True)
            (ws / "src" / "cometbft").mkdir(parents=True)
            (ws / "SCOPE.md").write_text(
                "# Scope\n\nsome preamble\n\n"
                "## Fork Bases\n"
                "bor = ethereum/go-ethereum@v1.16.8\n"
                "cosmos-sdk = cosmos/cosmos-sdk@v0.50.11\n"
                "- cometbft = cometbft/cometbft@v0.38.23\n"
                "\n## Next Section\nnot a base row = nope/nope@bad ignored-context\n",
                encoding="utf-8",
            )
            parsed = _MOD.parse_scope_fork_bases(ws)
            self.assertEqual(parsed["bor"],
                             {"upstream_repo": "ethereum/go-ethereum",
                              "base_ref": "v1.16.8"})
            self.assertEqual(parsed["cosmos-sdk"]["base_ref"], "v0.50.11")
            self.assertEqual(parsed["cometbft"]["upstream_repo"],
                             "cometbft/cometbft")

            rows, warnings = _MOD.resolve_fork_bases(ws)
            by = {r["local_name"]: r for r in rows}
            self.assertEqual(set(by), {"bor", "cosmos-sdk", "cometbft"})
            self.assertEqual(by["bor"]["upstream_repo"], "ethereum/go-ethereum")
            self.assertEqual(by["bor"]["base_ref"], "v1.16.8")
            self.assertEqual(by["bor"]["resolved_via"], "scope.md")
            self.assertEqual(warnings, [])

    def test_git_history_fallback_with_marker(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "fork_ws"
            fork = ws / "src" / "bor"
            _init_fork_with_merge(fork, "Merge tag 'v1.16.8' into devel")
            # no SCOPE.md row; upstream owner/repo via marker file
            (ws / ".auditooor").mkdir(parents=True)
            (ws / ".auditooor" / "fork_target.json").write_text(
                json.dumps({"upstream": "https://github.com/ethereum/go-ethereum"}),
                encoding="utf-8",
            )
            ref = _MOD.discover_base_ref_from_git(fork)
            self.assertEqual(ref, "v1.16.8")
            rows, warnings = _MOD.resolve_fork_bases(ws)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["upstream_repo"], "ethereum/go-ethereum")
            self.assertEqual(rows[0]["base_ref"], "v1.16.8")
            self.assertEqual(rows[0]["resolved_via"], "git-history")
            self.assertEqual(warnings, [])

    def test_unresolvable_fork_omitted_with_warn(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            # a fork dir with no .git, no SCOPE.md row, no marker -> unresolved
            (ws / "src" / "mystery").mkdir(parents=True)
            rows, warnings = _MOD.resolve_fork_bases(ws)
            self.assertEqual(rows, [])
            self.assertEqual(len(warnings), 1)
            self.assertIn("mystery", warnings[0])
            self.assertIn("OMITTED", warnings[0])
            self.assertIn("MANUAL STEP", warnings[0])

    def test_idempotent_write(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "polygon"
            (ws / "src" / "bor").mkdir(parents=True)
            (ws / "SCOPE.md").write_text(
                "## Fork Bases\nbor = ethereum/go-ethereum@v1.16.8\n",
                encoding="utf-8",
            )
            out1, rows1, _ = _MOD.write_fork_bases(ws)
            b1 = out1.read_bytes()
            out2, rows2, _ = _MOD.write_fork_bases(ws)
            b2 = out2.read_bytes()
            self.assertEqual(b1, b2)
            self.assertEqual(rows1, rows2)

    def test_cli_writes_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "polygon"
            (ws / "src" / "bor").mkdir(parents=True)
            (ws / "SCOPE.md").write_text(
                "## Fork Bases\nbor = ethereum/go-ethereum@v1.16.8\n",
                encoding="utf-8",
            )
            rc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--json"],
                capture_output=True, text=True,
            )
            self.assertEqual(rc.returncode, 0, rc.stderr)
            fb = ws / ".auditooor" / "fork_bases.json"
            self.assertTrue(fb.is_file())
            data = json.loads(fb.read_text())
            self.assertEqual(data[0]["local_name"], "bor")
            self.assertEqual(data[0]["base_ref"], "v1.16.8")


if __name__ == "__main__":
    unittest.main()
