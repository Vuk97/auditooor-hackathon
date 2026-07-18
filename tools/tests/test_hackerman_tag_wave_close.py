"""Tests for ``tools/hackerman-tag-wave-close.py`` (PR #726 Wave-1).

The tag-close tool reads HEAD of an arbitrary repo and creates an annotated
git tag with an embedded corpus snapshot + Wave-2 readiness verdict. To
keep tests hermetic each test creates a throwaway git repo in tempdir,
seeds a stub corpus-stats tool that prints a pinned JSON envelope, and
drives the CLI / module-level helpers directly.

Coverage (>=8 cases):

1. ``WAVE_NAME_RE`` accepts ``wave-1-final`` / ``wave-2-foo-bar``; rejects
   ``v1.0`` / empty / mixed-case.
2. ``wave2_readiness`` returns READY for a healthy snapshot, NOT-READY for
   total_records==0, UNKNOWN for skipped snapshot.
3. ``build_annotation`` includes corpus stats + Wave-2 verdict line.
4. CLI creates an annotated tag on a fresh repo (status=created, rc=0).
5. The created tag is ANNOTATED (``git cat-file -t`` returns ``tag``, not
   ``commit``); body contains shape_counts and total_records.
6. Idempotent re-run: second invocation on the same HEAD returns
   ``already-present-same-sha`` (rc=0); does NOT overwrite.
7. Already-exists-different-sha: tag pre-pointed elsewhere, run refuses
   with rc=2; ``--force`` overrides.
8. Skip-corpus path: ``--skip-corpus`` produces a tag whose annotation
   says ``status: skipped`` and verdict UNKNOWN.
9. Stub stats tool returning rc!=0 makes the CLI exit 4 (refuse to create
   half-empty tag).
10. ``--dry-run`` does NOT create the tag (no ref in ``refs/tags/``).
11. Invalid wave name (``v1.0``) rejected with rc=2.
12. ``--json`` round-trip emits the documented envelope keys.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-tag-wave-close.py"

# The repo's git wrapper (~/.auditooor/bin/git) requires a fresh MCP recall
# token before committing. In tests we bypass it by invoking the real git
# binary directly (mirrors the tool's own ``_git_binary`` resolution).
_REAL_GIT = (
    os.environ.get("AUDITOOOR_HACKERMAN_TAG_GIT")
    or os.environ.get("AUDITOOOR_REAL_GIT")
    or ("/usr/bin/git" if os.path.exists("/usr/bin/git") else "git")
)


def _child_env() -> dict[str, str]:
    """Env for child CLI subprocesses - force the tool to use the real git."""
    env = dict(os.environ)
    env["AUDITOOOR_HACKERMAN_TAG_GIT"] = _REAL_GIT
    return env


def _load_tool() -> Any:
    name = "_hackerman_tag_wave_close_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _run_git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_REAL_GIT, *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=True,
    )


def _seed_repo(repo: Path) -> str:
    """Create a tiny git repo with a single commit. Returns the head SHA."""
    repo.mkdir(parents=True, exist_ok=True)
    _run_git(repo, "init", "-q", "-b", "main")
    _run_git(repo, "config", "user.email", "test@example.invalid")
    _run_git(repo, "config", "user.name", "Test User")
    _run_git(repo, "commit", "--allow-empty", "-q", "-m", "seed")
    proc = _run_git(repo, "rev-parse", "HEAD")
    return proc.stdout.strip()


def _seed_second_commit(repo: Path) -> str:
    _run_git(repo, "commit", "--allow-empty", "-q", "-m", "second")
    proc = _run_git(repo, "rev-parse", "HEAD")
    return proc.stdout.strip()


def _write_stub_stats(path: Path, payload: dict[str, Any], rc: int = 0) -> None:
    """Write a stub script that mimics tools/hackerman-corpus-stats.py --json."""
    blob = json.dumps(payload, sort_keys=True)
    # Use repr to safely embed JSON into Python source.
    src = (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"sys.stdout.write({blob!r})\n"
        f"sys.exit({int(rc)})\n"
    )
    path.write_text(src, encoding="utf-8")
    path.chmod(0o755)


def _stub_payload(total: int = 5, v1: int = 4, q: int = 1) -> dict[str, Any]:
    return {
        "schema": "auditooor.hackerman_corpus_stats.v1",
        "stats": {
            "schema": "auditooor.hackerman_corpus_stats.v1",
            "tags_dir": "/tmp/fake",
            "total_records": total,
            "hackerman_v1_total": v1,
            "shape_counts": {"record.yaml": v1, "flat.yaml": total - v1},
            "hackerman_v1_by_shape": {"record.yaml": v1},
            "subtrees": [
                {"subtree": "sample_subtree", "records": total - q},
                {"subtree": "_QUARANTINE_FOO", "records": q},
            ],
            "quarantine": {"total": q, "per_reason": {"foo": q}},
        },
    }


class TestWaveNameValidation(unittest.TestCase):
    def test_wave_name_re_accepts_and_rejects(self) -> None:
        mod = _load_tool()
        good = ["wave-1-final", "wave-2-foo-bar", "wave-10-x", "wave-1"]
        bad = ["v1.0", "", "Wave-1-Final", "wave1final", "wave--1"]
        for w in good:
            self.assertIsNotNone(mod.WAVE_NAME_RE.match(w), w)
        for w in bad:
            self.assertIsNone(mod.WAVE_NAME_RE.match(w), w)


class TestWave2Readiness(unittest.TestCase):
    def test_ready_path(self) -> None:
        mod = _load_tool()
        snap = {
            "status": "ok",
            "total_records": 100,
            "hackerman_v1_total": 50,
            "non_quarantine_subtree_count": 3,
        }
        v, r = mod.wave2_readiness(snap)
        self.assertEqual(v, "READY")
        self.assertIn("total_records=100", r)

    def test_not_ready_when_empty(self) -> None:
        mod = _load_tool()
        v, _ = mod.wave2_readiness({"status": "ok", "total_records": 0, "hackerman_v1_total": 0})
        self.assertEqual(v, "NOT-READY")

    def test_unknown_when_skipped(self) -> None:
        mod = _load_tool()
        v, r = mod.wave2_readiness({"status": "skipped", "reason": "test"})
        self.assertEqual(v, "UNKNOWN")
        self.assertIn("skipped", r)


class TestBuildAnnotation(unittest.TestCase):
    def test_annotation_body_includes_stats_and_verdict(self) -> None:
        mod = _load_tool()
        snap = {
            "status": "ok",
            "total_records": 7,
            "hackerman_v1_total": 4,
            "quarantine_total": 1,
            "non_quarantine_subtree_count": 2,
            "shape_counts": {"record.yaml": 4, "flat.yaml": 3},
        }
        body = mod.build_annotation(
            "wave-1-final",
            "wave-1-hackerman-capability-lift",
            "deadbeef" * 5,
            snap,
            generated_at="2026-05-16T00:00:00Z",
            pr_ref="PR #726",
        )
        self.assertIn("wave-1-final", body)
        self.assertIn("total_records: 7", body)
        self.assertIn("hackerman_v1_total: 4", body)
        self.assertIn("quarantine_total: 1", body)
        self.assertIn("Wave-2 readiness", body)
        self.assertIn("verdict: READY", body)
        self.assertIn("PR #726", body)
        self.assertIn("auditooor.hackerman_tag_wave_close.v1", body)


class TestEndToEndCLI(unittest.TestCase):
    def _common_run(self, *extra: str, stats_payload: dict[str, Any] | None = None,
                     stats_rc: int = 0) -> tuple[int, str, str, Path, str]:
        td = tempfile.mkdtemp(prefix="tag_wave_close_test_")
        repo = Path(td) / "repo"
        head = _seed_repo(repo)
        stub = Path(td) / "stub_stats.py"
        _write_stub_stats(stub, stats_payload or _stub_payload(), rc=stats_rc)
        cmd = [
            sys.executable,
            str(TOOL_PATH),
            "--repo",
            str(repo),
            "--stats-tool",
            str(stub),
            "--generated-at",
            "2026-05-16T00:00:00Z",
            *extra,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=_child_env())
        return proc.returncode, proc.stdout, proc.stderr, repo, head

    def test_cli_creates_annotated_tag(self) -> None:
        rc, stdout, stderr, repo, head = self._common_run("--wave-name", "wave-1-final")
        self.assertEqual(rc, 0, f"stdout={stdout!r} stderr={stderr!r}")
        # Tag exists and points at head.
        proc = subprocess.run(
            [_REAL_GIT, "rev-parse", "refs/tags/wave-1-final^{commit}"],
            cwd=str(repo), capture_output=True, text=True, check=True,
        )
        self.assertEqual(proc.stdout.strip(), head)
        # Tag is annotated (not lightweight).
        proc = subprocess.run(
            [_REAL_GIT, "cat-file", "-t", "refs/tags/wave-1-final"],
            cwd=str(repo), capture_output=True, text=True, check=True,
        )
        self.assertEqual(proc.stdout.strip(), "tag")
        # Tag annotation body contains corpus stats keywords. ``git tag -l
        # -n100`` strips lines beginning with ``#`` (markdown-header convention),
        # so we read the raw tag object via ``cat-file tag`` to verify the
        # full annotation body landed including the ``## Wave-2 readiness``
        # heading.
        proc = subprocess.run(
            [_REAL_GIT, "cat-file", "tag", "wave-1-final"],
            cwd=str(repo), capture_output=True, text=True, check=True,
        )
        msg = proc.stdout
        self.assertIn("total_records", msg)
        self.assertIn("hackerman_v1_total", msg)
        self.assertIn("Wave-2 readiness", msg)
        self.assertIn("verdict: READY", msg)

    def test_cli_idempotent_same_sha(self) -> None:
        rc1, _, _, repo, _ = self._common_run("--wave-name", "wave-1-final")
        self.assertEqual(rc1, 0)
        # Second run on same repo should be a no-op.
        stub = next((Path(repo).parent / f for f in os.listdir(Path(repo).parent) if f.startswith("stub")), None)
        self.assertIsNotNone(stub)
        proc2 = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--repo",
                str(repo),
                "--stats-tool",
                str(stub),
                "--generated-at",
                "2026-05-16T00:00:00Z",
                "--wave-name",
                "wave-1-final",
                "--json",
            ],
            capture_output=True, text=True, check=False, env=_child_env(),
        )
        self.assertEqual(proc2.returncode, 0, f"stdout={proc2.stdout!r}")
        env = json.loads(proc2.stdout)
        self.assertEqual(env["tag_result"]["status"], "already-present-same-sha")

    def test_cli_refuses_different_sha_without_force(self) -> None:
        td = tempfile.mkdtemp(prefix="tag_wave_close_diff_")
        repo = Path(td) / "repo"
        head1 = _seed_repo(repo)
        # Pre-create the tag at head1.
        _run_git(repo, "tag", "-a", "wave-1-final", "-m", "pre-existing", head1)
        # Advance HEAD.
        head2 = _seed_second_commit(repo)
        self.assertNotEqual(head1, head2)
        stub = Path(td) / "stub_stats.py"
        _write_stub_stats(stub, _stub_payload())
        # Without --force: refuse.
        proc = subprocess.run(
            [
                sys.executable, str(TOOL_PATH),
                "--repo", str(repo),
                "--stats-tool", str(stub),
                "--generated-at", "2026-05-16T00:00:00Z",
                "--wave-name", "wave-1-final",
                "--json",
            ],
            capture_output=True, text=True, check=False, env=_child_env(),
        )
        self.assertEqual(proc.returncode, 2, f"stdout={proc.stdout!r}")
        env = json.loads(proc.stdout)
        self.assertEqual(env["tag_result"]["status"], "already-present-different-sha")
        # Tag still points at head1.
        p2 = subprocess.run(
            [_REAL_GIT, "rev-parse", "refs/tags/wave-1-final^{commit}"],
            cwd=str(repo), capture_output=True, text=True, check=True,
        )
        self.assertEqual(p2.stdout.strip(), head1)
        # With --force: overwrite to head2.
        proc2 = subprocess.run(
            [
                sys.executable, str(TOOL_PATH),
                "--repo", str(repo),
                "--stats-tool", str(stub),
                "--generated-at", "2026-05-16T00:00:00Z",
                "--wave-name", "wave-1-final",
                "--force",
            ],
            capture_output=True, text=True, check=False, env=_child_env(),
        )
        self.assertEqual(proc2.returncode, 0, f"stderr={proc2.stderr!r}")
        p3 = subprocess.run(
            [_REAL_GIT, "rev-parse", "refs/tags/wave-1-final^{commit}"],
            cwd=str(repo), capture_output=True, text=True, check=True,
        )
        self.assertEqual(p3.stdout.strip(), head2)

    def test_skip_corpus_marks_unknown(self) -> None:
        td = tempfile.mkdtemp(prefix="tag_wave_close_skip_")
        repo = Path(td) / "repo"
        _seed_repo(repo)
        proc = subprocess.run(
            [
                sys.executable, str(TOOL_PATH),
                "--repo", str(repo),
                "--skip-corpus",
                "--generated-at", "2026-05-16T00:00:00Z",
                "--wave-name", "wave-1-final",
                "--json",
            ],
            capture_output=True, text=True, check=False, env=_child_env(),
        )
        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr!r}")
        env = json.loads(proc.stdout)
        self.assertEqual(env["wave2_readiness"]["verdict"], "UNKNOWN")
        self.assertEqual(env["corpus_snapshot"]["status"], "skipped")
        self.assertIn("status: skipped", env["annotation_body"])

    def test_stats_tool_rc_nonzero_refuses_tag(self) -> None:
        rc, stdout, stderr, repo, _ = self._common_run(
            "--wave-name", "wave-1-final",
            stats_payload={"stats": {}}, stats_rc=2,
        )
        self.assertEqual(rc, 4, f"stdout={stdout!r} stderr={stderr!r}")
        # Tag must NOT have been created.
        proc = subprocess.run(
            [_REAL_GIT, "tag", "-l", "wave-1-final"],
            cwd=str(repo), capture_output=True, text=True, check=True,
        )
        self.assertEqual(proc.stdout.strip(), "")

    def test_dry_run_does_not_create_tag(self) -> None:
        rc, stdout, _, repo, _ = self._common_run("--wave-name", "wave-1-final", "--dry-run", "--json")
        self.assertEqual(rc, 0)
        env = json.loads(stdout)
        self.assertEqual(env["tag_result"]["status"], "dry-run")
        proc = subprocess.run(
            [_REAL_GIT, "tag", "-l", "wave-1-final"],
            cwd=str(repo), capture_output=True, text=True, check=True,
        )
        self.assertEqual(proc.stdout.strip(), "")

    def test_invalid_wave_name_rejected(self) -> None:
        td = tempfile.mkdtemp(prefix="tag_wave_close_bad_")
        repo = Path(td) / "repo"
        _seed_repo(repo)
        proc = subprocess.run(
            [
                sys.executable, str(TOOL_PATH),
                "--repo", str(repo),
                "--skip-corpus",
                "--wave-name", "v1.0",
            ],
            capture_output=True, text=True, check=False, env=_child_env(),
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("invalid wave name", proc.stderr)

    def test_json_envelope_keys(self) -> None:
        rc, stdout, _, _, _ = self._common_run("--wave-name", "wave-1-final", "--json")
        self.assertEqual(rc, 0)
        env = json.loads(stdout)
        for key in (
            "schema", "generated_at", "wave", "branch", "head_sha",
            "tag_result", "wave2_readiness", "annotation_body", "corpus_snapshot",
        ):
            self.assertIn(key, env)
        self.assertEqual(env["schema"], "auditooor.hackerman_tag_wave_close.v1")


if __name__ == "__main__":
    unittest.main()
