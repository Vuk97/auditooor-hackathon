"""Unit tests for tools/agent-pathspec-register.py.

Verifies that the helper produces a JSON shape that R36 + R55 hooks
can parse, and that the subcommands behave as documented.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "agent-pathspec-register.py"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AgentPathspecRegisterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(tempfile.mkdtemp(prefix="r55_register_"))
        self.pathspec = self.repo / ".auditooor" / "agent_pathspec.json"

    def tearDown(self) -> None:
        shutil.rmtree(self.repo, ignore_errors=True)

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        cmd = [sys.executable, str(TOOL),
               "--pathspec-file", str(self.pathspec), *args]
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def _load(self) -> dict:
        with self.pathspec.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def test_register_creates_file_when_missing(self) -> None:
        result = self._run(
            "register", "--lane", "lane-X",
            "--files", "tools/foo.py,tools/tests/test_foo.py",
            "--ttl", "3600",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.pathspec.exists())
        data = self._load()
        self.assertEqual(len(data["agents"]), 1)
        agent = data["agents"][0]
        self.assertEqual(agent["agent_id"], "lane-X")
        self.assertEqual(agent["files"], ["tools/foo.py", "tools/tests/test_foo.py"])
        self.assertIn("expires_at", agent)

    def test_register_replaces_existing_lane(self) -> None:
        self._run("register", "--lane", "lane-X",
                  "--files", "tools/foo.py", "--ttl", "3600")
        result = self._run("register", "--lane", "lane-X",
                           "--files", "tools/bar.py", "--ttl", "3600")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self._load()
        self.assertEqual(len(data["agents"]), 1)
        self.assertEqual(data["agents"][0]["files"], ["tools/bar.py"])

    def test_register_multiple_lanes_distinct(self) -> None:
        self._run("register", "--lane", "lane-A",
                  "--files", "tools/a.py", "--ttl", "3600")
        self._run("register", "--lane", "lane-B",
                  "--files", "tools/b.py", "--ttl", "3600")
        data = self._load()
        self.assertEqual(len(data["agents"]), 2)
        ids = {a["agent_id"] for a in data["agents"]}
        self.assertEqual(ids, {"lane-A", "lane-B"})

    def test_register_glob_pattern_rejected(self) -> None:
        result = self._run("register", "--lane", "lane-X",
                           "--files", "tools/*.py", "--ttl", "3600")
        self.assertEqual(result.returncode, 2)
        self.assertIn("ERROR", result.stderr)
        self.assertIn("glob", result.stderr.lower())
        self.assertFalse(self.pathspec.exists())

    def test_register_pathspec_alias_glob_rejected(self) -> None:
        result = self._run(
            "register",
            "--lane", "lane-X",
            "--pathspec", "tools/*.py",
            "--ttl", "3600",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("ERROR", result.stderr)
        self.assertFalse(self.pathspec.exists())

    def test_register_dedupes_and_strips(self) -> None:
        self._run("register", "--lane", "lane-X",
                  "--files", " tools/foo.py , tools/foo.py , tools/bar.py , ",
                  "--ttl", "3600")
        data = self._load()
        self.assertEqual(data["agents"][0]["files"],
                         ["tools/foo.py", "tools/bar.py"])

    def test_lane_brief_aliases_register_repeated_pathspecs(self) -> None:
        result = self._run(
            "register",
            "--agent-id", "lane-CAP010",
            "--pathspec", "tools/foo.py",
            "--pathspec", "tools/tests/test_foo.py",
            "--expires-in", "3600",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self._load()
        self.assertEqual(data["agents"][0]["agent_id"], "lane-CAP010")
        self.assertEqual(
            data["agents"][0]["files"],
            ["tools/foo.py", "tools/tests/test_foo.py"],
        )

    def test_bare_lane_brief_aliases_default_to_register(self) -> None:
        result = self._run(
            "--agent-id", "lane-CAP010",
            "--pathspec", "tools/foo.py",
            "--expires-in", "3600",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self._load()
        self.assertEqual(data["agents"][0]["agent_id"], "lane-CAP010")
        self.assertEqual(data["agents"][0]["files"], ["tools/foo.py"])

    def test_register_empty_files_rejected(self) -> None:
        result = self._run("register", "--lane", "lane-X",
                           "--files", "  ,  ,  ", "--ttl", "3600")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERROR", result.stderr)

    def test_unregister_drops_lane(self) -> None:
        self._run("register", "--lane", "lane-A",
                  "--files", "tools/a.py", "--ttl", "3600")
        self._run("register", "--lane", "lane-B",
                  "--files", "tools/b.py", "--ttl", "3600")
        result = self._run("unregister", "--lane", "lane-A")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self._load()
        self.assertEqual([a["agent_id"] for a in data["agents"]], ["lane-B"])

    def test_unregister_missing_lane_is_noop(self) -> None:
        self._run("register", "--lane", "lane-A",
                  "--files", "tools/a.py", "--ttl", "3600")
        result = self._run("unregister", "--lane", "lane-DOES-NOT-EXIST")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self._load()
        self.assertEqual(len(data["agents"]), 1)

    def test_refresh_updates_expiry(self) -> None:
        self._run("register", "--lane", "lane-X",
                  "--files", "tools/foo.py", "--ttl", "60")
        first = self._load()["agents"][0]["expires_at"]
        # Sleep briefly to ensure the new timestamp differs.
        import time
        time.sleep(1.1)
        result = self._run("refresh", "--lane", "lane-X", "--ttl", "7200")
        self.assertEqual(result.returncode, 0, result.stderr)
        second = self._load()["agents"][0]["expires_at"]
        self.assertNotEqual(first, second)

    def test_refresh_missing_lane_returns_nonzero(self) -> None:
        self._run("register", "--lane", "lane-X",
                  "--files", "tools/foo.py", "--ttl", "60")
        result = self._run("refresh", "--lane", "lane-DOES-NOT-EXIST")
        self.assertEqual(result.returncode, 1)

    def test_list_shows_registered_lanes(self) -> None:
        self._run("register", "--lane", "lane-X",
                  "--files", "tools/foo.py", "--ttl", "3600")
        self._run("register", "--lane", "lane-Y",
                  "--files", "tools/bar.py", "--ttl", "3600",
                  "--lane-title", "Y title")
        result = self._run("list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("lane-X", result.stdout)
        self.assertIn("lane-Y", result.stdout)
        self.assertIn("Y title", result.stdout)
        self.assertIn("live", result.stdout)

    def test_prune_drops_expired(self) -> None:
        # Register with TTL=60 then manually rewrite expires_at to the past.
        self._run("register", "--lane", "lane-X",
                  "--files", "tools/foo.py", "--ttl", "60")
        data = self._load()
        data["agents"][0]["expires_at"] = "2020-01-01T00:00:00Z"
        self.pathspec.write_text(json.dumps(data), encoding="utf-8")
        result = self._run("prune")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self._load()
        self.assertEqual(data["agents"], [])

    def test_concurrent_registers_all_survive(self) -> None:
        """Race regression test (NEG-A 2026-05-23): 10 concurrent register
        calls must produce 10 surviving entries. The legacy mtime-optimistic
        implementation silently lost ~15% of writers in this scenario - both
        writers saw matching mtime within the same sub-second tick, both
        atomic-renamed, and the second `exit 0` clobbered the first."""
        N = 10
        procs = []
        for i in range(N):
            cmd = [
                sys.executable, str(TOOL),
                "--pathspec-file", str(self.pathspec),
                "register",
                "--lane", f"lane-concurrent-{i}",
                "--files", f"tools/concurrent_{i}.py",
                "--ttl", "3600",
            ]
            procs.append(subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            ))
        for p in procs:
            _, err = p.communicate(timeout=60)
            self.assertEqual(
                p.returncode, 0,
                f"register exited {p.returncode}: {err.decode(errors='replace')}"
            )
        data = self._load()
        ids = sorted(a["agent_id"] for a in data["agents"])
        expected = sorted(f"lane-concurrent-{i}" for i in range(N))
        self.assertEqual(
            ids, expected,
            f"race lost some lanes: expected {expected}, got {ids}",
        )

    def test_concurrent_50_registers_all_survive(self) -> None:
        """Heavier stress variant of the race regression test - 50
        concurrent processes. If the lock has a flaw, the larger
        window makes it observable."""
        N = 50
        procs = []
        for i in range(N):
            cmd = [
                sys.executable, str(TOOL),
                "--pathspec-file", str(self.pathspec),
                "register",
                "--lane", f"lane-c50-{i}",
                "--files", f"tools/c50_{i}.py",
                "--ttl", "3600",
            ]
            procs.append(subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ))
        for p in procs:
            p.communicate(timeout=120)
            self.assertEqual(p.returncode, 0)
        data = self._load()
        self.assertEqual(len(data["agents"]), N)

    def test_concurrent_mixed_register_unregister(self) -> None:
        """Mixed concurrent register + unregister + refresh - all must
        leave the file structurally valid (no JSON corruption) and the
        final entries must be a consistent subset of the registrations."""
        # Pre-populate.
        for i in range(5):
            self._run(
                "register", "--lane", f"baseline-{i}",
                "--files", f"tools/baseline_{i}.py", "--ttl", "3600",
            )
        procs = []
        for i in range(8):
            cmd = [
                sys.executable, str(TOOL),
                "--pathspec-file", str(self.pathspec),
                "register",
                "--lane", f"new-{i}",
                "--files", f"tools/new_{i}.py",
                "--ttl", "3600",
            ]
            procs.append(subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ))
        for i in range(3):
            cmd = [
                sys.executable, str(TOOL),
                "--pathspec-file", str(self.pathspec),
                "unregister", "--lane", f"baseline-{i}",
            ]
            procs.append(subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ))
        for p in procs:
            p.communicate(timeout=60)
            self.assertEqual(p.returncode, 0)
        # File still parses, and the surviving agents are exactly the
        # registered set minus the unregistered baselines.
        data = self._load()
        ids = sorted(a["agent_id"] for a in data["agents"])
        expected = sorted(
            [f"baseline-{i}" for i in range(3, 5)]
            + [f"new-{i}" for i in range(8)]
        )
        self.assertEqual(ids, expected)

    def test_list_does_not_require_lock(self) -> None:
        """Read-only `list` must NOT block on the lock - that lets a
        long-running writer (or a stale lock) hang every `list` caller."""
        # Hold the lock from this process and verify list still succeeds.
        from importlib.util import spec_from_file_location, module_from_spec
        spec = spec_from_file_location("apr_module", str(TOOL))
        apr = module_from_spec(spec)
        spec.loader.exec_module(apr)
        self._run("register", "--lane", "lane-A",
                  "--files", "tools/a.py", "--ttl", "3600")
        with apr._exclusive_lock(self.pathspec):
            # While we hold the lock, `list` must still complete promptly.
            start = __import__("time").monotonic()
            result = self._run("list")
            elapsed = __import__("time").monotonic() - start
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(
            elapsed, 2.0,
            f"list took {elapsed:.2f}s with lock held - should skip lock"
        )
        self.assertIn("lane-A", result.stdout)

    def test_stale_lock_after_kill_recovers(self) -> None:
        """If a writer process is force-killed (SIGKILL) mid-lock, the
        next register must still succeed - fcntl.flock releases on
        process exit (POSIX guarantee), so there is no on-disk stale
        lock state to recover from. This test asserts the property
        holds: kill a writer, then the next register lands cleanly."""
        # Start a writer that grabs the lock and sleeps inside an
        # imported context manager. We use a small helper script.
        helper = self.repo / "hold_lock.py"
        helper.write_text(
            "import sys, time\n"
            "from importlib.util import spec_from_file_location, module_from_spec\n"
            f"spec = spec_from_file_location('apr', {str(TOOL)!r})\n"
            "apr = module_from_spec(spec); spec.loader.exec_module(apr)\n"
            "from pathlib import Path\n"
            f"path = Path({str(self.pathspec)!r})\n"
            "path.parent.mkdir(parents=True, exist_ok=True)\n"
            "with apr._exclusive_lock(path):\n"
            "    print('LOCKED', flush=True)\n"
            "    time.sleep(60)\n",
            encoding="utf-8",
        )
        # Spawn the writer.
        writer = subprocess.Popen(
            [sys.executable, str(helper)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            # Wait for the writer to print LOCKED (lock acquired).
            import time as _t
            deadline = _t.monotonic() + 5.0
            line = b""
            while _t.monotonic() < deadline:
                line = writer.stdout.readline()
                if b"LOCKED" in line:
                    break
            self.assertIn(b"LOCKED", line)
            # Force-kill the lock-holder.
            os.kill(writer.pid, signal.SIGKILL)
            writer.wait(timeout=5)
            # The next register must succeed promptly.
            t0 = _t.monotonic()
            result = self._run(
                "register", "--lane", "post-kill",
                "--files", "tools/x.py", "--ttl", "3600",
            )
            elapsed = _t.monotonic() - t0
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertLess(elapsed, 5.0,
                            f"post-kill register took {elapsed:.2f}s")
            data = self._load()
            self.assertIn("post-kill",
                          {a["agent_id"] for a in data["agents"]})
        finally:
            try:
                if writer.poll() is None:
                    writer.kill()
                    writer.wait(timeout=5)
            finally:
                if writer.stdout:
                    writer.stdout.close()
                if writer.stderr:
                    writer.stderr.close()

    def test_lock_timeout_exits_nonzero(self) -> None:
        """If a writer is hung holding the lock for longer than the
        timeout, a competing register must exit non-zero rather than
        hang the orchestrator indefinitely."""
        helper = self.repo / "hold_lock_long.py"
        helper.write_text(
            "import sys, time\n"
            "from importlib.util import spec_from_file_location, module_from_spec\n"
            f"spec = spec_from_file_location('apr', {str(TOOL)!r})\n"
            "apr = module_from_spec(spec); spec.loader.exec_module(apr)\n"
            "from pathlib import Path\n"
            f"path = Path({str(self.pathspec)!r})\n"
            "path.parent.mkdir(parents=True, exist_ok=True)\n"
            "with apr._exclusive_lock(path):\n"
            "    print('LOCKED', flush=True)\n"
            "    time.sleep(30)\n",
            encoding="utf-8",
        )
        writer = subprocess.Popen(
            [sys.executable, str(helper)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            import time as _t
            deadline = _t.monotonic() + 5.0
            line = b""
            while _t.monotonic() < deadline:
                line = writer.stdout.readline()
                if b"LOCKED" in line:
                    break
            self.assertIn(b"LOCKED", line)
            # Call the tool with a tiny timeout via env.
            env = os.environ.copy()
            cmd = [
                sys.executable, str(TOOL),
                "--pathspec-file", str(self.pathspec),
                "--lock-timeout", "2",
                "register", "--lane", "should-fail",
                "--files", "tools/x.py", "--ttl", "3600",
            ]
            t0 = _t.monotonic()
            result = subprocess.run(
                cmd, capture_output=True, text=True, env=env, timeout=15
            )
            elapsed = _t.monotonic() - t0
            self.assertNotEqual(
                result.returncode, 0,
                "expected non-zero exit when lock timeout expires"
            )
            # Should fail within ~2s + small overhead, not block 30s.
            self.assertLess(elapsed, 10.0,
                            f"lock-timeout register hung {elapsed:.2f}s")
        finally:
            try:
                writer.kill()
                writer.wait(timeout=5)
            finally:
                if writer.stdout:
                    writer.stdout.close()
                if writer.stderr:
                    writer.stderr.close()

    def test_schema_matches_hook_expectations(self) -> None:
        """Verify shape matches what R36/R55 hooks parse."""
        self._run("register", "--lane", "lane-X",
                  "--files", "tools/foo.py,tools/tests/test_foo.py",
                  "--ttl", "3600")
        data = self._load()
        self.assertIn("agents", data)
        self.assertIsInstance(data["agents"], list)
        agent = data["agents"][0]
        # R36/R55 read: agent["files"] (list), agent["agent_id"], agent["expires_at"]
        self.assertIn("agent_id", agent)
        self.assertIn("files", agent)
        self.assertIn("expires_at", agent)
        self.assertIsInstance(agent["files"], list)
        # expires_at must be parseable ISO-8601 UTC
        from datetime import datetime
        ts = agent["expires_at"]
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        parsed = datetime.fromisoformat(ts)
        self.assertIsNotNone(parsed)


if __name__ == "__main__":
    unittest.main()
