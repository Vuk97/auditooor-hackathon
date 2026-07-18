#!/usr/bin/env python3
"""Tests for tools/forever-mode-status.py.

The status tool is read-only — it never writes pid/log/queue files. These
tests therefore stage a sandbox tmp tree mimicking /tmp/forever_logs/ and
the per-loop iter root dirs, then call `collect()` directly and inspect
the resulting Snapshot.

Live-process pids are tested with the current process (alive) and a known
unused pid (dead), which is platform-portable without forking.

Coverage:
  1. `collect()` against a fully-populated GREEN sandbox returns health=GREEN.
  2. One dead loop (stale pid) downgrades to YELLOW.
  3. Two dead loops downgrade to RED.
  4. Dead watchdog is RED regardless of loops.
  5. Stale queue (mtime > 1hr) downgrades to YELLOW (loops still alive).
  6. `render_human()` includes loop names + HEALTH banner; `--json` schema
     keys present.
  7. Missing pid file = treated as dead (no crash).
  8. `_latest_iter_dir` picks the iter_NNN with the freshest mtime, not the
     highest numeric suffix — the forever loops wrap (iter_060 → iter_001
     after outer-loop restart) so a numeric sort would falsely keep the
     stale previous-cycle dir. Non-matching directories are ignored.
"""
from __future__ import annotations

import json
import os
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "forever-mode-status.py"


def _load_module():
    """Load tools/forever-mode-status.py as a module under the name
    `forever_mode_status` (the hyphenated filename can't be imported
    directly).

    Register in sys.modules BEFORE exec so dataclasses can resolve the
    module's __module__ during class construction (Python 3.14 strict)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "forever_mode_status", str(SCRIPT)
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["forever_mode_status"] = mod
    spec.loader.exec_module(mod)
    return mod


fms = _load_module()


# A pid that is overwhelmingly unlikely to be in use. PID 0 is reserved on
# POSIX and `os.kill(0, 0)` signals the whole process group, so we use a
# large pid that isn't ours and verify it's dead.
def _find_dead_pid() -> int:
    for candidate in (999_999, 999_998, 999_997, 888_888):
        try:
            os.kill(candidate, 0)
        except ProcessLookupError:
            return candidate
        except PermissionError:
            continue
        except OSError:
            continue
    raise RuntimeError("could not find a dead pid for testing")


DEAD_PID = _find_dead_pid()
ALIVE_PID = os.getpid()


def _stage_sandbox(tmp: Path, *,
                   alive_loops: tuple[str, ...] = (
                       "overnight", "improvement", "next_roadmap",
                       "self_reflection", "dispatch_ready",
                   ),
                   watchdog_alive: bool = True,
                   queue_age_sec: float = 30.0,
                   ) -> tuple[Path, Path, dict[str, Path]]:
    """Build a fake forever-mode tree under `tmp`. The tool's `tmp_base`
    arg reroots all `/tmp/...` constants under `tmp` — so we mirror the
    real `/tmp/forever_logs/`, `/tmp/llm_loop_v2/`, etc. layout under `tmp`.
    Returns (log_dir, watchdog_pid_path, queue_paths)."""
    log_dir = tmp / "forever_logs"
    log_dir.mkdir()
    queue_dirs = {
        "auto_improvement_root": tmp / "auto_improvement_v2",
        "overnight_root": tmp / "llm_loop_v2",
        "next_roadmap_md": tmp / "next_roadmap_consultations.md",
        "self_reflection_md": tmp / "llm_self_reflections.md",
        "ready_to_dispatch_md": tmp / "ready_to_dispatch.md",
        "improvement_queue_md": tmp / "auto_improvement_v2" / "queue.md",
    }
    queue_dirs["auto_improvement_root"].mkdir()
    queue_dirs["overnight_root"].mkdir()

    # Iter dirs: overnight=iter_037, improvement=iter_010 + a non-matching one.
    (queue_dirs["overnight_root"] / "iter_035").mkdir()
    (queue_dirs["overnight_root"] / "iter_037").mkdir()
    (queue_dirs["overnight_root"] / "junk_dir").mkdir()
    (queue_dirs["auto_improvement_root"] / "iter_009").mkdir()
    (queue_dirs["auto_improvement_root"] / "iter_010").mkdir()

    # Per-loop pid + log files.
    loop_files = {
        "overnight": ("overnight.pid", "overnight.log"),
        "improvement": ("improvement.pid", "improvement.log"),
        "next_roadmap": ("next_roadmap.pid", "next_roadmap.log"),
        "self_reflection": ("self_reflection.pid", "self_reflection.log"),
        "dispatch_ready": ("dispatch_ready.pid", "dispatch_ready.log"),
    }
    for name, (pidfile, logfile) in loop_files.items():
        (log_dir / pidfile).write_text(
            f"{ALIVE_PID if name in alive_loops else DEAD_PID}\n"
        )
        (log_dir / logfile).write_text(f"[{name}] alive at fake-time\n")

    # Watchdog pid.
    wd_pid = tmp / "forever_watchdog.pid"
    wd_pid.write_text(f"{ALIVE_PID if watchdog_alive else DEAD_PID}\n")

    # Queue files.
    queue_dirs["next_roadmap_md"].write_text(
        "# Next-roadmap consultations\n\n"
        "## 2026-04-25T23:34Z — exhaustion check\n"
        "(consultation body)\n"
    )
    queue_dirs["self_reflection_md"].write_text(
        "# Self-reflections\n## 2026-04-25T23:32Z\n(body)\n"
    )
    queue_dirs["ready_to_dispatch_md"].write_text(
        "# Ready-to-dispatch\n## Iter 7 — title\n"
    )
    queue_dirs["improvement_queue_md"].write_text(
        "# Auto-improvement queue v2\n\n"
        "## Iter 1 — 2026-04-25T23:38Z\nGAP-CONFIRMED\n"
    )

    # Bump mtimes so queue staleness is controllable.
    fresh = time.time() - queue_age_sec
    for q_path in (
        queue_dirs["next_roadmap_md"],
        queue_dirs["self_reflection_md"],
        queue_dirs["ready_to_dispatch_md"],
        queue_dirs["improvement_queue_md"],
    ):
        os.utime(q_path, (fresh, fresh))

    return log_dir, wd_pid, queue_dirs


# ───────────────────────────────────────────────────────────────── tests ──


class TestCollect(unittest.TestCase):
    def test_green_when_all_alive_and_fresh(self):
        with TemporaryDirectory() as td:
            log_dir, wd_pid, _ = _stage_sandbox(Path(td))
            snap = fms.collect(log_dir, wd_pid, tmp_base=Path(td))
            self.assertEqual(snap.health, "GREEN", msg=snap.to_dict())
            self.assertTrue(snap.watchdog["alive"])
            for name, info in snap.loops.items():
                self.assertTrue(info["alive"], f"loop {name} should be alive")
            self.assertIn("auto_improvement", snap.queues)
            self.assertGreater(snap.queues["auto_improvement"]["size_bytes"], 0)

    def test_yellow_when_one_loop_dead(self):
        with TemporaryDirectory() as td:
            log_dir, wd_pid, _ = _stage_sandbox(
                Path(td), alive_loops=("improvement", "next_roadmap",
                                       "self_reflection", "dispatch_ready"),
            )
            snap = fms.collect(log_dir, wd_pid, tmp_base=Path(td))
            self.assertEqual(snap.health, "YELLOW")
            self.assertFalse(snap.loops["overnight"]["alive"])

    def test_red_when_two_loops_dead(self):
        with TemporaryDirectory() as td:
            log_dir, wd_pid, _ = _stage_sandbox(
                Path(td),
                alive_loops=("next_roadmap", "self_reflection",
                             "dispatch_ready"),
            )
            snap = fms.collect(log_dir, wd_pid, tmp_base=Path(td))
            self.assertEqual(snap.health, "RED")

    def test_red_when_watchdog_dead(self):
        with TemporaryDirectory() as td:
            log_dir, wd_pid, _ = _stage_sandbox(
                Path(td), watchdog_alive=False,
            )
            snap = fms.collect(log_dir, wd_pid, tmp_base=Path(td))
            self.assertEqual(snap.health, "RED")
            self.assertFalse(snap.watchdog["alive"])

    def test_yellow_when_queue_stale(self):
        # Queue mtime bumped to > 1hr in the past — loops still alive.
        stale = 60 * 60 + 120  # 1h2m
        with TemporaryDirectory() as td:
            log_dir, wd_pid, _ = _stage_sandbox(Path(td), queue_age_sec=stale)
            snap = fms.collect(log_dir, wd_pid, tmp_base=Path(td))
            self.assertEqual(snap.health, "YELLOW", msg=snap.to_dict())

    def test_missing_pid_file_treated_as_dead(self):
        with TemporaryDirectory() as td:
            log_dir, wd_pid, _ = _stage_sandbox(Path(td))
            (log_dir / "overnight.pid").unlink()
            snap = fms.collect(log_dir, wd_pid, tmp_base=Path(td))
            self.assertFalse(snap.loops["overnight"]["alive"])
            self.assertEqual(snap.loops["overnight"]["pid"], 0)
            # Single missing pid → YELLOW (one loop dead).
            self.assertEqual(snap.health, "YELLOW")

    def test_latest_iter_picks_freshest_mtime_single_cycle(self):
        # Within a single cycle the highest-numbered dir IS the freshest, so
        # mtime sort and numeric sort agree.
        with TemporaryDirectory() as td:
            tmp = Path(td)
            root = tmp / "iter_root"
            root.mkdir()
            now = time.time()
            for idx, name in enumerate(("iter_001", "iter_009", "iter_037")):
                d = root / name
                d.mkdir()
                # Stagger mtimes so iter_037 is freshest.
                os.utime(d, (now - (100 - idx * 10), now - (100 - idx * 10)))
            (root / "junk").mkdir()  # ignored
            latest = fms._latest_iter_dir(root)
            self.assertIsNotNone(latest)
            self.assertEqual(latest.name, "iter_037")

    def test_latest_iter_picks_freshest_mtime_after_outer_loop_restart(self):
        # Multi-cycle scenario: inner loop ran to iter_060, outer wrapper
        # slept and restarted, fresh inner run is now at iter_034. The
        # freshest dir is iter_034 even though iter_060 has a higher number.
        with TemporaryDirectory() as td:
            tmp = Path(td)
            root = tmp / "iter_root"
            root.mkdir()
            now = time.time()
            old_cycle_start = now - (60 * 60 + 38 * 60)  # ~1h38m ago
            new_cycle_start = now - (10 * 60)            # ~10m ago
            # First cycle iter_001..iter_060, all old.
            for n in range(1, 61):
                d = root / f"iter_{n:03d}"
                d.mkdir()
                ts = old_cycle_start + n  # monotonically increasing within cycle
                os.utime(d, (ts, ts))
            # Second cycle iter_001..iter_034, all fresh — same names as before
            # would clash, so only the *new* iters that don't already exist.
            # In practice the outer wrapper rms or recreates the root; here we
            # simulate by re-stamping iter_001..iter_034 with fresh mtimes.
            for n in range(1, 35):
                d = root / f"iter_{n:03d}"
                ts = new_cycle_start + n
                os.utime(d, (ts, ts))
            latest = fms._latest_iter_dir(root)
            self.assertIsNotNone(latest)
            # iter_034 from the new cycle should win over iter_060 from the
            # old cycle, even though 60 > 34, because iter_034's mtime is
            # ~1h28m newer.
            self.assertEqual(
                latest.name, "iter_034",
                msg=f"expected iter_034 (freshest mtime), got {latest.name}",
            )

    def test_render_and_json_shape(self):
        with TemporaryDirectory() as td:
            log_dir, wd_pid, _ = _stage_sandbox(Path(td))
            snap = fms.collect(log_dir, wd_pid, tmp_base=Path(td))
            human = fms.render_human(snap)
            self.assertIn("forever-mode status", human)
            self.assertIn("HEALTH:", human)
            for name in ("overnight", "improvement", "next_roadmap",
                         "self_reflection", "dispatch_ready"):
                self.assertIn(name, human)

            # JSON schema keys.
            d = snap.to_dict()
            self.assertEqual(set(d.keys()),
                             {"watchdog", "loops", "queues", "health",
                              "last_check"})
            self.assertEqual(set(d["loops"].keys()),
                             {"overnight", "improvement", "next_roadmap",
                              "self_reflection", "dispatch_ready"})
            self.assertEqual(
                set(d["queues"].keys()),
                {"auto_improvement", "next_roadmap_consultations",
                 "ready_to_dispatch"},
            )
            for loop_info in d["loops"].values():
                self.assertEqual(
                    set(loop_info.keys()) >= {"alive", "pid", "last_iter_dir",
                                              "last_iter_age_sec"},
                    True,
                )
            # JSON serialisability.
            blob = json.dumps(d)
            self.assertTrue(blob)


class TestProcessHelpers(unittest.TestCase):
    def test_alive_pid(self):
        self.assertTrue(fms._process_alive(ALIVE_PID))

    def test_dead_pid(self):
        self.assertFalse(fms._process_alive(DEAD_PID))

    def test_zero_and_none(self):
        self.assertFalse(fms._process_alive(None))
        self.assertFalse(fms._process_alive(0))
        self.assertFalse(fms._process_alive(-1))

    def test_read_pid_handles_garbage(self):
        with TemporaryDirectory() as td:
            p = Path(td) / "x.pid"
            p.write_text("nope\n")
            self.assertIsNone(fms._read_pid(p))
            p.write_text("")
            self.assertIsNone(fms._read_pid(p))
            p.write_text("12345\n")
            self.assertEqual(fms._read_pid(p), 12345)


if __name__ == "__main__":
    unittest.main()
