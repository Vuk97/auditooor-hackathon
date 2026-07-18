#!/usr/bin/env python3
"""Test audit-heavy-lock: a live lock refuses a 2nd concurrent heavy run; a stale
(dead-pid or expired) lock is reclaimed. Prevents the OOM-by-stacking machine kill."""
import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "audit-heavy-lock.py"
_spec = importlib.util.spec_from_file_location("ahl", _MOD)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)


class TestHeavyLock(unittest.TestCase):
    def test_is_live_fresh_pid(self):
        now = 1000.0
        self.assertTrue(_m._is_live({"pid": os.getpid(), "ts": now - 10}, 1200, now))

    def test_is_live_dead_pid(self):
        now = 1000.0
        self.assertFalse(_m._is_live({"pid": 999999999, "ts": now - 10}, 1200, now))

    def test_is_live_expired_ttl(self):
        now = 1000.0
        # our own pid but the lock is older than the TTL -> presumed stuck/dead
        self.assertFalse(_m._is_live({"pid": os.getpid(), "ts": now - 5000}, 1200, now))

    def test_run_refuses_when_live_lock_held(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        now = 2000.0
        lp = _m._lock_path(ws, "audit-complete")
        lp.write_text(json.dumps({"pid": os.getpid(), "ts": now - 5,
                                  "target": "audit-complete", "ttl": 1200}))
        rc = _m.cmd_run(ws, "audit-complete", ["true"], 1200, now)
        self.assertEqual(rc, 3)  # refused, did not run

    def test_run_reclaims_stale_lock_and_runs(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        now = 2000.0
        lp = _m._lock_path(ws, "audit-complete")
        lp.write_text(json.dumps({"pid": 999999999, "ts": now - 10,
                                  "target": "audit-complete", "ttl": 1200}))
        rc = _m.cmd_run(ws, "audit-complete", ["true"], 1200, now)
        self.assertEqual(rc, 0)          # stale reclaimed, cmd ran
        self.assertFalse(lp.exists())    # released after run


if __name__ == "__main__":
    unittest.main()
