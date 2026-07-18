"""Tests for tools/audit-run-guard.sh - the per-workspace concurrency guard that
stops a recurring loop tick from launching a 2nd `make audit` while one is active
(the orphaned-scan-orchestrator pileup fix)."""
import os
import subprocess
from pathlib import Path

_GUARD = Path(__file__).resolve().parents[1] / "audit-run-guard.sh"


def _run(ws, owner_pid, name="audit_run"):
    env = {**os.environ, "AUDITOOOR_RUN_OWNER_PID": str(owner_pid)}
    return subprocess.run(["bash", str(_GUARD), str(ws), name],
                          env=env, capture_output=True, text=True, timeout=15)


def test_first_acquire_then_busy_for_live_owner(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    live = os.getpid()  # this test process is alive
    r1 = _run(ws, live)
    assert r1.returncode == 0, "first acquire should succeed"
    lock = ws / ".auditooor" / ".audit_run.lock"
    assert lock.is_file() and lock.read_text().strip() == str(live)
    r2 = _run(ws, live)
    assert r2.returncode == 3, "second run while live owner holds the lock must be BUSY"
    assert "BUSY" in r2.stderr


def test_stale_dead_pid_lock_is_reclaimed(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    (ws / ".auditooor" / ".audit_run.lock").write_text("999999\n")  # almost-certainly-dead pid
    r = _run(ws, os.getpid())
    assert r.returncode == 0, "a lock held by a dead pid must be reclaimable (no permanent block)"
    assert (ws / ".auditooor" / ".audit_run.lock").read_text().strip() == str(os.getpid())


def test_distinct_lock_names_independent(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    live = os.getpid()
    assert _run(ws, live, "audit_run").returncode == 0
    # a different stage name has its own lock -> not blocked by audit_run
    assert _run(ws, live, "audit_deep").returncode == 0


def test_usage_error_without_workspace(tmp_path):
    r = subprocess.run(["bash", str(_GUARD)], capture_output=True, text=True, timeout=15)
    assert r.returncode == 2
