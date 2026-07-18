"""Regression: the auditooor gh wrapper must TIME-BOUND every real-gh call so a
blocked macOS keychain / expired token (no TTY to refresh on) can never hang the
audit pipeline (the `gh auth token` hang that stalled `make audit` on near-intents)."""
import os
import subprocess
import time
from pathlib import Path

_WRAP = Path(__file__).resolve().parents[1] / "auditooor-gh-wrapper.sh"


def _fake_gh(tmp_path, body):
    p = tmp_path / "fake_gh.sh"
    p.write_text("#!/usr/bin/env bash\n" + body + "\n", encoding="utf-8")
    p.chmod(0o755)
    return str(p)


def _run(real_gh, args, timeout_s, hard_timeout=30):
    env = {**os.environ, "AUDITOOOR_REAL_GH": real_gh,
           "AUDITOOOR_GH_TIMEOUT_S": str(timeout_s),
           "AUDITOOOR_NO_FRESHNESS_CHECK": "1"}
    t0 = time.time()
    r = subprocess.run(["bash", str(_WRAP), *args], env=env,
                       capture_output=True, text=True, timeout=hard_timeout)
    return r, time.time() - t0


def test_nongated_slow_gh_times_out_not_hangs(tmp_path):
    slow = _fake_gh(tmp_path, "sleep 60\necho should-never-print")
    r, elapsed = _run(slow, ["auth", "token", "--hostname", "github.com"], timeout_s=3)
    assert r.returncode == 124, f"expected timeout rc=124, got {r.returncode}"
    assert elapsed < 15, f"wrapper hung: {elapsed:.1f}s (timeout was 3s)"
    assert "should-never-print" not in r.stdout


def test_gated_slow_gh_also_time_bounded(tmp_path):
    # gated path (pr create) with no token + MCP_REQUIRED=0 bypass still time-bounds
    slow = _fake_gh(tmp_path, "sleep 60\necho should-never-print")
    env = {**os.environ, "AUDITOOOR_REAL_GH": slow, "AUDITOOOR_GH_TIMEOUT_S": "3",
           "AUDITOOOR_NO_FRESHNESS_CHECK": "1", "AUDITOOOR_MCP_REQUIRED": "0"}
    t0 = time.time()
    r = subprocess.run(["bash", str(_WRAP), "pr", "create", "--title", "x"],
                       env=env, capture_output=True, text=True, timeout=30)
    assert time.time() - t0 < 15, "gated path hung"
    assert r.returncode == 124


def test_fast_command_passes_through(tmp_path):
    fast = _fake_gh(tmp_path, 'echo "ok:$*"')
    r, elapsed = _run(fast, ["repo", "view", "foo/bar"], timeout_s=30)
    assert r.returncode == 0
    assert "ok:repo view foo/bar" in r.stdout
    assert elapsed < 10


def test_timeout_disabled_when_zero(tmp_path):
    # AUDITOOOR_GH_TIMEOUT_S=0 disables the bound (passthrough); fast cmd still works
    fast = _fake_gh(tmp_path, 'echo "ok"')
    r, _ = _run(fast, ["repo", "view", "x/y"], timeout_s=0)
    assert r.returncode == 0 and "ok" in r.stdout
