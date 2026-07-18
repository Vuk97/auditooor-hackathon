#!/usr/bin/env python3
"""test_stale_pin_check.py

Enforcement-gap R007 (2026-07-03): no gate compared the local src/<repo> git HEAD to
the declared audit pin (pin_policy.json / SCOPE.md), so a stale/drifted checkout passed
every coverage gate while the audit ran against DIFFERENT code than it claims.
stale-pin-check compares each src/ git clone HEAD to the declared pin set; a repo at NO
declared pin -> FLAG. Advisory by default; rc 1 under AUDITOOOR_STALE_PIN_STRICT.

Also pins the audit-done-guard wiring (advisory-first, final-boundary, FLAG-gated).
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "stale-pin-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("stale_pin_check", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["stale_pin_check"] = m
    spec.loader.exec_module(m)
    return m


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo)] + list(args), capture_output=True, text=True, check=True)


def _mk_repo_ws(pin_value_factory):
    """Build a ws with src/repo git-init'd (one commit) + a pin_policy.json whose pin is
    pin_value_factory(head_sha)."""
    ws = Path(tempfile.mkdtemp())
    repo = ws / "src" / "repo"
    repo.mkdir(parents=True)
    (repo / "a.sol").write_text("contract A {}", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "x")
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    (ws / ".auditooor").mkdir()
    (ws / ".auditooor" / "pin_policy.json").write_text(
        json.dumps({"policy": "deployed", "repo_deployed_pin": pin_value_factory(head)}),
        encoding="utf-8")
    return ws, head


class TestStalePinCheck(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_head_at_pin_passes(self):
        ws, head = _mk_repo_ws(lambda h: h)  # pin == HEAD
        self.assertEqual(self.m.check(ws)["verdict"], "pass")

    def test_head_at_short_pin_passes(self):
        ws, head = _mk_repo_ws(lambda h: h[:9])  # declared short pin prefixes HEAD
        self.assertEqual(self.m.check(ws)["verdict"], "pass")

    def test_head_not_at_pin_flags(self):
        ws, head = _mk_repo_ws(lambda h: "deadbea1234567890deadbea1234567890abcdef")  # a real-looking other sha
        r = self.m.check(ws)
        self.assertEqual(r["verdict"], "FLAG")
        self.assertTrue(r["mismatched"])

    def test_no_pins_is_advisory_neutral_pass(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        self.assertEqual(self.m.check(ws)["verdict"], "pass")  # no git clones -> pass

    def test_strict_env_returns_rc1_on_flag(self):
        ws, head = _mk_repo_ws(lambda h: "abcdef1234567890abcdef1234567890abcdef12")
        env = dict(os.environ, AUDITOOOR_STALE_PIN_STRICT="1")
        r = subprocess.run([sys.executable, str(_TOOL), str(ws), "--json"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 1, "FLAG under strict env must rc 1")


class TestDoneGuardStalePinWired(unittest.TestCase):
    def test_wiring_present_and_advisory_first(self):
        src = (Path(__file__).resolve().parents[1] / "audit-done-guard.py").read_text(
            encoding="utf-8", errors="replace")
        self.assertIn("stale-pin-check.py", src, "done-guard must invoke stale-pin-check")
        self.assertIn("stale_pin_advisory", src, "must attach a read-only advisory")
        self.assertIn("AUDITOOOR_DONE_STALE_PIN_STRICT", src, "hard-block must be env-gated")
        i_block = src.find("stale-pin FLAG (STRICT)")
        i_done = src.rfind('res["done"] = True')
        self.assertGreater(i_block, 0)
        self.assertLess(i_block, i_done, "must sit at the final DONE boundary")


if __name__ == "__main__":
    unittest.main()
