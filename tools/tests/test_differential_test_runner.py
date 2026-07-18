#!/usr/bin/env python3
"""Tests for tools/audit/differential-test-runner.py (W4.8).

Stdlib-only. Builds a synthetic two-tree fixture in a tempdir: an upstream
Go library pin and a "fork" of it that drops one guard, changes one call
set, refactors one function cosmetically, adds one function, and leaves one
function identical. Asserts each divergence is classified correctly.

Coverage:
  1.  Schema field is auditooor.differential_report.v1.
  2.  upstream/fork function counts are reported.
  3.  Dropped-upstream-guard function is classified security-relevant.
  4.  security-relevant detail lists the dropped guard.
  5.  Fork-added guard is classified security-relevant (other direction).
  6.  Call-set-only change is classified behavior-changing.
  7.  Cosmetic refactor (extra blank lines, same guards/calls/sig) is cosmetic.
  8.  Identical function is counted but NOT listed in divergences.
  9.  Fork-only function is classified added.
  10. Upstream-only function is classified removed.
  11. divergences are sorted security-relevant first.
  12. summary.security_relevant_count matches.
  13. summary.top_finding_keys is populated.
  14. --strict exits 2 when a security-relevant divergence exists.
  15. non-strict exits 0 even with security-relevant divergence.
  16. --out writes a JSON file.
  17. bad --upstream path exits 1.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_RUNNER = _TOOLS / "audit" / "differential-test-runner.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("_diff_runner", _RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------
# Synthetic two-tree fixture.
# --------------------------------------------------------------------------
# Upstream: Withdraw has an authority-check guard + a require-auth guard.
UPSTREAM_GO = """\
package vault

func (k Keeper) Withdraw(ctx Context, amt int) error {
\tif msg.Sender != k.GetAuthority() {
\t\treturn fmt.Errorf("unauthorized")
\t}
\trequire_auth(ctx)
\tk.balance.Set(amt)
\treturn nil
}

func (k Keeper) Deposit(ctx Context, amt int) error {
\tk.balance.Set(amt)
\tlog.Info("deposit")
\treturn nil
}

func (k Keeper) Refactored(ctx Context) error {
\tk.balance.Set(0)
\treturn nil
}

func (k Keeper) StableFn(ctx Context) error {
\treturn nil
}

func (k Keeper) OnlyUpstream(ctx Context) error {
\treturn nil
}
"""

# Fork: Withdraw DROPPED the authority-check guard (security-relevant).
#       Deposit gained a pause-check guard (security-relevant, other dir).
#       Refactored only has extra blank lines (cosmetic).
#       StableFn unchanged (identical).
#       OnlyFork is new (added). OnlyUpstream is gone (removed).
FORK_GO = """\
package vault

func (k Keeper) Withdraw(ctx Context, amt int) error {
\trequire_auth(ctx)
\tk.balance.Set(amt)
\treturn nil
}

func (k Keeper) Deposit(ctx Context, amt int) error {
\tif paused() {
\t\treturn fmt.Errorf("paused")
\t}
\tk.balance.Set(amt)
\tlog.Info("deposit")
\treturn nil
}

func (k Keeper) Refactored(ctx Context) error {

\tk.balance.Set(0)

\treturn nil
}

func (k Keeper) StableFn(ctx Context) error {
\treturn nil
}

func (k Keeper) OnlyFork(ctx Context) error {
\treturn nil
}
"""


class DifferentialRunnerTest(unittest.TestCase):
    def setUp(self):
        self.runner = _load_runner()
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.up = root / "upstream"
        self.fk = root / "fork"
        self.up.mkdir()
        self.fk.mkdir()
        (self.up / "vault.go").write_text(UPSTREAM_GO, encoding="utf-8")
        (self.fk / "vault.go").write_text(FORK_GO, encoding="utf-8")
        self.extractor = self.runner._load_extractor()
        self.report = self.runner.build_report(
            self.extractor, self.up, self.fk, "go", "deadbeef")
        self.bykey = {d["function_key"]: d for d in self.report["divergences"]}

    def tearDown(self):
        self.tmp.cleanup()

    def test_01_schema(self):
        self.assertEqual(self.report["schema"], "auditooor.differential_report.v1")

    def test_02_function_counts(self):
        s = self.report["summary"]
        self.assertEqual(s["upstream_functions"], 5)
        self.assertEqual(s["fork_functions"], 5)

    def test_03_dropped_guard_is_security_relevant(self):
        d = self.bykey["Keeper.Withdraw"]
        self.assertEqual(d["verdict"], "security-relevant")

    def test_04_dropped_guard_listed(self):
        d = self.bykey["Keeper.Withdraw"]
        self.assertIn("authority-check", d["detail"]["guards_dropped_in_fork"])

    def test_05_fork_added_guard_is_security_relevant(self):
        d = self.bykey["Keeper.Deposit"]
        self.assertEqual(d["verdict"], "security-relevant")
        self.assertIn("pause-check", d["detail"]["guards_added_in_fork"])

    def test_06_call_change_is_behavior_changing(self):
        # Withdraw also lost the GetAuthority call; but guard delta dominates.
        # Deposit's only delta beyond guard is none — use guard test above.
        # Verify behavior-changing rank exists in classifier directly:
        up = {"function_signature": "func F()", "guards_detected": [],
              "calls_made": ["a"], "line_start": 1, "line_end": 5}
        fk = {"function_signature": "func F()", "guards_detected": [],
              "calls_made": ["a", "b"], "line_start": 1, "line_end": 5}
        verdict, _ = self.runner._classify(up, fk)
        self.assertEqual(verdict, "behavior-changing")

    def test_07_cosmetic_refactor(self):
        d = self.bykey["Keeper.Refactored"]
        self.assertEqual(d["verdict"], "cosmetic")

    def test_08_identical_not_listed(self):
        self.assertNotIn("Keeper.StableFn", self.bykey)
        self.assertEqual(self.report["summary"]["counts"]["identical"], 1)

    def test_09_fork_only_is_added(self):
        self.assertEqual(self.bykey["Keeper.OnlyFork"]["verdict"], "added")

    def test_10_upstream_only_is_removed(self):
        self.assertEqual(self.bykey["Keeper.OnlyUpstream"]["verdict"], "removed")

    def test_11_security_relevant_sorted_first(self):
        verdicts = [d["verdict"] for d in self.report["divergences"]]
        first_non_sec = next((i for i, v in enumerate(verdicts)
                              if v != "security-relevant"), len(verdicts))
        self.assertTrue(all(v == "security-relevant"
                            for v in verdicts[:first_non_sec]))
        self.assertNotIn("security-relevant", verdicts[first_non_sec:])

    def test_12_security_relevant_count(self):
        self.assertEqual(self.report["summary"]["security_relevant_count"], 2)

    def test_13_top_finding_keys(self):
        keys = self.report["summary"]["top_finding_keys"]
        self.assertIn("Keeper.Withdraw", keys)
        self.assertIn("Keeper.Deposit", keys)

    def test_14_strict_exits_2(self):
        rc = subprocess.run(
            [sys.executable, str(_RUNNER), "--upstream", str(self.up),
             "--fork", str(self.fk), "--language", "go", "--strict"],
            capture_output=True, text=True).returncode
        self.assertEqual(rc, 2)

    def test_15_non_strict_exits_0(self):
        rc = subprocess.run(
            [sys.executable, str(_RUNNER), "--upstream", str(self.up),
             "--fork", str(self.fk), "--language", "go"],
            capture_output=True, text=True).returncode
        self.assertEqual(rc, 0)

    def test_16_out_writes_file(self):
        out = Path(self.tmp.name) / "report.json"
        subprocess.run(
            [sys.executable, str(_RUNNER), "--upstream", str(self.up),
             "--fork", str(self.fk), "--language", "go", "--out", str(out)],
            capture_output=True, text=True, check=True)
        self.assertTrue(out.is_file())
        data = json.loads(out.read_text())
        self.assertEqual(data["schema"], "auditooor.differential_report.v1")

    def test_17_bad_path_exits_1(self):
        rc = subprocess.run(
            [sys.executable, str(_RUNNER), "--upstream", "/nonexistent/xyz",
             "--fork", str(self.fk), "--language", "go"],
            capture_output=True, text=True).returncode
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
