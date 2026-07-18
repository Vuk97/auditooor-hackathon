#!/usr/bin/env python3
"""test_rehunt_uncovered_makefile.py

Regression for the B1 pre-hunt rewire: `make rehunt-uncovered` drains the
NOT-ENUMERATED completeness cells the matrix wrote to
.auditooor/completeness_enumeration_worklist.jsonl by fanning them out into N
CONCURRENT spawn-worker hunt lanes (via tools/spawn-worker-fanout.py, which
composes spawn-worker.sh - neither is forked).

Contract under test:
  1. The target exists and is DEFAULT-OFF behind AUDITOOOR_REHUNT_UNCOVERED
     (unset => a SKIPPED no-op that mutates nothing).
  2. It pipes the completeness_enumeration_worklist.jsonl into
     spawn-worker-fanout.py --worklist with the canonical rehunt template.
  3. A functional dry-run against a temp workspace expands N worklist rows to N
     per-lane prompts with distinct sidecars (never touching spawn-worker.sh).
  4. `make -n rehunt-uncovered` parses in both env states.

Static Makefile checks avoid subprocess; the functional run uses --dry-run so
spawn-worker.sh / git / lane-registration are never invoked.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MAKEFILE = REPO / "Makefile"
TEMPLATE = REPO / "reference" / "dispatch-templates" / "rehunt_uncovered_cell.md.tmpl"
FANOUT = REPO / "tools" / "spawn-worker-fanout.py"


def _read_makefile() -> str:
    return MAKEFILE.read_text(encoding="utf-8")


def _extract_target_body(text: str, target: str) -> str:
    start_marker = f"\n{target}:"
    start = text.find(start_marker)
    if start == -1:
        raise ValueError(f"target '{target}' not found in Makefile")
    body_start = text.index("\n", start + 1) + 1
    pos = body_start
    while pos < len(text):
        nl = text.find("\n", pos)
        if nl == -1:
            break
        line = text[nl + 1:]
        if (
            line
            and not line[0].isspace()
            and ":" in line.split("=")[0]
            and not line.startswith(".PHONY")
            and not line.startswith("#")
        ):
            return text[body_start: nl + 1]
        pos = nl + 1
    return text[body_start:]


class TestRehuntUncoveredStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not MAKEFILE.is_file():
            raise unittest.SkipTest(f"{MAKEFILE} not found")
        cls._text = _read_makefile()
        cls._body = _extract_target_body(cls._text, "rehunt-uncovered")

    def test_target_is_phony(self) -> None:
        self.assertIn("rehunt-uncovered", self._text.split("\n")[14],
                      "rehunt-uncovered must be declared .PHONY")

    def test_default_off_env_gate(self) -> None:
        """DEFAULT-OFF: the target must gate on AUDITOOOR_REHUNT_UNCOVERED and
        print a SKIPPED sentinel + exit 0 when it is unset."""
        self.assertIn("AUDITOOOR_REHUNT_UNCOVERED", self._body)
        self.assertIn("SKIPPED", self._body,
                      "unset env must print a SKIPPED no-op sentinel")

    def test_pipes_worklist_into_fanout(self) -> None:
        """B1 core wiring: consume completeness_enumeration_worklist.jsonl via
        spawn-worker-fanout.py --worklist."""
        self.assertIn("completeness_enumeration_worklist.jsonl", self._body)
        self.assertIn("spawn-worker-fanout.py", self._body)
        self.assertIn("--worklist", self._body)

    def test_uses_canonical_template(self) -> None:
        self.assertIn("rehunt_uncovered_cell.md.tmpl", self._body,
                      "must default to the canonical rehunt template")
        self.assertTrue(TEMPLATE.is_file(),
                        f"canonical rehunt template must exist on disk: {TEMPLATE}")

    def test_dry_run_unless_dispatch_env(self) -> None:
        """--dry-run must be the default; only AUDITOOOR_REHUNT_UNCOVERED_DISPATCH=1
        drops it (so an opt-in run does not register lanes / touch git until the
        operator explicitly asks to dispatch)."""
        self.assertIn("--dry-run", self._body)
        self.assertIn("AUDITOOOR_REHUNT_UNCOVERED_DISPATCH", self._body)

    def test_no_dash_characters(self) -> None:
        self.assertNotIn("—", self._body, "em-dash present in recipe")
        self.assertNotIn("–", self._body, "en-dash present in recipe")

    def test_template_no_dash_characters(self) -> None:
        t = TEMPLATE.read_text(encoding="utf-8")
        self.assertNotIn("—", t)
        self.assertNotIn("–", t)


def _make_n(env_extra: dict[str, str]) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(env_extra)
    return subprocess.run(
        ["make", "-n", "rehunt-uncovered", "WS=/tmp"],
        capture_output=True, text=True, cwd=str(REPO), env=env)


class TestRehuntUncoveredMakeParses(unittest.TestCase):
    def test_make_n_parses_env_unset(self) -> None:
        """`make -n rehunt-uncovered` must parse (rc 0) with the env unset."""
        r = _make_n({"AUDITOOOR_REHUNT_UNCOVERED": ""})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SKIPPED", r.stdout, "env-unset should render the SKIPPED branch")

    def test_make_n_parses_env_set(self) -> None:
        """`make -n rehunt-uncovered` must parse (rc 0) with the env set, and the
        dry-run fanout invocation must appear."""
        r = _make_n({"AUDITOOOR_REHUNT_UNCOVERED": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("spawn-worker-fanout.py", r.stdout)
        self.assertIn("--dry-run", r.stdout, "env-set (no dispatch) keeps --dry-run")

    def test_make_n_dispatch_drops_dry_run(self) -> None:
        r = _make_n({"AUDITOOOR_REHUNT_UNCOVERED": "1",
                     "AUDITOOOR_REHUNT_UNCOVERED_DISPATCH": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("spawn-worker-fanout.py", r.stdout)
        self.assertNotIn("--dry-run", r.stdout,
                         "dispatch env must drop --dry-run")


class TestRehuntUncoveredFunctional(unittest.TestCase):
    def test_dry_run_fans_worklist_into_distinct_lanes(self) -> None:
        """End-to-end (dry-run): 2 uncovered worklist rows -> 2 per-lane prompts
        with DISTINCT sidecars, spawn-worker.sh never invoked."""
        if not FANOUT.is_file():
            self.skipTest("spawn-worker-fanout.py missing")
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True)
            wl = ws / ".auditooor" / "completeness_enumeration_worklist.jsonl"
            rows = [
                {"axis": "function", "asset": "Vault", "function": "withdraw",
                 "file": "src/Vault.sol", "impact_category": "value-movement",
                 "status": "not-enumerated", "cell_kind": "value_moving",
                 "action": "enumerate", "reason": "uncovered"},
                {"axis": "invariant", "asset": "Vault", "invariant_category": "conservation",
                 "impact_category": "conservation", "status": "not-enumerated",
                 "cell_kind": "value_moving", "action": "enumerate", "reason": "uncovered"},
            ]
            wl.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
            env = dict(os.environ)
            env["AUDITOOOR_REHUNT_UNCOVERED"] = "1"  # opt in, but dry-run (no dispatch)
            r = subprocess.run(
                ["make", "-s", "rehunt-uncovered", f"WS={ws}"],
                capture_output=True, text=True, cwd=str(REPO), env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            combined = r.stdout + r.stderr
            self.assertIn("dispatched=2", combined, combined)
            self.assertIn("spawn-worker NOT invoked", combined, combined)
            man = ws / ".auditooor" / "fanout_rehunt_manifest.jsonl"
            self.assertTrue(man.is_file(), "fan-out manifest must be written")
            recs = [json.loads(l) for l in man.read_text().splitlines() if l.strip()]
            self.assertEqual(len(recs), 2)
            sidecars = {rec["output_sidecar"] for rec in recs}
            self.assertEqual(len(sidecars), 2, "each lane needs a DISTINCT sidecar")

    def test_default_off_is_noop(self) -> None:
        """With AUDITOOOR_REHUNT_UNCOVERED unset the target is a SKIPPED no-op:
        even with a worklist present, no fan-out manifest is written."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True)
            wl = ws / ".auditooor" / "completeness_enumeration_worklist.jsonl"
            wl.write_text(json.dumps({"axis": "function", "asset": "A"}) + "\n",
                          encoding="utf-8")
            env = dict(os.environ)
            env["AUDITOOOR_REHUNT_UNCOVERED"] = ""
            r = subprocess.run(
                ["make", "-s", "rehunt-uncovered", f"WS={ws}"],
                capture_output=True, text=True, cwd=str(REPO), env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("SKIPPED", r.stdout + r.stderr)
            self.assertFalse(
                (ws / ".auditooor" / "fanout_rehunt_manifest.jsonl").exists(),
                "default-off must not fan out anything")


if __name__ == "__main__":
    unittest.main()
