#!/usr/bin/env python3
"""test_closure_health_check.py

Enforcement-gap closure-degrade (2026-07-03): the D-CONNECT closure-aware `unguarded`
correction stamps closure_consulted/closure_degraded per dataflow record, but no gate
read them - so a run where the closure DEGRADED on every record (predicates unimportable)
was indistinguishable from clean (slice-local `unguarded` over-reports on role-gated code).
closure-health-check FLAGs a run-wide degraded closure; advisory by default, rc 1 under
AUDITOOOR_CLOSURE_DEGRADE_STRICT. Wired into audit-done-guard advisory-first.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "closure-health-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("closure_health_check", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["closure_health_check"] = m
    spec.loader.exec_module(m)
    return m


def _ws(records):
    d = Path(tempfile.mkdtemp())
    (d / ".auditooor").mkdir()
    (d / ".auditooor" / "dataflow_paths.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return d


class TestClosureHealth(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_healthy_closure_passes(self):
        ws = _ws([{"closure_consulted": True, "closure_degraded": False}] * 20)
        self.assertEqual(self.m.check(ws)["verdict"], "pass")

    def test_all_degraded_flags(self):
        ws = _ws([{"closure_consulted": False, "closure_degraded": True}] * 20)
        r = self.m.check(ws)
        self.assertEqual(r["verdict"], "FLAG")

    def test_majority_degraded_flags(self):
        ws = _ws([{"closure_consulted": True, "closure_degraded": False}] * 3
                 + [{"closure_consulted": False, "closure_degraded": True}] * 17)
        self.assertEqual(self.m.check(ws)["verdict"], "FLAG")

    def test_closure_not_requested_passes(self):
        # records with NO closure_* keys -> closure not requested -> nothing to verify
        ws = _ws([{"unguarded": True, "sink": "x"}] * 10)
        self.assertEqual(self.m.check(ws)["verdict"], "pass")

    def test_no_dataflow_file_passes(self):
        self.assertEqual(self.m.check(Path(tempfile.mkdtemp()))["verdict"], "pass")

    def test_strict_env_rc1_on_flag(self):
        ws = _ws([{"closure_consulted": False, "closure_degraded": True}] * 10)
        env = dict(os.environ, AUDITOOOR_CLOSURE_DEGRADE_STRICT="1")
        r = subprocess.run([sys.executable, str(_TOOL), str(ws), "--json"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 1)

    def test_done_guard_wiring(self):
        src = (Path(__file__).resolve().parents[1] / "audit-done-guard.py").read_text(
            encoding="utf-8", errors="replace")
        self.assertIn("closure-health-check.py", src)
        self.assertIn("closure_health_advisory", src)
        self.assertIn("AUDITOOOR_DONE_CLOSURE_DEGRADE_STRICT", src)


if __name__ == "__main__":
    unittest.main()
