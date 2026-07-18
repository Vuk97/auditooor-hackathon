#!/usr/bin/env python3
# r36-rebuttal: lane-RULE-65-CALIBRATION declared in .auditooor/agent_pathspec.json
"""Regression coverage for tools/deepseek-task-router.py.

Covers:
- Verdict vocabulary (pass-calibration-fresh / pass-calibration-not-required /
  ok-rebuttal / fail-no-calibration / fail-calibration-stale / error)
- Routing.json lookup (case-insensitive, missing-entry, malformed-date)
- Budget threshold short-circuit
- Env bypass marker (AUDITOOOR_R65_BYPASS=1)
- --require-fresh-calibration exit code
- JSON output shape
- TOK-B-CL "11 dollar Pro commitment without calibration" anchor
"""
from __future__ import annotations

import datetime as _dt
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_THIS = Path(__file__).resolve().parent
_REPO = _THIS.parent.parent
_TOOL_PATH = _REPO / "tools" / "deepseek-task-router.py"

# Import as module.
_spec = importlib.util.spec_from_file_location("router_mod", _TOOL_PATH)
router_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(router_mod)


class TestRoutingLookup(unittest.TestCase):
    def test_lookup_case_insensitive(self):
        routing = {
            "schema": "auditooor.deepseek_task_routing.v1",
            "entries": [
                {"task_id": "TOK-B-CL", "calibration_date": "2026-05-26",
                 "winner": "deepseek-pro"},
            ],
        }
        entry = router_mod.lookup_routing_entry(routing, "tok-b-cl")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["winner"], "deepseek-pro")

    def test_lookup_missing(self):
        routing = {"schema": "x", "entries": []}
        self.assertIsNone(router_mod.lookup_routing_entry(routing, "TOK-X"))

    def test_lookup_malformed_entries(self):
        routing = {"entries": ["not-a-dict", {"task_id": "OK"}]}
        # Should not crash and find the dict entry.
        entry = router_mod.lookup_routing_entry(routing, "OK")
        self.assertIsNotNone(entry)


class TestRouteTask(unittest.TestCase):
    def _routing_with_fresh_entry(self, task_id="TOK-B-CL"):
        return {
            "schema": "auditooor.deepseek_task_routing.v1",
            "entries": [{
                "task_id": task_id,
                "calibration_date": _dt.date.today().isoformat(),
                "winner": "deepseek-pro",
                "confidence": 0.85,
                "flash_score": 3.2,
                "pro_score": 4.7,
                "ratio_flash_over_pro": 0.68,
                "decision_rationale": "Pro 5/5 idiomatic Rust",
            }],
        }

    def _routing_with_stale_entry(self, task_id="TOK-X-OLD", days_old=120):
        old_date = (_dt.date.today() - _dt.timedelta(days=days_old)).isoformat()
        return {
            "schema": "auditooor.deepseek_task_routing.v1",
            "entries": [{
                "task_id": task_id,
                "calibration_date": old_date,
                "winner": "deepseek-pro",
                "confidence": 0.7,
                "flash_score": 3.0,
                "pro_score": 4.5,
            }],
        }

    def test_pass_calibration_fresh(self):
        routing = self._routing_with_fresh_entry()
        result = router_mod.route_task(
            task_id="TOK-B-CL", budget_usd=11.0, routing=routing,
            ttl_days=90, bypass=False,
        )
        self.assertEqual(result["verdict"], "pass-calibration-fresh")
        self.assertEqual(result["recommended_provider"], "deepseek-pro")
        self.assertEqual(result["calibration_days_old"], 0)
        self.assertEqual(result["flash_score"], 3.2)

    def test_fail_no_calibration(self):
        routing = {"schema": "x", "entries": []}
        result = router_mod.route_task(
            task_id="TOK-MISSING", budget_usd=11.0, routing=routing,
            ttl_days=90, bypass=False,
        )
        self.assertEqual(result["verdict"], "fail-no-calibration")
        self.assertIn("make deepseek-calibrate", result["decision_rationale"])

    def test_fail_calibration_stale(self):
        routing = self._routing_with_stale_entry(days_old=120)
        result = router_mod.route_task(
            task_id="TOK-X-OLD", budget_usd=11.0, routing=routing,
            ttl_days=90, bypass=False,
        )
        self.assertEqual(result["verdict"], "fail-calibration-stale")
        self.assertTrue(result["stale"])
        self.assertEqual(result["calibration_days_old"], 120)

    def test_pass_calibration_not_required_low_budget(self):
        # $0.50 < $1 R65 threshold
        routing = {"schema": "x", "entries": []}
        result = router_mod.route_task(
            task_id="TOK-X", budget_usd=0.50, routing=routing,
            ttl_days=90, bypass=False,
        )
        self.assertEqual(result["verdict"], "pass-calibration-not-required")

    def test_ok_rebuttal_via_bypass(self):
        routing = {"schema": "x", "entries": []}
        result = router_mod.route_task(
            task_id="TOK-X", budget_usd=11.0, routing=routing,
            ttl_days=90, bypass=True,
        )
        self.assertEqual(result["verdict"], "ok-rebuttal")

    def test_tok_b_cl_anchor_11_dollar_no_calibration(self):
        """Empirical anchor: TOK-B-CL $11 commit without calibration -> refused."""
        routing = {"schema": "x", "entries": []}  # empty routing.json
        result = router_mod.route_task(
            task_id="TOK-B-CL", budget_usd=11.0, routing=routing,
            ttl_days=90, bypass=False,
        )
        self.assertEqual(result["verdict"], "fail-no-calibration")

    def test_malformed_calibration_date(self):
        routing = {"entries": [{"task_id": "TOK-X",
                                "calibration_date": "not-a-date",
                                "winner": "deepseek-pro"}]}
        result = router_mod.route_task(
            task_id="TOK-X", budget_usd=11.0, routing=routing,
            ttl_days=90, bypass=False,
        )
        self.assertEqual(result["verdict"], "error")


class TestLoadRouting(unittest.TestCase):
    def test_load_missing_file(self):
        result = router_mod.load_routing(Path("/tmp/nonexistent-routing.json"))
        self.assertEqual(result, {})

    def test_load_valid_routing(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False,
                                         mode="w") as f:
            json.dump({"entries": [{"task_id": "OK"}]}, f)
            path = Path(f.name)
        try:
            result = router_mod.load_routing(path)
            self.assertIn("entries", result)
        finally:
            path.unlink()

    def test_load_malformed_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False,
                                         mode="w") as f:
            f.write("{ not valid json")
            path = Path(f.name)
        try:
            result = router_mod.load_routing(path)
            self.assertIn("_error", result)
        finally:
            path.unlink()


class TestCLI(unittest.TestCase):
    def setUp(self):
        # Use a temporary routing file with a known fresh entry.
        self.tmpdir = Path(tempfile.mkdtemp())
        self.routing_path = self.tmpdir / "routing.json"
        doc = {
            "schema": "auditooor.deepseek_task_routing.v1",
            "entries": [{
                "task_id": "TOK-B-CL",
                "calibration_date": _dt.date.today().isoformat(),
                "winner": "deepseek-pro",
                "confidence": 0.85,
                "flash_score": 3.2,
                "pro_score": 4.7,
                "ratio_flash_over_pro": 0.68,
                "decision_rationale": "Pro decisive",
            }],
        }
        self.routing_path.write_text(json.dumps(doc))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, task_id, *args, env=None):
        env_full = dict(os.environ)
        if env:
            env_full.update(env)
        cmd = [sys.executable, str(_TOOL_PATH),
               "--task-id", task_id,
               "--routing-json", str(self.routing_path),
               *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                              env=env_full)

    def test_cli_json_output_shape(self):
        proc = self._run("TOK-B-CL", "--budget-usd", "11", "--json")
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.deepseek_task_router.v1")
        self.assertEqual(payload["verdict"], "pass-calibration-fresh")

    def test_cli_fail_no_calibration_returns_rc0_default(self):
        proc = self._run("TOK-DOES-NOT-EXIST", "--budget-usd", "11", "--json")
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-no-calibration")

    def test_cli_require_fresh_fails_when_missing(self):
        proc = self._run("TOK-DOES-NOT-EXIST", "--budget-usd", "11",
                         "--require-fresh-calibration", "--json")
        self.assertEqual(proc.returncode, 1)

    def test_cli_require_fresh_passes_when_fresh(self):
        proc = self._run("TOK-B-CL", "--budget-usd", "11",
                         "--require-fresh-calibration", "--json")
        self.assertEqual(proc.returncode, 0)

    def test_cli_low_budget_passes_without_calibration(self):
        proc = self._run("TOK-DOES-NOT-EXIST", "--budget-usd", "0.50",
                         "--require-fresh-calibration", "--json")
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-calibration-not-required")

    def test_cli_env_bypass(self):
        proc = self._run("TOK-DOES-NOT-EXIST", "--budget-usd", "11",
                         "--require-fresh-calibration", "--json",
                         env={"AUDITOOOR_R65_BYPASS": "1"})
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "ok-rebuttal")


if __name__ == "__main__":
    unittest.main()
