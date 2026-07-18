#!/usr/bin/env python3
"""Tests for the hunt-dispatch PROVENANCE guard
(tools/hunt-dispatch-provenance-check.py) - the Rule-3 enforcement that catches a
per-fn hunt dispatched OUTSIDE tools/spawn-worker.sh (no ledger entry).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hunt-dispatch-provenance-check.py"
_s = importlib.util.spec_from_file_location("hunt_dispatch_provenance", _T)
mod = importlib.util.module_from_spec(_s)
sys.modules["hunt_dispatch_provenance"] = mod
_s.loader.exec_module(mod)


class HuntDispatchProvenanceTest(unittest.TestCase):
    def _setup(self, wsname="testws", n_batches=4, ledger_refs=0,
               sidecar=False, plan=True):
        root = Path(tempfile.mkdtemp())
        derived = root / "derived"
        plan_dir = derived / f"haiku_harness_{wsname}_scoped_n{n_batches}" / "_haiku_plan"
        plan_token = f"haiku_harness_{wsname}_scoped_n{n_batches}"
        if plan:
            plan_dir.mkdir(parents=True)
            for i in range(n_batches):
                (plan_dir / f"agent_batch_{i:04d}.md").write_text("task", encoding="utf-8")
        ws = root / wsname
        (ws / ".auditooor").mkdir(parents=True)
        if sidecar:
            sc = ws / ".auditooor" / "hunt_findings_sidecars"
            sc.mkdir()
            time.sleep(0.01)
            (sc / "v.json").write_text("{}", encoding="utf-8")
        ledger = root / "spawn_worker_log.jsonl"
        lines = []
        for i in range(ledger_refs):
            lines.append(json.dumps({
                "workspace": str(ws), "lane_type": "hunt",
                "prompt_file": f"/x/{plan_token}/_haiku_plan/agent_batch_{i:04d}.md",
            }))
        ledger.write_text("\n".join(lines), encoding="utf-8")
        # inject tmp paths into the module
        mod.DERIVED = derived
        mod.LEDGER = ledger
        return ws

    def test_fail_dispatched_but_unlogged(self):
        ws = self._setup(n_batches=4, ledger_refs=0, sidecar=True)
        res = mod.check(ws)
        self.assertEqual(res["verdict"], mod.V_FAIL)
        self.assertEqual(mod.main([str(ws), "--json"]), 1)

    def test_pass_dispatched_and_logged(self):
        ws = self._setup(n_batches=4, ledger_refs=4, sidecar=True)
        res = mod.check(ws)
        self.assertEqual(res["verdict"], mod.V_PASS)
        self.assertEqual(mod.main([str(ws), "--json"]), 0)

    def test_na_plan_not_yet_dispatched(self):
        ws = self._setup(n_batches=4, ledger_refs=0, sidecar=False)
        self.assertEqual(mod.check(ws)["verdict"], mod.V_NA)

    def test_na_no_plan(self):
        ws = self._setup(plan=False, sidecar=True)
        self.assertEqual(mod.check(ws)["verdict"], mod.V_NA)

    def test_warn_partial(self):
        ws = self._setup(n_batches=8, ledger_refs=1, sidecar=True)
        self.assertEqual(mod.check(ws)["verdict"], mod.V_WARN)

    def _write_provider_receipt(self, ws, plan_token, **overrides):
        receipt = {
            "schema": mod.PROVIDER_RECEIPT_SCHEMA,
            "workspace": str(ws), "output_dir": str(ws / "out"),
            "plan_token": plan_token, "provider": "mimo", "task_count": 4,
            "terminal_counts": {"ok": 4},
            "started_at_utc": "2026-07-16T10:00:00Z",
            "ended_at_utc": "2026-07-16T10:00:01Z",
        }
        receipt.update(overrides)
        (ws / ".auditooor" / "provider_dispatch_receipt.json").write_text(
            json.dumps(receipt), encoding="utf-8")

    def test_provider_receipt_is_canonical_dispatch_path(self):
        ws = self._setup(n_batches=4, ledger_refs=0, sidecar=True)
        self._write_provider_receipt(ws, "haiku_harness_testws_scoped_n4")
        result = mod.check(ws)
        self.assertEqual(result["verdict"], mod.V_PASS)
        self.assertIn("provider fanout receipt", result["reason"])

    def test_missing_provider_receipt_still_fails_unlogged_raw_fanout(self):
        ws = self._setup(n_batches=4, ledger_refs=0, sidecar=True)
        self.assertEqual(mod.check(ws)["verdict"], mod.V_FAIL)

    def test_invalid_provider_receipts_do_not_green_raw_fanout(self):
        ws = self._setup(n_batches=4, ledger_refs=0, sidecar=True)
        token = "haiku_harness_testws_scoped_n4"
        self._write_provider_receipt(ws, token, terminal_counts={"ok": 3})
        self.assertEqual(mod.check(ws)["verdict"], mod.V_FAIL)
        self._write_provider_receipt(ws, "wrong-plan")
        self.assertEqual(mod.check(ws)["verdict"], mod.V_FAIL)

    def test_incomplete_provider_receipt_does_not_green_dispatch(self):
        ws = self._setup(n_batches=4, ledger_refs=0, sidecar=True)
        token = "haiku_harness_testws_scoped_n4"
        self._write_provider_receipt(
            ws, token, terminal_counts={"ok": 0, "skipped": 4}
        )
        result = mod.check(ws)
        self.assertEqual(result["verdict"], mod.V_FAIL)
        self.assertIn("incomplete", result["detail"]["provider_receipt"])

    def test_failed_provider_receipt_does_not_green_dispatch(self):
        ws = self._setup(n_batches=4, ledger_refs=0, sidecar=True)
        token = "haiku_harness_testws_scoped_n4"
        self._write_provider_receipt(
            ws, token, terminal_counts={"ok": 3, "failed": 1}
        )
        result = mod.check(ws)
        self.assertEqual(result["verdict"], mod.V_FAIL)

    def test_incomplete_provider_receipt_cannot_be_masked_by_dispatch_ledger(self):
        ws = self._setup(n_batches=4, ledger_refs=4, sidecar=True)
        token = "haiku_harness_testws_scoped_n4"
        self._write_provider_receipt(
            ws, token, terminal_counts={"ok": 0, "skipped": 4}
        )
        result = mod.check(ws)
        self.assertEqual(result["verdict"], mod.V_FAIL)
        self.assertIn("receipt invalid", result["reason"])

    def test_failed_provider_receipt_cannot_be_masked_by_dispatch_ledger(self):
        ws = self._setup(n_batches=4, ledger_refs=4, sidecar=True)
        token = "haiku_harness_testws_scoped_n4"
        self._write_provider_receipt(
            ws, token, terminal_counts={"ok": 3, "failed": 1}
        )
        result = mod.check(ws)
        self.assertEqual(result["verdict"], mod.V_FAIL)

    def test_duplicate_dispatches_are_hard_failure_even_with_valid_receipt(self):
        ws = self._setup(n_batches=4, ledger_refs=8, sidecar=True)
        token = "haiku_harness_testws_scoped_n4"
        self._write_provider_receipt(ws, token)
        result = mod.check(ws)
        self.assertEqual(result["verdict"], mod.V_FAIL)
        self.assertIn("duplicate dispatch", result["reason"])


if __name__ == "__main__":
    unittest.main()
