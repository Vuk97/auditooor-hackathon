#!/usr/bin/env python3
# <!-- r36-rebuttal: lane L-AUDIT-NEXT-STEP registered via agent-pathspec-register.py -->
"""Guard tests for tools/audit-next-step.py - the unified "next required step" answer.

Pins (stdlib-only):
  - it REUSES readme-conformance-check.evaluate over a real fake-workspace fixture
    with a custom manifest (no re-implemented step-eval), and identifies the FIRST
    unmet REQUIRED step in runbook order;
  - it separates the RED list into REQUIRED vs ADVISORY;
  - rc == 1 when a required step is RED (even if the done-guard would pass);
  - rc == 0 when all required steps PASS and the injected done-guard says DONE;
  - when required steps pass but the done-guard is NOT-DONE, rc == 1 and there is
    no next_required_step (the remaining work is a done-guard gate).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "audit-next-step.py"


def _load():
    spec = importlib.util.spec_from_file_location("audit_next_step", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["audit_next_step"] = m
    spec.loader.exec_module(m)
    return m


# A tiny manifest: two required steps (t-req-a first, t-req-b second) and one
# advisory step (t-adv). Each is satisfied by the presence of a marker file so the
# REAL conformance evaluator (which the tool reuses) drives the PASS/RED status.
_MANIFEST = {
    "_schema_version": "test.v1",
    "waiver_file": ".auditooor/readme_step_waivers.txt",
    "steps": [
        {
            "step_id": "t-req-a", "label": "required step A", "class": "mechanical",
            "required": True, "language_filter": None,
            "what_must_be_done": "do A",
            "how_to_verify_done": {
                "artifact_checks": [{"type": "file_exists", "path": "A.md"}],
                "attestation_required": False,
            },
        },
        {
            "step_id": "t-adv", "label": "advisory step", "class": "conditional-mechanical",
            "required": False, "language_filter": None,
            "what_must_be_done": "do advisory",
            "how_to_verify_done": {
                "artifact_checks": [{"type": "file_exists", "path": "ADV.md"}],
                "attestation_required": False,
            },
        },
        {
            "step_id": "t-req-b", "label": "required step B", "class": "manual-judgment",
            "required": True, "language_filter": None,
            "what_must_be_done": "do B",
            "how_to_verify_done": {
                "artifact_checks": [{"type": "file_exists", "path": "B.md"}],
                "attestation_required": False,
            },
        },
    ],
}


class _StubGuard:
    """Stand-in for audit-done-guard: returns a fixed evaluate() verdict."""

    def __init__(self, done: bool, reason: str = "", fail_gates=None):
        self._done = done
        self._reason = reason
        self._fails = fail_gates or []

    def evaluate(self, ws, ttl_hours=6.0, **kw):
        return {"done": self._done, "reason": self._reason, "fail_gates": list(self._fails)}


class AuditNextStepTest(unittest.TestCase):
    def setUp(self):
        self.mod = _load()

    def _ws(self, tmp: str) -> Path:
        ws = Path(tmp)
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        return ws

    def _manifest_file(self, ws: Path) -> Path:
        mp = ws / "_test_manifest.json"
        mp.write_text(json.dumps(_MANIFEST), encoding="utf-8")
        return mp

    def test_first_unmet_required_and_split(self):
        """t-req-a satisfied, t-adv + t-req-b RED: next = t-req-b (first unmet
        REQUIRED in runbook order, NOT the earlier advisory t-adv); the split puts
        t-adv in advisory and t-req-b in required."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "A.md").write_text("x", encoding="utf-8")  # t-req-a PASS
            # ADV.md and B.md absent -> t-adv RED (advisory), t-req-b RED (required)
            mp = self._manifest_file(ws)
            res = self.mod.evaluate(
                ws, manifest_path=mp, guard_mod=_StubGuard(done=True),
            )
            self.assertIsNotNone(res["next_required_step"])
            self.assertEqual(res["next_required_step"]["id"], "t-req-b")
            self.assertEqual(res["next_required_step"]["kind"], "manual")
            self.assertEqual(res["next_required_step"]["what"], "do B")
            self.assertIn("file_exists(B.md)", res["next_required_step"]["verify"])
            # split
            req_ids = [r["id"] for r in res["red_required"]]
            adv_ids = [r["id"] for r in res["red_advisory"]]
            self.assertEqual(req_ids, ["t-req-b"])
            self.assertEqual(adv_ids, ["t-adv"])

    def test_rc1_when_required_red_even_if_guard_done(self):
        """A required RED step forces rc=1 regardless of the done-guard verdict."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "A.md").write_text("x", encoding="utf-8")  # only t-req-a passes
            mp = self._manifest_file(ws)
            res = self.mod.evaluate(
                ws, manifest_path=mp, guard_mod=_StubGuard(done=True),
            )
            self.assertFalse(res["all_required_pass"])
            self.assertEqual(res["rc"], 1)

    def test_rc0_when_all_pass_and_guard_done(self):
        """All required steps satisfied + done-guard DONE -> rc=0, no next step."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "A.md").write_text("x", encoding="utf-8")
            (ws / "B.md").write_text("x", encoding="utf-8")
            # advisory t-adv still RED, but advisory must NOT block rc
            mp = self._manifest_file(ws)
            res = self.mod.evaluate(
                ws, manifest_path=mp, guard_mod=_StubGuard(done=True, reason="ok"),
            )
            self.assertTrue(res["all_required_pass"])
            self.assertEqual(res["red_required"], [])
            self.assertEqual([r["id"] for r in res["red_advisory"]], ["t-adv"])
            self.assertIsNone(res["next_required_step"])
            self.assertEqual(res["rc"], 0)
            self.assertTrue(res["done_guard"]["done"])

    def test_required_pass_but_guard_not_done_rc1(self):
        """All required steps pass but the done-guard is NOT-DONE (a gate failed):
        rc=1, no next_required_step, and the guard FAIL reasons are surfaced."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "A.md").write_text("x", encoding="utf-8")
            (ws / "B.md").write_text("x", encoding="utf-8")
            mp = self._manifest_file(ws)
            res = self.mod.evaluate(
                ws, manifest_path=mp,
                guard_mod=_StubGuard(done=False, reason="stale pass",
                                     fail_gates=["readme-conformance:step-3"]),
            )
            self.assertTrue(res["all_required_pass"])
            self.assertIsNone(res["next_required_step"])
            self.assertEqual(res["rc"], 1)
            self.assertFalse(res["done_guard"]["done"])
            self.assertIn("readme-conformance:step-3", res["done_guard"]["fails"])
            self.assertTrue(res["done_guard"]["verdict"].startswith("NOT-DONE:"))

    def test_missing_workspace_rc2(self):
        res = self.mod.evaluate(Path("/nonexistent/ws/path/xyz"))
        self.assertEqual(res["rc"], 2)
        self.assertIn("error", res)


if __name__ == "__main__":
    unittest.main()
