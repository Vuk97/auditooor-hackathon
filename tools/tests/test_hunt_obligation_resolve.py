#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-HUNT-OBLIGATION-RESOLVE registered via agent-pathspec-register.py -->
"""Guard: hunt-obligation-resolve marks a dispatch-required obligation
`completed` ONLY when genuine verdict sidecars exist, and never otherwise.

The load-bearing negative cases: an obligation with ZERO sidecars (hunt queued
but never dispatched) must STAY dispatch-required (no false-green), and a
consent-required obligation must be left untouched.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("hor", str(_TOOLS / "hunt-obligation-resolve.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["hor"] = m
spec.loader.exec_module(m)


def _ws() -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    return ws


def _obl(ws: Path, status="orchestrator-dispatch-required"):
    (ws / ".auditooor" / "hunt_provider_obligation.json").write_text(
        json.dumps({"schema": "auditooor.hunt_provider_obligation.v1",
                    "hunt_provider": "agent-via-orchestrator", "status": status}),
        encoding="utf-8")


def _sidecars(ws: Path, n: int, with_verdict=True):
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    d.mkdir(exist_ok=True)
    for i in range(n):
        body = {"task_id": f"t{i}"}
        if with_verdict:
            body["result"] = json.dumps({"applies_to_target": "no", "confidence": "high"})
        (d / f"sc_{i}.json").write_text(json.dumps(body), encoding="utf-8")

def _status(ws: Path) -> str:
    return json.loads((ws / ".auditooor" / "hunt_provider_obligation.json")
                      .read_text())["status"]


class TestHuntObligationResolve(unittest.TestCase):
    def test_genuine_sidecars_mark_completed(self):
        ws = _ws(); _obl(ws); _sidecars(ws, 6, with_verdict=True)
        r = m.resolve(ws, min_sidecars=6)
        self.assertTrue(r["completed"], r["reason"])
        self.assertEqual(r["action"], "completed")
        self.assertEqual(_status(ws), "completed")
        # evidence embedded, not a bare flip
        ev = json.loads((ws / ".auditooor" / "hunt_provider_obligation.json").read_text())
        self.assertIn("resolution", ev)
        self.assertGreaterEqual(ev["resolution"]["genuine_verdict_sidecars"], 6)

    def test_residual_empty_with_pending_dispatch_resolves_from_sidecars(self):
        """A stale residual-empty label must not block genuine dispatch evidence."""
        ws = _ws()
        (ws / ".auditooor" / "hunt_provider_obligation.json").write_text(
            json.dumps({"schema": "auditooor.hunt_provider_obligation.v1",
                        "hunt_provider": "agent-via-orchestrator",
                        "status": "residual-empty-no-hunt-required",
                        "residual_surface_units": 0,
                        "next": ["dispatch each agent_batch_*.md via Agent(model=sonnet)",
                                  "make mimo-corpus-mine WS=<ws>"]}),
            encoding="utf-8")
        _sidecars(ws, 2, with_verdict=True)
        r = m.resolve(ws, min_sidecars=1)
        self.assertTrue(r["completed"], r["reason"])
        self.assertEqual(_status(ws), "completed")

    def test_zero_sidecars_stays_required_no_false_green(self):
        ws = _ws(); _obl(ws)  # NO sidecars
        r = m.resolve(ws, min_sidecars=1)
        self.assertFalse(r["completed"])
        self.assertEqual(r["action"], "still-required")
        self.assertEqual(_status(ws), "orchestrator-dispatch-required")

    def test_verdictless_sidecars_dont_count(self):
        ws = _ws(); _obl(ws); _sidecars(ws, 5, with_verdict=False)
        r = m.resolve(ws, min_sidecars=1)
        self.assertFalse(r["completed"], "sidecars with no verdict must not earn completion")
        self.assertEqual(_status(ws), "orchestrator-dispatch-required")

    def test_aggregate_jsonl_sidecars_count(self):
        # Agent-dispatched step-3 hunts (the README-endorsed path) emit ONE
        # aggregate *.jsonl per batch with many verdict rows - these must verify
        # the obligation, not just the canonical per-verdict *.json from verdict-sink.
        ws = _ws(); _obl(ws)
        d = ws / ".auditooor" / "hunt_findings_sidecars"; d.mkdir(exist_ok=True)
        for b in range(3):
            rows = [json.dumps({"unit_id": f"fn{b}_{i}", "verdict": "REJECTED",
                                "in_scope": True}) for i in range(4)]
            (d / f"batch_{b}_verdicts.jsonl").write_text("\n".join(rows) + "\n",
                                                         encoding="utf-8")
        r = m.resolve(ws, min_sidecars=1)
        self.assertTrue(r["completed"], r["reason"])
        self.assertEqual(_status(ws), "completed")
        ev = json.loads((ws / ".auditooor" / "hunt_provider_obligation.json").read_text())
        self.assertEqual(ev["resolution"]["genuine_verdict_sidecars"], 3)

    def test_empty_jsonl_sidecar_does_not_count(self):
        # an aggregate jsonl with no verdict-bearing line must NOT earn completion
        ws = _ws(); _obl(ws)
        d = ws / ".auditooor" / "hunt_findings_sidecars"; d.mkdir(exist_ok=True)
        (d / "empty_verdicts.jsonl").write_text(
            json.dumps({"unit_id": "x", "note": "no verdict here"}) + "\n", encoding="utf-8")
        r = m.resolve(ws, min_sidecars=1)
        self.assertFalse(r["completed"])
        self.assertEqual(_status(ws), "orchestrator-dispatch-required")

    def test_consent_required_left_untouched(self):
        # consent-required WITHOUT residual_surface_units = a pure operator-consent
        # gate; never auto-resolved regardless of unrelated sidecars.
        ws = _ws(); _obl(ws, status="consent-required"); _sidecars(ws, 9)
        r = m.resolve(ws, min_sidecars=1)
        self.assertEqual(r["action"], "left-untouched")
        self.assertEqual(_status(ws), "consent-required")

    def test_absent_obligation_is_pass(self):
        ws = _ws()  # no obligation file at all
        r = m.resolve(ws)
        self.assertTrue(r["completed"])
        self.assertEqual(r["action"], "no-obligation")

    def test_already_completed_refreshes_even_without_prior_provenance(self):
        ws = _ws(); _obl(ws, status="completed")
        with mock.patch.object(m, "_dispatch_provenance", return_value={
            "verdict": "not-applicable",
            "reason": "no scoped dispatch plan",
        }):
            r = m.resolve(ws)
        self.assertTrue(r["completed"])
        self.assertEqual(r["action"], "refreshed-provenance")
        ev = json.loads((ws / ".auditooor" / "hunt_provider_obligation.json").read_text())
        self.assertEqual(ev["dispatch_provenance"], "not-applicable")

    def test_completed_refreshes_dispatch_provenance(self):
        ws = _ws(); _obl(ws, status="completed")
        with mock.patch.object(m, "_dispatch_provenance", return_value={
            "verdict": "pass-hunt-dispatch-logged",
            "reason": "provider receipt verified",
        }):
            r = m.resolve(ws)
        self.assertTrue(r["completed"], r["reason"])
        self.assertEqual(r["action"], "refreshed-provenance")
        ev = json.loads((ws / ".auditooor" / "hunt_provider_obligation.json").read_text())
        self.assertEqual(ev["dispatch_provenance"], "pass-hunt-dispatch-logged")

    def test_completed_provenance_failure_blocks_without_strict_env(self):
        ws = _ws(); _obl(ws, status="completed")
        # The provenance guard is patched at the module seam so this test does
        # not need a plan or receipt artifact in the repository corpus.
        with mock.patch.dict(os.environ, {}, clear=False), mock.patch.object(
            m,
            "_dispatch_provenance",
            return_value={
                "verdict": "fail-hunt-dispatch-unlogged",
                "reason": "synthetic missing receipt",
            },
        ):
            os.environ.pop("AUDITOOOR_HUNT_DISPATCH_STRICT", None)
            r = m.resolve(ws)
        self.assertFalse(r["completed"])
        self.assertEqual(r["action"], "blocked-dispatch-unlogged")
        self.assertEqual(r["dispatch_provenance"], "fail-hunt-dispatch-unlogged")
        self.assertIn("synthetic missing receipt", r["reason"])

    def test_dry_run_does_not_write(self):
        ws = _ws(); _obl(ws); _sidecars(ws, 3)
        with mock.patch.object(m, "_dispatch_provenance", return_value={
            "verdict": "pass-hunt-dispatch-logged",
            "reason": "provider receipt verified",
        }):
            r = m.resolve(ws, min_sidecars=1, dry_run=True)
        self.assertTrue(r["completed"])
        self.assertEqual(r["action"], "would-complete")
        self.assertEqual(_status(ws), "orchestrator-dispatch-required")


# --- residual-llm-depth consent path (provider-agnostic resolution) ----------
# When the residual hunt runs via the Agent tool (local-CLI provider, used when
# the mimo API is 429 / key-less), workflow-drill-sidecar-emit writes sidecars
# named mimo_harness_<wsname>_<NNNN>.json under the REPO derived dir. These must
# resolve a consent-required residual obligation - but ONLY them, and ONLY when
# >= residual_surface_units genuine verdicts exist (no false-green).
import shutil  # noqa: E402

_DERIVED = _TOOLS.parent / "audit" / "corpus_tags" / "derived"


def _resid_obl(ws: Path, residual_surface_units: int):
    (ws / ".auditooor" / "hunt_provider_obligation.json").write_text(
        json.dumps({"schema": "auditooor.hunt_provider_obligation.v1",
                    "hunt_provider": "residual-llm-depth", "status": "consent-required",
                    "residual_surface_units": residual_surface_units}),
        encoding="utf-8")


def _emit_residual_sidecars(ws: Path, n: int, with_verdict=True, residual_named=True):
    """Write n sidecars under <repo>/audit/.../mimo_harness_<wsname>_test/.

    residual_named=True -> mimo_harness_<wsname>_<NNNN>.json (counts for residual).
    residual_named=False -> <wsname>-bNNNN-fn.json (per-fn; must NOT count residual).
    Returns the created dir for cleanup.
    """
    wsname = ws.name
    d = _DERIVED / f"mimo_harness_{wsname}_test"
    d.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        body = {"status": "ok", "task_id": f"x{i}", "source": "workflow-drill-sidecar-emit"}
        if with_verdict:
            body["result"] = json.dumps({"verdict": "KILL", "applies_to_target": "no"})
        name = (f"mimo_harness_{wsname}_{i:04d}.json" if residual_named
                else f"{wsname}-b{i:04d}-someFn.json")
        (d / name).write_text(json.dumps(body), encoding="utf-8")
    return d


class TestResidualConsentResolution(unittest.TestCase):
    def setUp(self):
        self._dirs = []

    def tearDown(self):
        for d in self._dirs:
            shutil.rmtree(d, ignore_errors=True)

    def test_residual_sidecars_resolve_consent(self):
        ws = _ws(); _resid_obl(ws, 8)
        self._dirs.append(_emit_residual_sidecars(ws, 8, with_verdict=True))
        r = m.resolve(ws)
        self.assertTrue(r["completed"], r["reason"])
        self.assertEqual(r["action"], "completed")
        self.assertEqual(_status(ws), "completed")
        ev = json.loads((ws / ".auditooor" / "hunt_provider_obligation.json").read_text())
        self.assertEqual(ev["resolution"]["path"], "consent-required-residual-llm-depth")
        self.assertGreaterEqual(ev["resolution"]["genuine_residual_verdict_sidecars"], 8)

    def test_too_few_residual_sidecars_stays_consent(self):
        ws = _ws(); _resid_obl(ws, 10)
        self._dirs.append(_emit_residual_sidecars(ws, 4, with_verdict=True))
        r = m.resolve(ws)
        self.assertFalse(r["completed"], "4 < 10 residual must not earn completion")
        self.assertEqual(r["action"], "still-required")
        self.assertEqual(_status(ws), "consent-required")

    def test_perfn_sidecars_do_not_satisfy_residual(self):
        # per-fn (non-residual-named) sidecars must NOT resolve the residual
        # obligation - the load-bearing anti-false-green property.
        ws = _ws(); _resid_obl(ws, 5)
        self._dirs.append(_emit_residual_sidecars(ws, 20, with_verdict=True,
                                                  residual_named=False))
        r = m.resolve(ws)
        self.assertFalse(r["completed"], "per-fn sidecars must not satisfy residual obligation")
        self.assertEqual(r["action"], "still-required")
        self.assertEqual(_status(ws), "consent-required")

    def test_verdictless_residual_sidecars_dont_count(self):
        ws = _ws(); _resid_obl(ws, 6)
        self._dirs.append(_emit_residual_sidecars(ws, 6, with_verdict=False))
        r = m.resolve(ws)
        self.assertFalse(r["completed"])
        self.assertEqual(_status(ws), "consent-required")


if __name__ == "__main__":
    unittest.main(verbosity=2)
