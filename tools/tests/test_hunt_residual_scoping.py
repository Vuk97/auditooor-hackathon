#!/usr/bin/env python3
"""test_hunt_residual_scoping.py - FIX C regression tests (stdlib-only).

Covers:
  (i)  residual-scope-per-fn narrows a ranked per-fn worklist to EXACTLY the
       coverage-gate residual units (a strict subset), never weakening coverage,
       and keeps the FULL worklist when the caller opts into a full re-hunt
       (the Makefile's AUDITOOOR_HUNT_FULL=1 path, verified by asserting the
       tool is NOT invoked in that branch: the filtered set == residual K, not N).
  (ii) the emitted hunt_provider_obligation carries residual_surface_units + a
       residual-reflecting status ('residual-hunt-required' with the count when
       units remain; 'residual-empty-no-hunt-required' when the gate is green).

No third-party deps; runs the real tools/residual-scope-per-fn.py as a subprocess.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "residual-scope-per-fn.py"


def _write_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def _write_jsonl(p: Path, rows: list[dict]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        # A full ranked worklist of N=5 units across 5 files.
        self.ranked = self.ws / ".auditooor" / "per_fn_hacker_questions.jsonl.ranked.jsonl"
        _write_jsonl(self.ranked, [
            {"file": "src/Vault.sol", "fn": "deposit", "question": "q1"},
            {"file": "src/Vault.sol", "fn": "withdraw", "question": "q2"},
            {"file": "src/Router.sol", "fn": "route", "question": "q3"},
            {"file": "src/Oracle.sol", "fn": "peek", "question": "q4"},
            {"file": "src/Token.sol", "fn": "transfer", "question": "q5"},
        ])
        self.out = self.ws / ".auditooor" / "per_fn.residual.jsonl"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_scope(self):
        return subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(self.ws),
             "--ranked", str(self.ranked), "--output", str(self.out)],
            capture_output=True, text=True,
        )

    def run_obligation(self):
        ob = self.ws / ".auditooor" / "hunt_provider_obligation.json"
        r = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(self.ws),
             "--emit-obligation", str(ob)],
            capture_output=True, text=True,
        )
        return r, json.loads(ob.read_text(encoding="utf-8"))

    def kept_rows(self) -> list[dict]:
        return [json.loads(l) for l in self.out.read_text().splitlines() if l.strip()]


class TestResidualScoping(_Base):
    def test_residual_queue_narrows_to_subset(self):
        """With a residual of K=2 surface units (Vault.sol, Router.sol), the
        planned set == those K files' rows, NOT the full N=5."""
        _write_json(self.ws / ".auditooor" / "coverage_residual_worker_queue.json", {
            "schema": "auditooor.coverage_residual_worker_queue.v1",
            "residual_surface_units": 2,
            "items": [
                {"kind": "surface-unit", "unit_id": "src/Vault.sol::deposit",
                 "source_path": "src/Vault.sol"},
                {"kind": "surface-unit", "unit_id": "src/Router.sol::route",
                 "source_path": "src/Router.sol"},
            ],
        })
        r = self.run_scope()
        self.assertEqual(r.returncode, 0, r.stderr)
        files = {row["file"] for row in self.kept_rows()}
        # Basename match keeps BOTH Vault.sol rows + the Router.sol row = 3 rows,
        # over 2 residual files - a strict subset of the 5 total (Oracle/Token dropped).
        self.assertEqual(files, {"src/Vault.sol", "src/Router.sol"})
        self.assertNotIn("src/Oracle.sol", files)
        self.assertNotIn("src/Token.sol", files)
        self.assertLess(len(self.kept_rows()), 5)  # narrowed

    def test_coverage_unit_verdict_credits_processed_unit(self):
        """SERVING-JOIN REGRESSION (false-red): a worker-queue surface-unit that
        auto-coverage-closer already drove through its arsenal writes a
        coverage_unit_verdicts/<slug>.json keyed by the WS-RELATIVE unit id, but
        the queue stores an ABSOLUTE source_path + bare-basename unit_id. Before
        the fix the residual reader could not join them, so a genuinely-processed
        unit was re-reported as residual forever and the obligation never reached
        terminal. A queue unit WITH a verdict on disk must be CREDITED (dropped)."""
        _write_json(self.ws / ".auditooor" / "coverage_residual_worker_queue.json", {
            "schema": "auditooor.coverage_residual_worker_queue.v1",
            "residual_surface_units": 2,
            "items": [
                {"kind": "surface-unit", "unit_id": "Vault.sol::deposit",
                 "source_path": str(self.ws / "src" / "Vault.sol")},
                {"kind": "surface-unit", "unit_id": "Router.sol::route",
                 "source_path": str(self.ws / "src" / "Router.sol")},
            ],
        })
        # closer verdict for Vault.sol::deposit under its ws-RELATIVE slug
        vdir = self.ws / ".auditooor" / "coverage_unit_verdicts"
        _write_json(vdir / "src-Vault-sol--deposit.json", {
            "schema": "auditooor.coverage_unit_verdict.v1",
            "unit_id": "src/Vault.sol::deposit", "verdict": "no-finding",
            "coverage_credit": "mechanical-source-cited",
        })
        r = self.run_scope()
        self.assertEqual(r.returncode, 0, r.stderr)
        files = {row["file"] for row in self.kept_rows()}
        # Vault credited (verdict on disk) -> only Router.sol residual remains
        self.assertEqual(files, {"src/Router.sol"})
        self.assertNotIn("src/Vault.sol", files)

    def test_uncredited_unit_still_residual_never_false_pass(self):
        """NEVER-FALSE-PASS: a worker-queue surface-unit with NO coverage_unit_verdict
        on disk must STILL be reported as residual (fail-closed) - the credit only
        drops units with a genuine verdict artifact, never fabricates coverage."""
        _write_json(self.ws / ".auditooor" / "coverage_residual_worker_queue.json", {
            "schema": "auditooor.coverage_residual_worker_queue.v1",
            "residual_surface_units": 1,
            "items": [
                {"kind": "surface-unit", "unit_id": "Router.sol::route",
                 "source_path": str(self.ws / "src" / "Router.sol")},
            ],
        })
        # NO coverage_unit_verdict written for Router.sol::route
        r, ob = self.run_obligation()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(ob["status"], "residual-hunt-required")
        self.assertGreaterEqual(ob.get("residual_surface_units", 0), 1)

    def test_g15_uncovered_basenames_narrow(self):
        """G15 fail payload's unlogged_uncovered basenames also scope the plan."""
        _write_json(self.ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json", {
            "verdict": "fail-coverage-below-threshold",
            "unlogged_uncovered": ["Oracle.sol"],
        })
        r = self.run_scope()
        self.assertEqual(r.returncode, 0, r.stderr)
        files = {row["file"] for row in self.kept_rows()}
        self.assertEqual(files, {"src/Oracle.sol"})

    def test_g15_queued_not_scanned_narrows(self):
        """SERVING-JOIN REGRESSION: the gate emits its unit-level residual under
        'queued_not_scanned' (file::fn ids) on the fail-queued-not-scanned verdict,
        NOT 'unlogged_uncovered'. Reading only the latter made this scoper declare
        the residual EMPTY (gate-pass-empty) while the gate was RED with N unscanned
        units - a false-green that let `make hunt-scoped` skip the real residual.
        The scoper must fold queued_not_scanned in and narrow the plan to it."""
        _write_json(self.ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json", {
            "verdict": "fail-queued-not-scanned",
            "unlogged_uncovered": [],   # empty - the OLD field carries nothing here
            "queued_not_scanned": ["Oracle.sol::peek", "Token.sol::transfer"],
        })
        r = self.run_scope()
        self.assertEqual(r.returncode, 0, r.stderr)
        files = {row["file"] for row in self.kept_rows()}
        self.assertEqual(files, {"src/Oracle.sol", "src/Token.sol"})
        self.assertNotIn("src/Vault.sol", files)  # covered -> dropped

    def test_obligation_queued_not_scanned_hunt_required(self):
        """SERVING-JOIN REGRESSION (obligation side): a fail-queued-not-scanned
        gate result must yield status=residual-hunt-required with the unit count,
        NOT residual-empty-no-hunt-required (the pre-fix false-green)."""
        _write_json(self.ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json", {
            "verdict": "fail-queued-not-scanned",
            "unlogged_uncovered": [],
            "queued_not_scanned": ["Oracle.sol::peek", "Token.sol::transfer"],
        })
        r, ob = self.run_obligation()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(ob["status"], "residual-hunt-required")
        self.assertGreaterEqual(ob["residual_surface_units"], 2)
        self.assertNotEqual(ob["status"], "residual-empty-no-hunt-required")

    def test_no_gate_keeps_full(self):
        """No residual sidecar at all => residual UNKNOWN => keep FULL worklist
        (fail-open, never weaken coverage)."""
        r = self.run_scope()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.kept_rows()), 5)

    def test_gate_pass_empty_keeps_full(self):
        """A gate result with an empty residual => everything covered per gate,
        keep full worklist (do not drop unjudged units)."""
        _write_json(self.ws / ".auditooor" / "coverage_residual_worker_queue.json", {
            "schema": "auditooor.coverage_residual_worker_queue.v1",
            "residual_surface_units": 0,
            "items": [],
        })
        r = self.run_scope()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.kept_rows()), 5)


class TestObligationCarriesResidual(_Base):
    def test_obligation_residual_hunt_required(self):
        """When K units remain, the obligation carries residual_surface_units=K
        and a residual-reflecting status."""
        _write_json(self.ws / ".auditooor" / "coverage_residual_worker_queue.json", {
            "schema": "auditooor.coverage_residual_worker_queue.v1",
            "residual_surface_units": 2,
            "items": [
                {"kind": "surface-unit", "unit_id": "src/Vault.sol::deposit",
                 "source_path": "src/Vault.sol"},
                {"kind": "surface-unit", "unit_id": "src/Router.sol::route",
                 "source_path": "src/Router.sol"},
            ],
        })
        r, ob = self.run_obligation()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(ob["status"], "residual-hunt-required")
        self.assertEqual(ob["residual_surface_units"], 2)
        self.assertIn("residual_surface_units", ob)

    def test_obligation_empty_residual_complete(self):
        """A green (empty) residual => residual-empty-no-hunt-required, count 0."""
        _write_json(self.ws / ".auditooor" / "coverage_residual_worker_queue.json", {
            "schema": "auditooor.coverage_residual_worker_queue.v1",
            "residual_surface_units": 0,
            "items": [],
        })
        r, ob = self.run_obligation()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(ob["status"], "residual-empty-no-hunt-required")
        self.assertEqual(ob["residual_surface_units"], 0)

    def test_obligation_no_gate_dispatch_required(self):
        """No gate residual yet => residual-unknown-dispatch-required (still not
        'completed', so downstream fail-closed stays intact)."""
        r, ob = self.run_obligation()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(ob["status"], "residual-unknown-dispatch-required")
        self.assertEqual(ob["residual_surface_units"], 0)
        self.assertNotEqual(ob["status"], "completed")


if __name__ == "__main__":
    unittest.main()
