#!/usr/bin/env python3
"""Regression: hunt-obligation-resolve credits the CANONICAL per-fn hunt.

SEI 2026-07-04 serving-join false-red: `_count_residual_sidecars` counted ONLY
`mimo_harness_<ws>_<NNNN>` sidecars (the legacy `make hunt-residual-llm-depth`
path) and deliberately excluded the per-fn `hunt__<basename>__<fn>__...json`
sidecars. But the CANONICAL step-3 flow (`make hunt-scoped` -> dispatch
agent_batch_*.md) is residual-scoped to the SAME units and emits exactly those
per-fn sidecars - so the canonical path could never resolve its own
consent-required residual-llm-depth obligation (37/37 residual units genuinely
hunted, resolver saw 0). Fix credits per-fn sidecars matched to the EXACT
residual (basename, fn) units. These tests pin both the credit AND the
false-green-safety (non-residual / hollow sidecars contribute nothing).
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "hor", str(Path(__file__).resolve().parent.parent / "hunt-obligation-resolve.py"))
hor = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(hor)


def _mk_ws(tmp: Path, residual_units, sidecars) -> Path:
    """residual_units: list[(basename, fn)]; sidecars: list[(filename, obj|None)]
    where obj=None writes a hollow (no-verdict) sidecar."""
    ws = tmp / "ws"
    ad = ws / ".auditooor"
    (ad / "hunt_findings_sidecars").mkdir(parents=True)
    queue = {
        "schema": "auditooor.coverage_residual_worker_queue.v1",
        "workspace": "ws", "workspace_path": str(ws),
        "residual_surface_units": len(residual_units),
        "items": [
            {"kind": "surface-unit",
             "unit_id": f"src/pkg/{base}::{fn}",
             "source_path": str(ws / "src" / "pkg" / base)}
            for base, fn in residual_units
        ],
    }
    (ad / "coverage_residual_worker_queue.json").write_text(json.dumps(queue), encoding="utf-8")
    for fname, obj in sidecars:
        body = json.dumps(obj) if obj is not None else json.dumps({"notes": "hollow, no verdict"})
        (ad / "hunt_findings_sidecars" / fname).write_text(body, encoding="utf-8")
    return ws


VERDICT = {"applies_to_target": "no", "confidence": "high"}


class PerFnResidualCreditTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_residual_surface_units_parsed(self):
        # DIRECTORY-AWARE contract (2026-07-10): keyed by the full ws-relative
        # source path (src/pkg/<base>), NOT the bare basename, so same-named files
        # in sibling dirs are distinct units.
        ws = _mk_ws(self.tmp, [("a.go", "Foo"), ("b.go", "Bar")], [])
        self.assertEqual(hor._residual_surface_units(ws),
                         {("src/pkg/a.go", "Foo"), ("src/pkg/b.go", "Bar")})

    def test_perfn_hit_counts_matching_genuine_sidecar(self):
        ws = _mk_ws(self.tmp,
                    [("a.go", "Foo"), ("b.go", "Bar")],
                    [("hunt__a.go__Foo__deadbeef__I-generic.json", VERDICT),
                     ("hunt__b.go__Bar__deadbeef__I-generic.json", VERDICT)])
        self.assertEqual(hor._count_perfn_residual_hits(ws), 2)

    def test_hollow_sidecar_not_credited(self):
        # a matching (basename,fn) but NO verdict signal must not count
        ws = _mk_ws(self.tmp,
                    [("a.go", "Foo"), ("b.go", "Bar")],
                    [("hunt__a.go__Foo__deadbeef__I-generic.json", VERDICT),
                     ("hunt__b.go__Bar__deadbeef__I-generic.json", None)])
        self.assertEqual(hor._count_perfn_residual_hits(ws), 1)

    def test_non_residual_sidecar_not_credited(self):
        # false-green-safety: a genuine per-fn sidecar for a NON-residual unit
        # must contribute zero
        ws = _mk_ws(self.tmp,
                    [("a.go", "Foo")],
                    [("hunt__zzz.go__Other__deadbeef__I-generic.json", VERDICT)])
        self.assertEqual(hor._count_perfn_residual_hits(ws), 0)

    def test_distinct_units_not_double_counted(self):
        # two sidecars (different impact frames) for the SAME residual unit = 1
        ws = _mk_ws(self.tmp,
                    [("a.go", "Foo")],
                    [("hunt__a.go__Foo__deadbeef__I-generic.json", VERDICT),
                     ("hunt__a.go__Foo__deadbeef__I-bc-consensus.json", VERDICT)])
        self.assertEqual(hor._count_perfn_residual_hits(ws), 1)

    def test_no_queue_returns_zero(self):
        ws = self.tmp / "empty"
        (ws / ".auditooor" / "hunt_findings_sidecars").mkdir(parents=True)
        self.assertEqual(hor._count_perfn_residual_hits(ws), 0)
        self.assertEqual(hor._residual_surface_units(ws), set())

    def _mk_ws_full(self, units, sidecars):
        """units: list[(relpath, fn)]; sidecars: list[(filename, anchor_relpath|None, has_verdict)]"""
        ws = self.tmp / "wsf"
        ad = ws / ".auditooor"
        (ad / "hunt_findings_sidecars").mkdir(parents=True)
        queue = {"schema": "auditooor.coverage_residual_worker_queue.v1",
                 "workspace": "wsf", "workspace_path": str(ws),
                 "residual_surface_units": len(units),
                 "items": [{"kind": "surface-unit", "unit_id": f"{rel}::{fn}",
                            "source_path": str(ws / rel)} for rel, fn in units]}
        (ad / "coverage_residual_worker_queue.json").write_text(json.dumps(queue), encoding="utf-8")
        for fname, anchor, hasv in sidecars:
            obj = {}
            if anchor is not None:
                obj["function_anchor"] = {"file": anchor}
            if hasv:
                obj["applies_to_target"] = "no"
            (ad / "hunt_findings_sidecars" / fname).write_text(json.dumps(obj), encoding="utf-8")
        return ws

    def test_cross_dir_same_basename_anchored_credits_only_exact_dir(self):
        # evm/X.sol::f and evm-v1/X.sol::f share a basename; a sidecar ANCHORED to
        # evm/X.sol credits ONLY the evm/ unit - the OOS v1 unit stays uncovered
        # (the basename false-green this directory-aware fix closes).
        ws = self._mk_ws_full(
            [("src/evm/X.sol", "f"), ("src/evm-v1/X.sol", "f")],
            [("hunt__X.sol__f__d__I-generic.json", "src/evm/X.sol", True)])
        self.assertEqual(hor._count_perfn_residual_hits(ws), 1)

    def test_anchorless_ambiguous_basename_credits_neither(self):
        # two residual units share basename+fn; an ANCHORLESS sidecar cannot be
        # attributed to either -> credits NEITHER (false-green-safe).
        ws = self._mk_ws_full(
            [("src/evm/X.sol", "f"), ("src/evm-v1/X.sol", "f")],
            [("hunt__X.sol__f__d__I-generic.json", None, True)])
        self.assertEqual(hor._count_perfn_residual_hits(ws), 0)

    def test_threshold_from_live_queue_supersedes_stale_inflated_file(self):
        # obligation-file residual_surface_units is stale + OOS-inflated (41) while
        # the live OOS-pruned queue has 2 units, both genuinely hunted -> resolves
        # on the LIVE count, not the unreachable file snapshot.
        ws = self._mk_ws_full(
            [("src/evm/A.sol", "f"), ("src/evm/B.sol", "g")],
            [("hunt__A.sol__f__d__I-generic.json", "src/evm/A.sol", True),
             ("hunt__B.sol__g__d__I-generic.json", "src/evm/B.sol", True)])
        obl = {"schema": "auditooor.hunt_provider_obligation.v1",
               "hunt_provider": "residual-llm-depth", "status": "consent-required",
               "residual_surface_units": 41}
        (ws / ".auditooor" / "hunt_provider_obligation.json").write_text(
            json.dumps(obl), encoding="utf-8")
        res = hor.resolve(ws)
        self.assertTrue(res["completed"], res.get("reason"))
        self.assertEqual(res["threshold"], 2)
        self.assertEqual(res.get("threshold_source"), "live-queue")

    def test_resolve_completes_when_perfn_covers_residual(self):
        ws = _mk_ws(self.tmp,
                    [("a.go", "Foo"), ("b.go", "Bar")],
                    [("hunt__a.go__Foo__x__I-generic.json", VERDICT),
                     ("hunt__b.go__Bar__x__I-generic.json", VERDICT)])
        obl = {"schema": "auditooor.hunt_provider_obligation.v1",
               "hunt_provider": "residual-llm-depth", "status": "consent-required",
               "residual_surface_units": 2}
        (ws / ".auditooor" / "hunt_provider_obligation.json").write_text(
            json.dumps(obl), encoding="utf-8")
        res = hor.resolve(ws)
        self.assertTrue(res["completed"], res.get("reason"))
        after = json.loads((ws / ".auditooor" / "hunt_provider_obligation.json").read_text())
        self.assertEqual(after["status"], "completed")

    def test_resolve_stays_red_when_residual_uncovered(self):
        # never-false-pass: one residual unit unhunted -> stays consent-required
        ws = _mk_ws(self.tmp,
                    [("a.go", "Foo"), ("b.go", "Bar")],
                    [("hunt__a.go__Foo__x__I-generic.json", VERDICT)])
        obl = {"schema": "auditooor.hunt_provider_obligation.v1",
               "hunt_provider": "residual-llm-depth", "status": "consent-required",
               "residual_surface_units": 2}
        (ws / ".auditooor" / "hunt_provider_obligation.json").write_text(
            json.dumps(obl), encoding="utf-8")
        res = hor.resolve(ws)
        self.assertFalse(res["completed"])
        after = json.loads((ws / ".auditooor" / "hunt_provider_obligation.json").read_text())
        self.assertEqual(after["status"], "consent-required")


if __name__ == "__main__":
    unittest.main()
