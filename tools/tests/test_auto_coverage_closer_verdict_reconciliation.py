# r36: lane AUTO-COVERAGE-CLOSER registered in .auditooor/agent_pathspec.json
"""Guard test for the RUN-VERDICT / coverage-fraction false-green in
tools/auto-coverage-closer.py.

ROOT CAUSE (regression this test locks down)
--------------------------------------------
The closer's bounded loop already terminates HONESTLY (the per-iter
``stop_reason`` reconciles to the strict L37 residual - see
test_auto_coverage_closer_coverage_notion.py). BUT the TOP-LEVEL run result
still lied:

  - ``result["verdict"]`` was HARDCODED to ``"pass-coverage-closed-or-fixpoint"``
    regardless of the strict axis.
  - ``result["final_coverage_fraction"]`` was the RAW heatmap fraction, which
    counts every ENUMERATED unit as covered and therefore reads ``1.0`` even
    when the strict L37 function-coverage gate reports hundreds/thousands of
    uncovered functions.

So on hyperbridge the closer emitted ``verdict=pass-coverage-closed-or-fixpoint``
with ``final_coverage_fraction=1.0`` while ``final_strict_uncovered_count=1914``
- a textbook false green (the #1 sin): the run CLAIMED coverage was closed while
the strict gate said it was not.

THE FIX (asserted here)
-----------------------
``_reconcile_run_verdict`` reconciles BOTH the run verdict and the reported
coverage fraction to the authoritative strict axis:

  1. NEGATIVE - strict OPEN: strict status ``ok`` with >=1 uncovered fn while the
     heatmap reads 1.0 -> verdict MUST be ``coverage-residual-open`` (never
     ``pass-coverage-closed-or-fixpoint``) and ``final_coverage_fraction`` MUST
     be < 1.0 (reconciled to the strict count), NEVER 1.0.
  2. NEGATIVE - strict UNRESOLVED: strict status ``failed`` (gate timed out /
     errored - the strict count is UNKNOWN) while the heatmap reads 1.0 ->
     verdict ``coverage-residual-open`` and ``final_coverage_fraction`` is
     ``None`` (no fraction may be claimed).
  3. POSITIVE control - strict GENUINELY CLOSED: status ``ok`` with 0 uncovered
     -> verdict ``pass-coverage-closed-or-fixpoint`` and the heatmap fraction is
     reported unchanged (the fix does NOT over-correct legitimate closes).
  4. POSITIVE control - strict UNAVAILABLE: gate tool missing -> treated as
     closed, exactly like the existing per-iter ``stop_reason`` guard.

The raw heatmap fraction is preserved in ``final_heatmap_coverage_fraction`` for
transparency; this test pins that the LYING value never leaks into the
authoritative ``final_coverage_fraction`` / ``verdict`` while the strict axis is
open or unknown.

This is an HONESTY reconciliation, never a gate weakening: the ONLY path to the
``pass-coverage-closed-or-fixpoint`` verdict / a 1.0 fraction requires the strict
axis to be genuinely closed (or the gate tool absent) - precisely the conditions
under which the heatmap 1.0 is itself honest. It cannot manufacture a green.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent


def _load(name: str, rel: str):
    path = TOOLS_DIR / rel
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


ACC = _load("acc_verdict_reconcile_under_test", "auto-coverage-closer.py")


class ReconcileUnitTest(unittest.TestCase):
    """Direct unit assertions on the pure reconciliation helper - no I/O, so the
    contract is pinned independently of the (slower) end-to-end run."""

    def test_strict_open_never_closed_never_full_fraction(self):
        # 1914 strict-uncovered (the hyperbridge number) of 5000 enumerated units,
        # heatmap over-credits to 1.0. MUST NOT claim closed; fraction MUST be
        # < 1.0 and reconciled to the strict count.
        verdict, frac = ACC._reconcile_run_verdict(
            strict_count=1914,
            strict_status=ACC.FCC_STATUS_OK,
            heatmap_fraction=1.0,
            total_units=5000,
        )
        self.assertEqual(verdict, ACC.VERDICT_RESIDUAL_OPEN)
        self.assertNotEqual(verdict, ACC.VERDICT_COVERAGE_CLOSED)
        self.assertIsNotNone(frac)
        self.assertLess(frac, 1.0)
        # reconciled = (5000 - 1914) / 5000
        self.assertAlmostEqual(frac, (5000 - 1914) / 5000, places=6)

    def test_strict_open_with_no_total_reports_unknown_fraction(self):
        # If the heatmap has no enumeration total to reconcile against, the
        # fraction is unknown (None) rather than a misleading 1.0.
        verdict, frac = ACC._reconcile_run_verdict(
            strict_count=10,
            strict_status=ACC.FCC_STATUS_OK,
            heatmap_fraction=1.0,
            total_units=0,
        )
        self.assertEqual(verdict, ACC.VERDICT_RESIDUAL_OPEN)
        self.assertIsNone(frac)

    def test_strict_open_fraction_never_exceeds_heatmap(self):
        # The reconciled fraction is also capped at the heatmap's own value: a
        # closer must never report MORE coverage than the (already over-crediting)
        # heatmap claimed.
        _verdict, frac = ACC._reconcile_run_verdict(
            strict_count=1,
            strict_status=ACC.FCC_STATUS_OK,
            heatmap_fraction=0.20,
            total_units=1000,
        )
        # (1000-1)/1000 = 0.999, but heatmap only claimed 0.20 -> cap at 0.20.
        self.assertLessEqual(frac, 0.20)

    def test_strict_failed_is_open_with_no_fraction(self):
        # Strict axis UNRESOLVED (timeout/error): count is unknown, so neither a
        # closed verdict nor any coverage fraction may be reported - even though
        # the heatmap says 1.0.
        verdict, frac = ACC._reconcile_run_verdict(
            strict_count=0,  # may be 0 ONLY because the probe failed - not real
            strict_status=ACC.FCC_STATUS_FAILED,
            heatmap_fraction=1.0,
            total_units=5000,
        )
        self.assertEqual(verdict, ACC.VERDICT_RESIDUAL_OPEN)
        self.assertIsNone(frac)

    def test_strict_count_none_is_open_with_no_fraction(self):
        verdict, frac = ACC._reconcile_run_verdict(
            strict_count=None,
            strict_status=ACC.FCC_STATUS_OK,
            heatmap_fraction=1.0,
            total_units=5000,
        )
        self.assertEqual(verdict, ACC.VERDICT_RESIDUAL_OPEN)
        self.assertIsNone(frac)

    def test_strict_closed_ok_reports_closed_and_keeps_heatmap(self):
        # POSITIVE control: genuine close (status ok, 0 uncovered) -> the heatmap
        # fraction is trustworthy, so it is reported unchanged and the verdict is
        # the legitimate coverage-closed value. The fix does NOT over-correct.
        verdict, frac = ACC._reconcile_run_verdict(
            strict_count=0,
            strict_status=ACC.FCC_STATUS_OK,
            heatmap_fraction=1.0,
            total_units=5000,
        )
        self.assertEqual(verdict, ACC.VERDICT_COVERAGE_CLOSED)
        self.assertEqual(frac, 1.0)

    def test_strict_unavailable_reports_closed(self):
        # POSITIVE control: gate tool absent -> matches the existing per-iter
        # stop_reason strict_axis_closed definition (unavailable == closed).
        verdict, frac = ACC._reconcile_run_verdict(
            strict_count=0,
            strict_status=ACC.FCC_STATUS_UNAVAILABLE,
            heatmap_fraction=1.0,
            total_units=5000,
        )
        self.assertEqual(verdict, ACC.VERDICT_COVERAGE_CLOSED)
        self.assertEqual(frac, 1.0)


class _EndToEndBase(unittest.TestCase):
    """Shared synthetic-ws harness for the full run() reconciliation assertions.

    Stubs the heatmap/G15 measurement notion to a perfect false green (cov=1.0,
    0 uncovered, rubric complete) - the exact production shape - and drives the
    strict axis via the _genuine_uncovered_units stub, so the only honest signal
    is the strict count. Mirrors the existing coverage-notion guard test setup.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        ws = Path(self.tmp.name) / "synth_ws"
        (ws / "src").mkdir(parents=True)
        (ws / ".auditooor").mkdir(parents=True)
        (ws / "src" / "vault.go").write_text(
            "package vault\nfunc WithdrawFunds() error { return nil }\n",
            encoding="utf-8",
        )
        self.ws = ws
        self._orig: dict = {}

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(ACC, k, v)
        self.tmp.cleanup()

    def _stub(self, name, fn):
        self._orig[name] = getattr(ACC, name)
        setattr(ACC, name, fn)

    def _stub_heatmap_full_green(self, total):
        self._stub("_rebuild_coverage_report", lambda ws: {
            "schema": "auditooor.workspace_coverage_report.v1",
            "workspace_name": "synth_ws", "total_units": total,
            "covered": total, "uncovered": 0, "uncovered_units": [],
            "coverage_fraction": 1.0,
        })
        self._stub("_read_g15_result", lambda ws, rid: {
            "verdict": "pass-coverage-met", "uncovered_count": 0,
            "coverage_fraction": 1.0, "unlogged_uncovered": []})
        self._stub("_read_rubric_uncovered",
                   lambda ws: ({"rows_uncovered": 0}, []))
        self._stub("_seed_surface", lambda ws, rid: {
            "rc": 0, "seed_rows_total": 0, "rows_written": 0,
            "rows_updated": 0, "verdict": "x"})
        self._stub("_seed_rubric", lambda ws, rid: {
            "rc": 0, "uncovered_rows_seeded": 0, "queue_rows_written": 0,
            "queue_rows_updated": 0, "seeded_briefs": [], "verdict": "x"})
        self._stub("_source_path_for_unit", lambda ws, u: u.partition("::")[0])

    @staticmethod
    def _strict_units(n):
        # token set fires an invariant anchor so the deterministic generator
        # emits >=1 question per unit (matches the sibling guard test).
        return ["src/vault.go::WithdrawFunds%03d" % k for k in range(n)]


class RunResultNoFalseGreenTest(_EndToEndBase):
    """End-to-end: the full run() result never reports a closed verdict / 1.0
    fraction while the strict axis is open or unknown."""

    def test_open_strict_axis_run_is_not_a_false_green(self):
        # 50 strict-uncovered fns (cap=10, 2 iters -> residual remains), heatmap
        # = perfect green. The result MUST be honest.
        N, total = 50, 80
        self._stub_heatmap_full_green(total)
        self._stub("_genuine_uncovered_units",
                   lambda ws: (self._strict_units(N), ACC.FCC_STATUS_OK))
        res = ACC.run(self.ws, max_iters=2, coverage_threshold=1.0, unit_cap=10)

        # the lie this guard pins: NOT closed, NOT 1.0, while strict_uncovered>0.
        self.assertEqual(res["verdict"], ACC.VERDICT_RESIDUAL_OPEN)
        self.assertNotEqual(res["verdict"], ACC.VERDICT_COVERAGE_CLOSED)
        self.assertGreater(res["final_strict_uncovered_count"], 0)
        self.assertIsNotNone(res["final_coverage_fraction"])
        self.assertLess(res["final_coverage_fraction"], 1.0)
        # the raw over-crediting heatmap value is preserved separately, never
        # leaked into the authoritative field.
        self.assertEqual(res["final_heatmap_coverage_fraction"], 1.0)

    def test_failed_strict_axis_run_is_not_a_false_green(self):
        self._stub_heatmap_full_green(80)
        self._stub("_genuine_uncovered_units",
                   lambda ws: ([], ACC.FCC_STATUS_FAILED))
        res = ACC.run(self.ws, max_iters=1, coverage_threshold=1.0, unit_cap=10)
        self.assertEqual(res["verdict"], ACC.VERDICT_RESIDUAL_OPEN)
        self.assertIsNone(res["final_coverage_fraction"])
        self.assertEqual(res["final_heatmap_coverage_fraction"], 1.0)

    def test_genuine_close_run_still_reports_closed(self):
        # POSITIVE control: strict ran clean (ok, 0 uncovered) -> the run is
        # genuinely closed; the verdict + 1.0 fraction are legitimate here.
        self._stub_heatmap_full_green(3)
        self._stub("_genuine_uncovered_units",
                   lambda ws: ([], ACC.FCC_STATUS_OK))
        res = ACC.run(self.ws, max_iters=1, coverage_threshold=1.0, unit_cap=10)
        self.assertEqual(res["verdict"], ACC.VERDICT_COVERAGE_CLOSED)
        self.assertEqual(res["final_coverage_fraction"], 1.0)
        self.assertEqual(res["final_strict_uncovered_count"], 0)

    def test_constants_are_distinct(self):
        # the two verdicts must be different strings, else the reconciliation is
        # a no-op.
        self.assertNotEqual(
            ACC.VERDICT_COVERAGE_CLOSED, ACC.VERDICT_RESIDUAL_OPEN
        )
        # the closed verdict keeps the historical string so existing consumers
        # that recognise it are not broken.
        self.assertEqual(
            ACC.VERDICT_COVERAGE_CLOSED, "pass-coverage-closed-or-fixpoint"
        )


if __name__ == "__main__":
    unittest.main()
