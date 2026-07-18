# r36: lane AUTO-COVERAGE-CLOSER registered in .auditooor/agent_pathspec.json
"""Guard test for the COVERAGE-NOTION false-green in tools/auto-coverage-closer.py.

ROOT CAUSE (regression this test locks down)
--------------------------------------------
workspace-coverage-heatmap.py --coverage-report writes coverage_report.json
with coverage_fraction=1.0 because it counts every ENUMERATED unit as
"covered". auto-coverage-closer.py read that, saw 1.0, and declared the
coverage axis closed - even though NO unit had a real per-function attack
verdict. The strict L37 gate (function-coverage-completeness --emit-worklist)
is the authoritative notion (it counts a function "covered" only when it is a
``real-attack``), but the closer shelled it under a fixed 180s timeout and
swallowed any TimeoutExpired / parse error into a bare ``return []`` - so on a
large workspace the strict uncovered set silently vanished and the trivial
enumeration notion produced a FALSE GREEN
(stop_reason=coverage-threshold-met-and-rubric-complete).

This guard asserts, over a SMALL synthetic workspace (so it does not depend on
the slow full fcc run that is being optimised in parallel):

  1. POSITIVE: over a real uncovered external fn, the closer drives a per-unit
     hunt and folds >=1 per_fn hacker question over the uncovered fn.
  2. STATUS HONESTY: a strict-gate timeout/failure returns FCC_STATUS_FAILED
     (NOT a covered-looking empty list).
  3. NO FALSE GREEN: when the heatmap says coverage_fraction=1.0 but the strict
     gate reports >=1 uncovered fn, the closer does NOT declare
     coverage-threshold-met-and-rubric-complete.
  4. NO FALSE GREEN ON FAILURE: when the heatmap says 1.0 and the strict gate
     FAILED (unknown), the closer still does NOT declare coverage met off the
     heatmap alone.
"""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import subprocess
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


ACC = _load("acc_cov_notion_under_test", "auto-coverage-closer.py")


@contextlib.contextmanager
def _generous_fcc_timeout(seconds: int = 600):
    """Reload ACC's FCC_WORKLIST_TIMEOUT from a high env budget so a loaded
    machine cannot time the (sub-second) synthetic fcc run out. Restores the
    original value on exit. Touches ONLY the module constant, not behavior."""
    prev_env = os.environ.get("AUDITOOOR_ACC_TIMEOUT_FCC_WORKLIST")
    prev_const = ACC.FCC_WORKLIST_TIMEOUT
    os.environ["AUDITOOOR_ACC_TIMEOUT_FCC_WORKLIST"] = str(seconds)
    ACC.FCC_WORKLIST_TIMEOUT = seconds
    try:
        yield
    finally:
        ACC.FCC_WORKLIST_TIMEOUT = prev_const
        if prev_env is None:
            os.environ.pop("AUDITOOOR_ACC_TIMEOUT_FCC_WORKLIST", None)
        else:
            os.environ["AUDITOOOR_ACC_TIMEOUT_FCC_WORKLIST"] = prev_env


def _mk_synthetic_ws(tmp: Path) -> Path:
    """A tiny Go workspace: one external entry fn (no harness) + a helper."""
    ws = tmp / "synth_ws"
    (ws / "src").mkdir(parents=True)
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "src" / "vault.go").write_text(
        "package vault\n\n"
        "// Withdraw moves funds out - external entry, no harness.\n"
        "func Withdraw(amount uint64, recipient string) error {\n"
        "\tif amount == 0 {\n\t\treturn nil\n\t}\n"
        "\treturn transfer(recipient, amount)\n}\n\n"
        "func transfer(to string, amt uint64) error {\n\treturn nil\n}\n",
        encoding="utf-8",
    )
    (ws / "src" / "admin.go").write_text(
        "package vault\n\n"
        "// SetOwner is an admin entry - external, no harness.\n"
        "func SetOwner(newOwner string) error {\n\treturn nil\n}\n",
        encoding="utf-8",
    )
    return ws


def _mk_full_coverage_report(ws: Path, n_units: int = 3) -> None:
    """Write the trivial enumeration=covered heatmap report: every enumerated
    unit credited, coverage_fraction=1.0, uncovered_units=[] - the exact shape
    the heatmap emits and the closer historically over-trusted."""
    report = {
        "schema": "auditooor.workspace_coverage_report.v1",
        "workspace_name": "synth_ws",
        "total_units": n_units,
        "covered": n_units,
        "uncovered": 0,
        "uncovered_units": [],
        "uncovered_units_truncated": False,
        "coverage_fraction": 1.0,
        "source_freshness": {},
        "numerator_freshness": {},
        "enumeration": {"source_root": ""},
    }
    (ws / ".auditooor" / "coverage_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )


class StrictUncoveredStatusTest(unittest.TestCase):
    """Item 2: the strict-uncovered probe returns a load-bearing status; a
    failure/timeout is NOT a covered-looking empty."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = _mk_synthetic_ws(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_ok_status_returns_real_uncovered_units(self):
        # Give the strict gate a generous budget so a loaded CI machine cannot
        # spuriously time the tiny synthetic fcc run out (the synthetic ws fcc
        # run is sub-second; this only guards against contention).
        with _generous_fcc_timeout():
            units, status = ACC._genuine_uncovered_units(self.ws)
        self.assertEqual(status, ACC.FCC_STATUS_OK)
        # the external entry fn(s) have no harness -> strictly uncovered
        self.assertTrue(units, "expected >=1 strictly-uncovered unit")
        self.assertTrue(
            any("Withdraw" in u for u in units),
            "external entry Withdraw must be in the strict uncovered set",
        )

    def test_timeout_returns_failed_not_empty_covered(self):
        # Simulate fcc exceeding its budget: the probe MUST surface FAILED, not
        # a [] that the caller would mistake for "genuinely covered".
        orig_run = ACC.subprocess.run

        def fake_run(*a, **k):
            raise subprocess.TimeoutExpired(cmd="fcc", timeout=1)

        ACC.subprocess.run = fake_run
        try:
            units, status = ACC._genuine_uncovered_units(self.ws)
        finally:
            ACC.subprocess.run = orig_run
        self.assertEqual(units, [])
        self.assertEqual(status, ACC.FCC_STATUS_FAILED)
        # the load-bearing invariant: failed != ok-empty
        self.assertNotEqual(status, ACC.FCC_STATUS_OK)

    def test_unparseable_output_returns_failed(self):
        orig_run = ACC.subprocess.run

        class _CP:
            returncode = 0
            stdout = "not json at all\n"
            stderr = ""

        ACC.subprocess.run = lambda *a, **k: _CP()
        try:
            units, status = ACC._genuine_uncovered_units(self.ws)
        finally:
            ACC.subprocess.run = orig_run
        self.assertEqual(units, [])
        self.assertEqual(status, ACC.FCC_STATUS_FAILED)


class PerUnitHuntOverUncoveredTest(unittest.TestCase):
    """Item 1: the closer drives a per-unit hunt + emits >=1 per_fn question
    over the genuinely-uncovered external fn, even though the heatmap says
    coverage_fraction=1.0."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = _mk_synthetic_ws(Path(self.tmp.name))
        _mk_full_coverage_report(self.ws)
        # Deterministic strict-uncovered set so this end-to-end assertion does
        # NOT depend on fcc subprocess timing (the real fcc ok path is covered
        # by StrictUncoveredStatusTest). The units below are genuinely external
        # entry fns in the synthetic ws with no harness.
        self._orig_genuine = ACC._genuine_uncovered_units
        ACC._genuine_uncovered_units = lambda ws: (
            ["src/vault.go::Withdraw", "src/admin.go::SetOwner"],
            ACC.FCC_STATUS_OK,
        )

    def tearDown(self):
        ACC._genuine_uncovered_units = self._orig_genuine
        self.tmp.cleanup()

    def test_closer_drives_per_unit_hunt_and_folds_questions(self):
        res = ACC.run(self.ws, max_iters=1, coverage_threshold=1.0, unit_cap=400)
        per_unit = res["iters"][0]["per_unit_hunt"]
        # a per-unit hunt actually ran over the uncovered set (not 0 units)
        self.assertGreaterEqual(per_unit["units_processed"], 1)
        # >=1 per_fn hacker question was folded for the L37 gate to credit
        hq = res["per_fn_hacker_questions"]
        self.assertGreaterEqual(hq["records"], 1)
        # the folded JSONL actually exists with >=1 line
        jsonl = self.ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        self.assertTrue(jsonl.is_file())
        lines = [ln for ln in jsonl.read_text().splitlines() if ln.strip()]
        self.assertGreaterEqual(len(lines), 1)
        # the strict uncovered count is surfaced and non-zero
        self.assertEqual(res["final_strict_uncovered_status"], ACC.FCC_STATUS_OK)
        self.assertGreaterEqual(res["final_strict_uncovered_count"], 1)


class NoFalseGreenTest(unittest.TestCase):
    """Items 3 + 4: the trivial enumeration notion (coverage_fraction=1.0) can
    NEVER produce coverage-threshold-met-and-rubric-complete while the strict
    axis has >=1 uncovered fn OR is unresolved (failed)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = _mk_synthetic_ws(Path(self.tmp.name))
        _mk_full_coverage_report(self.ws)
        self._orig = {}

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(ACC, k, v)
        self.tmp.cleanup()

    def _stub(self, name, fn):
        self._orig[name] = getattr(ACC, name)
        setattr(ACC, name, fn)

    def _stub_heatmap_full_green_g15(self):
        # Force the heatmap/G15 measurement notion to a perfect green: cov=1.0,
        # 0 uncovered, rubric complete - exactly the false-green setup.
        self._stub("_rebuild_coverage_report", lambda ws: {
            "schema": "auditooor.workspace_coverage_report.v1",
            "workspace_name": "synth_ws", "total_units": 3, "covered": 3,
            "uncovered": 0, "uncovered_units": [], "coverage_fraction": 1.0,
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

    def test_no_false_green_when_strict_has_uncovered_units(self):
        # heatmap = perfect green, but the strict gate reports 1 uncovered fn.
        self._stub_heatmap_full_green_g15()
        self._stub("_genuine_uncovered_units",
                   lambda ws: (["src/vault.go::Withdraw"], ACC.FCC_STATUS_OK))
        res = ACC.run(self.ws, max_iters=1, coverage_threshold=1.0, unit_cap=10)
        self.assertNotEqual(
            res["stop_reason"], "coverage-threshold-met-and-rubric-complete",
            "false green: heatmap=1.0 but strict axis has uncovered fns",
        )

    def test_no_false_green_when_strict_status_failed(self):
        # heatmap = perfect green, but the strict gate FAILED (timeout) -> the
        # strict axis is UNKNOWN and must not be treated as covered.
        self._stub_heatmap_full_green_g15()
        self._stub("_genuine_uncovered_units",
                   lambda ws: ([], ACC.FCC_STATUS_FAILED))
        res = ACC.run(self.ws, max_iters=1, coverage_threshold=1.0, unit_cap=10)
        self.assertNotEqual(
            res["stop_reason"], "coverage-threshold-met-and-rubric-complete",
            "false green: heatmap=1.0 but strict axis unresolved (failed)",
        )

    def test_green_allowed_only_when_strict_clean(self):
        # control: heatmap green AND strict gate ran clean (ok, 0 uncovered) ->
        # NOW the coverage axis is genuinely closed and the green is legitimate.
        self._stub_heatmap_full_green_g15()
        self._stub("_genuine_uncovered_units",
                   lambda ws: ([], ACC.FCC_STATUS_OK))
        res = ACC.run(self.ws, max_iters=1, coverage_threshold=1.0, unit_cap=10)
        self.assertEqual(
            res["stop_reason"], "coverage-threshold-met-and-rubric-complete"
        )


class TerminationReconciledToStrictResidualTest(unittest.TestCase):
    """ROOT-CAUSE guard for coverage-notion-termination.

    BUG (regression locked down here): the bounded loop terminated on
    ``fixpoint-no-progress`` using the trivial heatmap effective-uncovered
    (flat at 0 / coverage_fraction=1.0) instead of the STRICT uncovered
    worklist. So with N strict-uncovered fns and a per-iter ``unit_cap`` < N,
    the closer hunted only the first ``unit_cap`` units in iter 1, re-hunted the
    SAME front slice in iter 2 (no progress tracking), saw eff_uncovered flat at
    0, and fixpointed - leaving the bulk of the strict-uncovered set unhunted and
    emitting questions for only the first slice (24 of 29,371 on injective).

    FIX asserted here: termination reconciles to the strict residual (strict
    uncovered fns with no persisted per-unit verdict sidecar). The loop drains
    the residual ``unit_cap`` units at a time across iters - it does NOT
    immediately fixpoint on the trivial heatmap fraction - and emits questions
    for the strict-uncovered fns beyond the first iter's slice.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = _mk_synthetic_ws(Path(self.tmp.name))
        # Heatmap = the trivial false-green: cov=1.0, eff_uncovered=0. The bug
        # trusted exactly this to terminate.
        _mk_full_coverage_report(self.ws)
        self._orig = {}

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(ACC, k, v)
        self.tmp.cleanup()

    def _stub(self, name, fn):
        self._orig[name] = getattr(ACC, name)
        setattr(ACC, name, fn)

    def _stub_heatmap_full_green(self, N):
        # heatmap/G15 perfectly green so the ONLY honest signal of remaining work
        # is the strict residual. Mirrors the false-green production shape.
        self._stub("_rebuild_coverage_report", lambda ws: {
            "schema": "auditooor.workspace_coverage_report.v1",
            "workspace_name": "synth_ws", "total_units": N, "covered": N,
            "uncovered": 0, "uncovered_units": [], "coverage_fraction": 1.0,
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

    @staticmethod
    def _synthetic_strict_units(n):
        # Names whose token set fires an invariant anchor (transfer/withdraw/
        # owner/amount/recipient ...) so the deterministic hacker-questions
        # generator emits >=1 question per unit -> the fold has work to do.
        return [
            "src/vault.go::WithdrawFunds%03d" % k for k in range(n)
        ]

    def test_loop_drains_strict_residual_not_heatmap_fixpoint(self):
        N = 25            # strict-uncovered fns
        cap = 10          # per-iter unit_cap < N -> needs multiple iters
        units = self._synthetic_strict_units(N)
        self._stub_heatmap_full_green(N)
        self._stub("_genuine_uncovered_units",
                   lambda ws: (list(units), ACC.FCC_STATUS_OK))
        # don't let source-path resolution wander; map each unit to its file.
        self._stub("_source_path_for_unit",
                   lambda ws, u: u.partition("::")[0])

        res = ACC.run(self.ws, max_iters=4, coverage_threshold=1.0, unit_cap=cap)

        # (a) it did NOT immediately fixpoint after iter 2 on the heatmap: with
        #     N=25 strict fns and cap=10 it needs >=3 iters to drain the residual.
        self.assertGreaterEqual(
            res["iters_run"], 3,
            "closer fixpointed early on the trivial heatmap instead of draining "
            "the strict residual",
        )
        # (b) the strict residual was genuinely drained (every strict fn now has
        #     a persisted per-unit verdict sidecar), not abandoned at the cap.
        self.assertEqual(
            res["final_strict_residual"], 0,
            "strict residual not drained: %s" % res["final_strict_residual"],
        )
        self.assertEqual(res["stop_reason"], "strict-residual-drained")

        # (c) the per-iter residual strictly shrank across iters (each iter
        #     advanced through the worklist instead of re-hunting the same slice).
        post_residuals = [it["strict_residual_post"] for it in res["iters"]]
        for earlier, later in zip(post_residuals, post_residuals[1:]):
            self.assertLess(
                later, earlier,
                "strict residual did not shrink across iters: %s" % post_residuals,
            )

        # (d) questions were emitted for the strict-uncovered fns BEYOND the first
        #     iter's slice: with the bug only ``cap`` units (<= 10) ever got a
        #     sidecar, so units_with_questions <= 10. After the fix all N fns are
        #     processed and emit a question.
        hq = res["per_fn_hacker_questions"]
        self.assertGreater(
            hq["units_with_questions"], cap,
            "only the first cap slice emitted questions (bug): %s" % hq,
        )
        self.assertEqual(hq["units_with_questions"], N)
        # the folded JSONL exists with >=N lines (>=1 question per strict fn)
        jsonl = self.ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        self.assertTrue(jsonl.is_file())
        lines = [ln for ln in jsonl.read_text().splitlines() if ln.strip()]
        self.assertGreaterEqual(len(lines), N)

    def test_does_not_fixpoint_at_iter2_when_residual_remains(self):
        # Minimal direct assertion of the bug's symptom: N strict fns, cap small,
        # only 2 iters allowed. The bug stopped at iter 2 with stop_reason=
        # fixpoint-no-progress and a non-empty residual it never returned to.
        # The fix keeps making progress, so within 2 iters the stop_reason is
        # NEVER the heatmap fixpoint while the strict residual is still shrinking.
        N = 30
        cap = 10
        units = self._synthetic_strict_units(N)
        self._stub_heatmap_full_green(N)
        self._stub("_genuine_uncovered_units",
                   lambda ws: (list(units), ACC.FCC_STATUS_OK))
        self._stub("_source_path_for_unit",
                   lambda ws, u: u.partition("::")[0])

        res = ACC.run(self.ws, max_iters=2, coverage_threshold=1.0, unit_cap=cap)
        # Capped at 2 iters: it must stop on max-iters with residual still > 0,
        # NOT prematurely declare a heatmap fixpoint while progress was being made.
        self.assertEqual(res["iters_run"], 2)
        self.assertNotEqual(
            res["stop_reason"], "fixpoint-no-progress",
            "false fixpoint: residual was still shrinking (iter1 -> iter2)",
        )
        self.assertGreater(
            res["final_strict_residual"], 0,
            "2 iters of cap=10 cannot drain 30 strict fns; residual must remain",
        )
        # each of the 2 iters processed a fresh cap-sized slice -> residual fell.
        post = [it["strict_residual_post"] for it in res["iters"]]
        self.assertLess(post[1], post[0])


if __name__ == "__main__":
    unittest.main()
