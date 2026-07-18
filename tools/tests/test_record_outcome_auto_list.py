#!/usr/bin/env python3
"""iter6-T2 regression: `make record-outcome` auto-emits `list --outcome <STATE>`.

Context
-------

Iter5 T6 validated the Manual Submission Ledger transition mechanism, but
surfaced an operator gotcha: after a transition, bare
``python3 tools/track-submissions.py list`` prints
``no submissions with outcome='pending'`` because the transitioned row is
now in a terminal state. The transitioned rows are still in the ledger,
just under a different filter.

Iter6 T2's fix, per ``docs/LOOP_ITER_006_PLAN.md`` §T2, is to have the
``make record-outcome`` Makefile target auto-emit a ``list --outcome
<STATE>`` invocation AFTER a successful transition. The ``list`` default
filter stays ``pending`` (operators rely on bare ``list`` showing what's
outstanding) - this regression guards the Makefile-target-only auto-list
convenience.

What this test covers
---------------------

1. **Positive**: after ``make record-outcome WS=<scratch> ID=<id>
   STATE=accepted``, the stdout contains the
   ``[record-outcome] Confirming transition`` banner AND the row's
   report-id in a line that now shows ``accepted`` state.

2. **Hard-negative**: when the transition itself fails (unknown
   ``report-id``), the confirmation banner is NEVER emitted - make halts
   before reaching the auto-list line. This is the guard against a
   misleading "transition complete" message surfacing after an error.

Isolation
---------

- Scratch workspace under ``tempfile.TemporaryDirectory()``.
- Real workspaces under ``~/audits/`` are never touched.
- Uses ``subprocess.run`` to invoke the actual ``make`` binary so the
  Makefile target chain (make halts on non-zero exit) is exercised end-
  to-end, not mocked.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _record_pending(ws: Path, report_id: str) -> None:
    """Seed a pending row by shelling out to the record subcommand."""
    subprocess.run(
        [
            "python3",
            "tools/track-submissions.py",
            "record",
            str(ws),
            "--platform",
            "other",
            "--report-url",
            f"https://example.test/{report_id}",
            "--report-id",
            report_id,
            "--title",
            f"iter6-T2 regression row {report_id}",
            "--severity",
            "Low",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def _run_make_record_outcome(ws: Path, report_id: str, state: str) -> subprocess.CompletedProcess:
    """Invoke `make record-outcome` and capture combined stdout/stderr."""
    env = os.environ.copy()
    return subprocess.run(
        [
            "make",
            "record-outcome",
            f"WS={ws}",
            f"ID={report_id}",
            f"STATE={state}",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
    )


def _run_make_update_outcome(ws: Path, report_id: str, state: str, *, new_rule_codified: bool = False) -> subprocess.CompletedProcess:
    """Invoke `make update-outcome` and capture combined stdout/stderr."""
    env = os.environ.copy()
    args = [
        "make",
        "update-outcome",
        f"WS={ws}",
        f"FINDING={report_id}",
        f"VERDICT={state}",
    ]
    if new_rule_codified:
        args.append("NEW_RULE_CODIFIED=1")
    return subprocess.run(
        args,
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
    )


def _read_outcomes(ws: Path) -> list[dict]:
    path = ws / "reference" / "outcomes.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class TestRecordOutcomeAutoList(unittest.TestCase):
    """Single regression for iter6-T2 — positive + hard-negative in one
    case so the iter6 test-count delta is exactly +1 (205 -> 206).
    """

    def test_auto_list_emitted_only_after_successful_transition(self) -> None:
        # ---------- positive path ----------
        # After a successful transition, the Makefile emits the auto-list
        # banner AND shows the transitioned row in its terminal state.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report_id = "ITER6-T2-REG-001"

            _record_pending(ws, report_id)

            result = _run_make_record_outcome(ws, report_id, "accepted")

            self.assertEqual(
                result.returncode,
                0,
                msg=(
                    "make record-outcome exited non-zero on a valid transition. "
                    f"stdout={result.stdout!r} stderr={result.stderr!r}"
                ),
            )

            # Banner is present on stdout.
            self.assertIn(
                "[record-outcome] Confirming transition",
                result.stdout,
                msg=f"auto-list banner missing from stdout: {result.stdout!r}",
            )

            # Banner mentions the terminal state explicitly so the
            # operator sees which filter is being applied.
            self.assertIn("'accepted'", result.stdout)

            # The transitioned row surfaces in the auto-list output. Must
            # show (a) the report_id, (b) the literal `accepted` state
            # string, (c) AFTER the banner (not before).
            banner_idx = result.stdout.index("[record-outcome] Confirming transition")
            tail = result.stdout[banner_idx:]
            self.assertIn(
                report_id, tail,
                msg=f"report_id missing from post-banner tail: {tail!r}",
            )
            self.assertIn(
                "accepted", tail,
                msg=f"'accepted' state missing from post-banner tail: {tail!r}",
            )

        # ---------- hard-negative path ----------
        # If the transition fails (unknown report_id), make halts on the
        # failing command before it reaches the @echo / auto-list lines -
        # the banner must NEVER appear on a failed transition.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Well-formed empty workspace so the tool can reach its
            # `report_id not found` check (rather than workspace-not-found).
            (ws / "reference").mkdir(parents=True, exist_ok=True)
            (ws / "submissions").mkdir(parents=True, exist_ok=True)

            unknown_id = "ITER6-T2-REG-NOPE"
            result = _run_make_record_outcome(ws, unknown_id, "accepted")

            # Non-zero exit: make halted on the failing transition.
            self.assertNotEqual(
                result.returncode,
                0,
                msg=(
                    "make record-outcome should fail when report_id is unknown "
                    f"but exit was 0. stdout={result.stdout!r} stderr={result.stderr!r}"
                ),
            )

            # CRITICAL: the auto-list banner must NEVER appear on a failed
            # transition. This is the misleading-confirmation guard.
            combined = result.stdout + result.stderr
            self.assertNotIn(
                "[record-outcome] Confirming transition",
                combined,
                msg=(
                    "auto-list 'Confirming transition' banner leaked into a "
                    f"FAILED transition output. combined={combined!r}"
                ),
            )

            # The underlying tool should still surface its own 'not found'
            # error on stderr so the operator understands why the
            # transition halted.
            self.assertIn("not found", combined)

    def test_update_outcome_alias_records_new_rule_codified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report_id = "ITER6-T2-UPD-001"

            _record_pending(ws, report_id)
            result = _run_make_update_outcome(
                ws, report_id, "rejected", new_rule_codified=True
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout={result.stdout!r} stderr={result.stderr!r}",
            )
            self.assertIn("[update-outcome] Confirming transition", result.stdout)
            self.assertIn(report_id, result.stdout)

            rows = _read_outcomes(ws)
            self.assertEqual(rows[-1]["outcome"], "rejected")
            self.assertIs(rows[-1]["new_rule_codified"], True)


if __name__ == "__main__":
    unittest.main()
