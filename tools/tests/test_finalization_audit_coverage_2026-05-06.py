"""Regression: KLBQ-008 + KLBQ-009 audit-coverage lock-in (2026-05-06).

KLBQ-008
--------
The slot-refill path in ``tools/memory-next-loop-dispatcher.py`` enforces
canonical task-finalization-ledger coverage on every terminal manifest row
through ``terminal_manifest_finalization_gaps`` -> ``manifest_completion_gaps``.
The KLBQ-008 row of ``docs/KNOWN_LIMITATIONS_BURNDOWN_QUEUE_2026-05-05.md``
demands that "future finalization paths must keep the same canonical-ledger
requirement". This module locks in the contract for the
``terminal_manifest_finalization_gaps`` path that landed since 2026-05-05.

The regression asserts:

  * Synthetic terminal manifest rows are rejected (slot-reuse-blocked) when
    the canonical ``reports/task_finalization.jsonl`` ledger is missing the
    matching row.
  * The rejection logs a ``slot_reuse_blocked_pending_finalization`` skip
    with explicit missing-ledger evidence in the ``skip_detail`` text.
  * Once a canonical, gap-retiring ledger row covers the exact terminal
    artifact, the same manifest no longer trips the audit.

KLBQ-009
--------
Unknown-reason declines must remain ``actionable_base_rate_only`` -- never
inferred per-case causes by the scorecard. This regression synthesizes an
``unknown:no-decline-reason`` outcome row, runs the feedback loop with
``dry_run=True``, and asserts:

  * The report's memory_action_routing emits ``actionable_base_rate_only``.
  * No promotion / demotion / mixed-flag adjustments are proposed.
  * Per-row cues set ``causal_reason_inferred=False`` and
    ``pattern_fp_learning_allowed=False``.

Run alone:
    python3 -m unittest tools.tests.test_finalization_audit_coverage_2026-05-06 -v
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

LEDGER_MODULE_PATH = TOOLS / "task-finalization-ledger.py"
DISPATCHER_MODULE_PATH = TOOLS / "memory-next-loop-dispatcher.py"
FEEDBACK_LOOP_MODULE_PATH = TOOLS / "outcome-feedback-loop.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ledger_tool = _load("task_finalization_ledger", LEDGER_MODULE_PATH)
dispatcher = _load("memory_next_loop_dispatcher", DISPATCHER_MODULE_PATH)
feedback_loop = _load("outcome_feedback_loop", FEEDBACK_LOOP_MODULE_PATH)


# ---------------------------------------------------------------------------
# KLBQ-008 -- finalization audit coverage on a NEW finalization-shaped path
# ---------------------------------------------------------------------------


class FinalizationAuditCoverageKLBQ008Test(unittest.TestCase):
    """Lock the canonical-ledger-required contract for slot-refill audit."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-finalization-audit-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        self.manifest = self.vault / "dispatch" / "next_dispatch_manifest.json"
        self.manifest.parent.mkdir(parents=True)
        self.canonical_ledger = self.root / "reports" / "task_finalization.jsonl"
        self.canonical_ledger.parent.mkdir(parents=True)
        self.completed_log = self.vault / "gap-analysis" / "_completed.jsonl"
        self.notes_dir = self.vault / "tasks" / "finalized"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_terminal_manifest(self, *, terminal_artifact: str) -> None:
        # Synthetic terminal manifest row -- this stands in for ANY future
        # finalization-shaped slot-refill payload that ships terminal rows.
        self.manifest.write_text(
            json.dumps(
                {
                    "schema": "auditooor.next_dispatch_manifest.v1",
                    "slots": [
                        {
                            "gap_id": "G8-901",
                            "slot_id": "slot-1",
                            "status": "landed",
                            "terminal_artifact": terminal_artifact,
                        }
                    ],
                    "in_flight_slots": [],
                }
            ),
            encoding="utf-8",
        )

    def _canonical_row(self, *, terminal_artifact: str) -> dict:
        return {
            "schema": "auditooor.task_finalization.v1",
            "task_id": "g8-901-slot-1-landed",
            "gap_id": "G8-901",
            "slot_id": "slot-1",
            "status": "landed",
            "finalization_row_kind": "merged_pr",
            "owner": "codex",
            "dispatch_source": "vault://NEXT_LOOP.md#G8-901",
            "source_manifest": "obsidian-vault/dispatch/next_dispatch_manifest.json",
            "terminal_artifact": terminal_artifact,
            "changed_files": ["tools/task-finalization-ledger.py"],
            "verification": {
                "commands": [
                    {"command": "make task-finalization-test", "exit_code": 0}
                ],
                "passed": True,
            },
            "open_followups": [],
            "docs_updated": True,
            "readme_updated": False,
            "frontdoor_updated": False,
            "outcome_or_calibration_updated": False,
            "memory_updates": [
                "obsidian-vault/tasks/finalized/g8-901-slot-1-landed.md"
            ],
            "blocked_by": None,
            "closed_at": "2026-05-06T00:00:00+00:00",
        }

    def test_slot_refill_rejects_terminal_row_without_canonical_ledger(self) -> None:
        artifact = "https://github.com/Vuk97/auditooor/pull/911"
        self._write_terminal_manifest(terminal_artifact=artifact)
        # Canonical ledger does NOT have a matching row -- mimic a future
        # finalization-shaped path that forgot the ledger.append step.

        blockers = dispatcher.terminal_manifest_finalization_gaps(
            self.vault, self.manifest
        )

        self.assertEqual(len(blockers), 1, blockers)
        blocker = blockers[0]
        self.assertEqual(blocker["gap_id"], "G8-901")
        self.assertEqual(blocker["slot_id"], "slot-1")
        self.assertEqual(blocker["status"], "landed")
        self.assertEqual(blocker["terminal_artifact"], artifact)
        self.assertTrue(blocker["completion_gap"])
        self.assertFalse(blocker["lint_pass"])
        self.assertEqual(
            blocker["skip_reason"], "slot_reuse_blocked_pending_finalization"
        )
        # The rejection must surface explicit missing-ledger evidence.
        self.assertIn(
            "lacks a valid canonical task-finalization ledger row",
            blocker["skip_detail"],
        )
        self.assertIn("G8-901/slot-1", blocker["skip_detail"])
        self.assertIn("status=landed", blocker["skip_detail"])

    def test_slot_refill_rejects_terminal_row_missing_provable_artifact(self) -> None:
        # An unprovable terminal_artifact (empty / non-canonical) must also
        # be rejected by the slot-refill audit, with a distinct evidence
        # string ('does not carry a provable terminal_artifact') so a future
        # finalization-shaped path can't slip a partial proof past the gate.
        self._write_terminal_manifest(terminal_artifact="")

        blockers = dispatcher.terminal_manifest_finalization_gaps(
            self.vault, self.manifest
        )

        self.assertEqual(len(blockers), 1, blockers)
        self.assertEqual(
            blockers[0]["skip_reason"], "slot_reuse_blocked_pending_finalization"
        )
        self.assertIn(
            "does not carry a provable terminal_artifact",
            blockers[0]["skip_detail"],
        )

    def test_slot_refill_clears_when_canonical_ledger_row_lands(self) -> None:
        artifact = "https://github.com/Vuk97/auditooor/pull/911"
        self._write_terminal_manifest(terminal_artifact=artifact)
        # Append the canonical, gap-retiring ledger row that proves the
        # exact terminal artifact -- the rejection must clear.
        ledger_tool.append_row(
            self._canonical_row(terminal_artifact=artifact),
            self.canonical_ledger,
            self.completed_log,
            self.notes_dir,
        )

        blockers = dispatcher.terminal_manifest_finalization_gaps(
            self.vault, self.manifest
        )

        self.assertEqual(blockers, [])

    def test_audit_keys_on_exact_artifact_so_swapped_proofs_dont_paper_over_gap(self) -> None:
        # Pin the contract: a canonical row covering a DIFFERENT artifact
        # must not retire the audit for the manifest's terminal_artifact.
        manifest_artifact = "https://github.com/Vuk97/auditooor/pull/911"
        other_artifact = "https://github.com/Vuk97/auditooor/pull/912"
        self._write_terminal_manifest(terminal_artifact=manifest_artifact)
        ledger_tool.append_row(
            self._canonical_row(terminal_artifact=other_artifact),
            self.canonical_ledger,
            self.completed_log,
            self.notes_dir,
        )

        blockers = dispatcher.terminal_manifest_finalization_gaps(
            self.vault, self.manifest
        )

        self.assertEqual(len(blockers), 1, blockers)
        self.assertEqual(blockers[0]["terminal_artifact"], manifest_artifact)
        self.assertIn(
            "lacks a valid canonical task-finalization ledger row",
            blockers[0]["skip_detail"],
        )


# ---------------------------------------------------------------------------
# KLBQ-009 -- unknown-reason decline base-rate-only contract
# ---------------------------------------------------------------------------


class UnknownReasonDeclineBaseRateOnlyKLBQ009Test(unittest.TestCase):
    """Lock the actionability_status=actionable_base_rate_only contract."""

    def _build_report(self, raw_rows: list[dict]) -> dict:
        rows = feedback_loop.build_outcome_rows(raw_rows)
        stats = feedback_loop.aggregate_pattern_stats(rows)
        adjustments = feedback_loop.compute_adjustments(
            stats, registry={}, now_str="2026-05-06T00:00:00Z"
        )
        return feedback_loop.build_report(
            rows,
            stats,
            adjustments,
            registry_size=0,
            now_str="2026-05-06T00:00:00Z",
            dry_run=True,
        )

    def test_dry_run_emits_actionable_base_rate_only_for_unknown_decline(self) -> None:
        raw_rows = [
            {
                "workspace": "morpho",
                "finding_id": "KLBQ009-A",
                "title": "#KLBQ009-A unknown-reason decline regression",
                "outcome_class": "rejected",
                "status": "DECLINED by Cantina (no decline reason provided to operator)",
                "rejection_reason": "unknown:no-decline-reason",
                "severity_claimed": "Medium",
                "submitted_date": "2026-05-06",
            }
        ]

        report = self._build_report(raw_rows)

        # Top-level routing must classify the unknown decline as
        # base-rate-only and forbid causal inference.
        routing = report["memory_action_routing"]["unknown_no_reason_declines"]
        self.assertEqual(routing["count"], 1)
        self.assertEqual(
            routing["actionability_status"], "actionable_base_rate_only"
        )
        self.assertTrue(routing["report_valid"])
        self.assertFalse(routing["causal_reason_inference_allowed"])
        self.assertIn(
            "platform_base_rate_calibration", routing["routes"]
        )
        self.assertIn("self_learning_followup", routing["routes"])

        # The scorecard / adjustments path must NOT propose a per-case
        # cause inference for an unknown-reason decline.
        self.assertEqual(report["adjustments_summary"]["promotion_candidates"], 0)
        self.assertEqual(report["adjustments_summary"]["demotions"], 0)
        self.assertEqual(report["adjustments_summary"]["mixed_flags"], 0)
        self.assertEqual(report["promotion_candidates"], [])
        self.assertEqual(report["demotions"], [])
        self.assertEqual(
            report["input_summary"]["base_rate_only_rejections"], 1
        )

        # Per-row cues must explicitly disable per-case cause inference.
        self.assertEqual(len(routing["rows"]), 1)
        cue = routing["rows"][0]
        self.assertEqual(cue["finding_id"], "KLBQ009-A")
        self.assertEqual(cue["terminal_state"], "terminal_rejected")
        self.assertFalse(cue["causal_reason_inferred"])
        self.assertFalse(cue["pattern_fp_learning_allowed"])
        self.assertEqual(cue["actionability_status"], "actionable_base_rate_only")

    def test_unknown_decline_with_causal_label_does_not_route_to_base_rate(self) -> None:
        # Negative branch: a row that already carries a labeled
        # rejection_reason (i.e. NOT unknown / no-reason) must NOT be
        # routed to the base-rate-only memory action surface.
        raw_rows = [
            {
                "workspace": "morpho",
                "finding_id": "KLBQ009-B",
                "title": "#KLBQ009-B duplicate rejection",
                "outcome_class": "rejected",
                "status": "DECLINED by Cantina (duplicate of finding #X)",
                "rejection_reason": "duplicate",
                "severity_claimed": "Medium",
                "submitted_date": "2026-05-06",
            }
        ]

        report = self._build_report(raw_rows)

        routing = report["memory_action_routing"]["unknown_no_reason_declines"]
        self.assertEqual(routing["count"], 0)
        self.assertEqual(routing["actionability_status"], "not_applicable")
        self.assertEqual(routing["rows"], [])
        self.assertEqual(report["input_summary"]["base_rate_only_rejections"], 0)


if __name__ == "__main__":
    unittest.main()
