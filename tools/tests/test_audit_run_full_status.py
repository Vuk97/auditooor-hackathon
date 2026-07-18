import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit-run-full-status.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("audit_run_full_status", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load audit-run-full-status.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STATUS = _load_tool()


REAL_ENGINE_HARNESS = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract FuzzProps {
    Vault vault;
    bool negative_control_cleanPath;

    function property_balance_conserved() public returns (bool) {
        uint256 beforeBalance = vault.balance();
        vault.deposit(1);
        uint256 afterBalance = vault.balance();
        return afterBalance == beforeBalance + 1;
    }
}
"""


def _write_manifest(ws: Path, rows: list[dict[str, object]]) -> Path:
    path = ws / ".auditooor" / "audit_run_full_manifest.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    return path


def _write_live_solidity_deep_manifest(
    ws: Path,
    *,
    run_id: str,
    generated_at: str = "2026-05-30T10:01:00Z",
    extra_fields: dict[str, object] | None = None,
) -> None:
    harness = ws / "poc-tests" / "x-engine-harness" / "FuzzProps.sol"
    harness.parent.mkdir(parents=True, exist_ok=True)
    harness.write_text(REAL_ENGINE_HARNESS, encoding="utf-8")

    step = ws / ".auditooor" / "solidity-deep-audit" / "halmos-runner.json"
    step.parent.mkdir(parents=True, exist_ok=True)
    step.write_text(
        json.dumps(
            {
                "schema": "auditooor.solidity_deep_audit.step.v1",
                "tool": "halmos-runner",
                "status": "ok",
                "returncode": 0,
                "run_id": run_id,
                "generated_at": "2026-05-30T10:01:30Z",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    runner = ws / ".auditooor" / "halmos" / "artifact.json"
    runner.parent.mkdir(parents=True, exist_ok=True)
    runner.write_text(
        json.dumps(
            {
                "schema_version": "auditooor.deep_engine_artifact.v1",
                "engine": "halmos",
                "status": "ok",
                "engine_rc": 0,
                "created_at": "2026-05-30T10:01:45Z",
                "workspace": str(ws),
                "run_id": run_id,
                "stdout": "",
                "stderr": "",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest = ws / ".auditooor" / "solidity-deep-audit" / "manifest.json"
    payload: dict[str, object] = {
        "schema": "auditooor.solidity_deep_audit.v1",
        "workspace": str(ws),
        "run_id": run_id,
        "generated_at": generated_at,
        "generated_per_function_harness_count": 0,
        "executed_generated_harness_count": 0,
        "available_engine_harness_count": 0,
        "executed_engine_harness_count": 0,
        "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
    }
    if extra_fields:
        payload.update(extra_fields)
    manifest.write_text(
        json.dumps(payload, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_live_deep_skip(ws: Path, *, run_id: str) -> None:
    path = ws / ".auditooor" / "stage_skips.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "NO_AUDIT_DEEP_REASON": {
                    "reason": "no supported deep engine for this workspace",
                    "timestamp_utc": "2026-05-30T10:01:00Z",
                    "run_id": run_id,
                }
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _typed_deep_skip_fields() -> dict[str, str]:
    return {
        "deep_engine_skip_key": "NO_AUDIT_DEEP_REASON",
        "deep_engine_skip_source": "stage_skips.json",
        "deep_engine_skip_path": ".auditooor/stage_skips.json",
    }


def _write_audit_deep_all_manifest(
    ws: Path,
    *,
    run_id: str,
    timestamp_utc: str,
) -> None:
    audit_logs = ws / ".audit_logs"
    audit_logs.mkdir(parents=True, exist_ok=True)
    report = audit_logs / "audit_deep_all_report.md"
    report.write_text("# audit-deep all-profile report\n", encoding="utf-8")
    log = audit_logs / "audit_deep_all_default.log"
    log.write_text("default profile completed\n", encoding="utf-8")
    manifest = audit_logs / "audit_deep_all_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(ws),
                "run_id": run_id,
                "timestamp_utc": timestamp_utc,
                "dry_run": False,
                "expected_profiles": ["default"],
                "report": str(report),
                "profiles": [
                    {
                        "profile": "default",
                        "status": "success",
                        "exit_code": 0,
                        "log": str(log),
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_live_rust_source_graph_manifest(
    ws: Path,
    *,
    run_id: str,
    generated_at: str = "2026-05-30T10:01:00Z",
) -> None:
    path = ws / ".auditooor" / "rust_source_graph.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "_meta": {
                    "schema_version": "auditooor.rust_source_graph.v1",
                    "workspace": str(ws),
                    "run_id": run_id,
                    "generated_at_utc": generated_at,
                    "crate_count": 1,
                },
                "crates": [],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_live_go_dlt_audit_enforcement_manifest(
    ws: Path,
    *,
    run_id: str,
    timestamp_utc: str = "2026-05-30T10:01:00Z",
) -> None:
    report = ws / ".audit_logs" / "go_dlt_audit_report.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("# go dlt audit report\n", encoding="utf-8")
    manifest = ws / ".audit_logs" / "go_dlt_audit_enforcement.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "auditooor.go_dlt_audit_enforcement.v1",
                "workspace": str(ws),
                "run_id": run_id,
                "timestamp_utc": timestamp_utc,
                "status": "pass",
                "audit_completion": {
                    "exists": True,
                    "check_rc": 0,
                },
                "audit_deep_report": str(report),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_failed_solidity_runner_manifest(ws: Path, *, run_id: str) -> None:
    step = ws / ".auditooor" / "solidity-deep-audit" / "echidna-campaign.json"
    step.parent.mkdir(parents=True, exist_ok=True)
    step.write_text(
        json.dumps(
            {
                "schema": "auditooor.solidity_deep_audit.step.v1",
                "tool": "echidna-campaign",
                "status": "ok",
                "returncode": 0,
                "run_id": run_id,
                "generated_at": "2026-05-30T10:01:30Z",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    runner = ws / ".auditooor" / "echidna" / "artifact.json"
    runner.parent.mkdir(parents=True, exist_ok=True)
    runner.write_text(
        json.dumps(
            {
                "schema_version": "auditooor.deep_engine_artifact.v1",
                "engine": "echidna",
                "status": "tool-unavailable",
                "engine_rc": None,
                "created_at": "2026-05-30T10:01:45Z",
                "workspace": str(ws),
                "run_id": run_id,
                "stdout": "",
                "stderr": "echidna binary unavailable",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest = ws / ".auditooor" / "solidity-deep-audit" / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(ws),
                "run_id": run_id,
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "echidna-campaign", "status": "ok", "artifact": str(step)}],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _mandatory_stage_pass_rows(run_id: str) -> list[dict[str, object]]:
    return [
        {
            "schema": "auditooor.audit_run_full_manifest.v1",
            "event": "stage-pass",
            "stage": stage,
            "run_id": run_id,
        }
        for stage in STATUS.MANDATORY_CERTIFICATION_STAGES
        if stage != "deep-freshness"
    ]


def _write_g15_sidecar(
    ws: Path,
    *,
    run_id: str,
    verdict: str = "pass-coverage-met",
    total_units: int = 12,
) -> None:
    path = ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": "auditooor.g15_hunt_coverage_gate.v1",
                "run_id": run_id,
                "generated_at_utc": "2026-05-30T10:02:00Z",
                "strict": True,
                "min_coverage": 1.0,
                "verdict": verdict,
                "reason": "coverage complete",
                "covered": total_units,
                "total_units": total_units,
                "coverage_fraction": 1.0 if total_units else 0.0,
                "queued_not_scanned": [],
                "detector_only_not_queued": [],
                "unlogged_uncovered": [],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_submission_draft(ws: Path, status: str, relative_path: str) -> Path:
    path = ws / "submissions" / status / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# draft\n", encoding="utf-8")
    return path


def _passing_live_audit_completeness(_workspace: Path) -> dict[str, object]:
    return {
        "ok": True,
        "verdict": "pass-audit-complete",
        "reason": "unit-test stub",
        "failures": [],
        "signals": [],
    }


class AuditRunFullStatusTest(unittest.TestCase):
    def setUp(self) -> None:
        self._original_live_audit_completeness = STATUS._live_audit_completeness
        STATUS._live_audit_completeness = _passing_live_audit_completeness

    def tearDown(self) -> None:
        STATUS._live_audit_completeness = self._original_live_audit_completeness

    def test_latest_bounded_complete_is_not_certification_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-bounded")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "12",
                        "run_id": "auditrun-bounded",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-bounded",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["latest_run_id"], "auditrun-bounded")
            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertEqual(payload["max_functions"], 12)
            self.assertFalse(payload["full_scope"])
            self.assertTrue(payload["terminal_complete"])
            self.assertTrue(payload["current_run_deep_proof"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("bounded-run", payload["certification_blockers"])

    def test_latest_bounded_complete_event_is_terminal_but_not_certification_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "12",
                        "run_id": "auditrun-bounded-event",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "bounded-complete",
                        "run_id": "auditrun-bounded-event",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["latest_run_id"], "auditrun-bounded-event")
            self.assertEqual(payload["status"], "bounded-complete")
            self.assertEqual(payload["terminal_event"], "bounded-complete")
            self.assertEqual(payload["terminal_stage"], "bounded-complete")
            self.assertTrue(payload["successful_terminal"])
            self.assertFalse(payload["terminal_complete"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("bounded-run", payload["certification_blockers"])
            self.assertIn("bounded-terminal-not-certifying", payload["certification_blockers"])
            self.assertNotIn("latest-run-not-terminal-complete", payload["certification_blockers"])

    def test_full_scope_complete_with_fresh_manifest_is_certification_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-full")
            _write_g15_sidecar(ws, run_id="auditrun-full")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-full",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows("auditrun-full"),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-full",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-full",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertTrue(payload["full_scope"])
            self.assertEqual(payload["status"], "complete")
            self.assertTrue(payload["live_audit_complete"])
            self.assertEqual(payload["live_audit_completeness_verdict"], "pass-audit-complete")
            self.assertEqual(payload["terminal_stage"], "complete")
            self.assertTrue(payload["terminal_complete"])
            self.assertTrue(payload["current_run_deep_proof"])
            self.assertTrue(payload["certification_complete"])
            self.assertEqual(payload["certification_blockers"], [])
            self.assertEqual(
                payload["post_certification_finding_status"],
                STATUS.POST_CERT_FINDING_STATUS_ZERO_CANDIDATES,
            )
            self.assertEqual(payload["finding_backlog_count"], 0)

    def test_full_scope_complete_with_rust_fresh_manifest_is_certification_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            run_id = "auditrun-rust-full"
            _write_live_rust_source_graph_manifest(ws, run_id=run_id)
            _write_g15_sidecar(ws, run_id=run_id)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": run_id,
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows(run_id),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": run_id,
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [".auditooor/rust_source_graph.json"],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": run_id,
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [".auditooor/rust_source_graph.json"],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "complete")
            self.assertTrue(payload["certification_complete"])
            self.assertTrue(payload["current_run_deep_proof"])
            self.assertEqual(payload["certification_blockers"], [])

    def test_full_scope_complete_with_go_dlt_fresh_manifest_is_certification_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            run_id = "auditrun-go-full"
            _write_live_go_dlt_audit_enforcement_manifest(ws, run_id=run_id)
            _write_g15_sidecar(ws, run_id=run_id)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": run_id,
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows(run_id),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": run_id,
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [".audit_logs/go_dlt_audit_enforcement.json"],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": run_id,
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [".audit_logs/go_dlt_audit_enforcement.json"],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "complete")
            self.assertTrue(payload["certification_complete"])
            self.assertTrue(payload["current_run_deep_proof"])
            self.assertEqual(payload["certification_blockers"], [])

    def test_full_scope_complete_requires_live_l37_audit_completeness(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            run_id = "auditrun-l37-fail"
            _write_live_solidity_deep_manifest(ws, run_id=run_id)
            _write_g15_sidecar(ws, run_id=run_id)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": run_id,
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows(run_id),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": run_id,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": run_id,
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            def failing_live_audit_completeness(_workspace: Path) -> dict[str, object]:
                return {
                    "ok": False,
                    "verdict": "fail-no-coverage-map",
                    "reason": "coverage map missing",
                    "failures": ["fail-no-coverage-map"],
                    "signals": [
                        {
                            "signal": "coverage-map",
                            "ok": False,
                            "verdict": "fail-no-coverage-map",
                            "reason": "coverage map missing",
                        }
                    ],
                }

            STATUS._live_audit_completeness = failing_live_audit_completeness
            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertFalse(payload["certification_complete"])
            self.assertFalse(payload["live_audit_complete"])
            self.assertEqual(payload["live_audit_completeness_verdict"], "fail-no-coverage-map")
            self.assertIn("live-audit-completeness-failed", payload["certification_blockers"])

    def test_certified_with_staging_draft_reports_real_finding_backlog(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-backlog")
            _write_g15_sidecar(ws, run_id="auditrun-backlog")
            _write_submission_draft(
                ws,
                "staging",
                "morpho-sample-finding-HIGH/morpho-sample-finding-HIGH.md",
            )
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-backlog",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows("auditrun-backlog"),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-backlog",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-backlog",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertTrue(payload["certification_complete"])
            self.assertEqual(payload["finding_backlog_count"], 1)
            self.assertEqual(payload["submission_drafts"]["status_counts"]["staging"], 1)
            self.assertEqual(
                payload["post_certification_finding_status"],
                STATUS.POST_CERT_FINDING_STATUS_BACKLOG,
            )

    def test_submission_backlog_counts_one_r41_draft_not_sidecar_markdown(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_submission_draft(ws, "staging", "sample-finding/sample-finding.md")
            _write_submission_draft(ws, "staging", "sample-finding/sample-finding.hardening.md")

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["finding_backlog_count"], 1)
            self.assertEqual(payload["submission_drafts"]["status_counts"]["staging"], 1)

    def test_pipeline_incomplete_status_takes_precedence_over_backlog(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_submission_draft(
                ws,
                "staging",
                "morpho-pipeline-incomplete-HIGH/morpho-pipeline-incomplete-HIGH.md",
            )
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-incomplete",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-start",
                        "run_id": "auditrun-incomplete",
                        "stage": "hunt-full",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertFalse(payload["certification_complete"])
            self.assertEqual(payload["finding_backlog_count"], 1)
            self.assertEqual(
                payload["post_certification_finding_status"],
                STATUS.POST_CERT_FINDING_STATUS_PIPELINE_INCOMPLETE,
            )

    def test_full_scope_complete_with_typed_skip_is_certification_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_deep_skip(ws, run_id="auditrun-skip")
            _write_g15_sidecar(ws, run_id="auditrun-skip")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": 0,
                        "run_id": "auditrun-skip",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows("auditrun-skip"),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-skip",
                        "deep_engine_completion_mode": "typed-skip",
                        "deep_engine_freshness_verdict": "pass-explicit-deep-skip",
                        "deep_engine_skip_reason": "no supported deep engine for this workspace",
                        **_typed_deep_skip_fields(),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-skip",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "typed-skip",
                        "deep_engine_freshness_verdict": "pass-explicit-deep-skip",
                        "deep_engine_skip_reason": "no supported deep engine for this workspace",
                        **_typed_deep_skip_fields(),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "complete")
            self.assertTrue(payload["terminal_complete"])
            self.assertTrue(payload["terminal_deep_proof"])
            self.assertTrue(payload["current_run_deep_proof"])
            self.assertEqual(payload["live_deep_freshness"]["verdict"], "pass-explicit-deep-skip")
            self.assertTrue(payload["certification_complete"])
            self.assertEqual(payload["certification_blockers"], [])

    def test_complete_with_untyped_terminal_skip_is_uncertified(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_deep_skip(ws, run_id="auditrun-untyped-skip")
            _write_g15_sidecar(ws, run_id="auditrun-untyped-skip")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": 0,
                        "run_id": "auditrun-untyped-skip",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows("auditrun-untyped-skip"),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-untyped-skip",
                        "deep_engine_completion_mode": "typed-skip",
                        "deep_engine_freshness_verdict": "pass-explicit-deep-skip",
                        "deep_engine_skip_reason": "no supported deep engine for this workspace",
                        **_typed_deep_skip_fields(),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-untyped-skip",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "typed-skip",
                        "deep_engine_freshness_verdict": "pass-explicit-deep-skip",
                        "deep_engine_skip_reason": "no supported deep engine for this workspace",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertFalse(payload["terminal_deep_proof"])
            self.assertFalse(payload["terminal_deep_proof_matches_live"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("terminal-deep-skip-not-typed", payload["certification_blockers"])
            self.assertIn("missing-current-run-deep-proof", payload["certification_blockers"])

    def test_complete_without_mandatory_stages_is_not_certified(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-missing-stage")
            _write_g15_sidecar(ws, run_id="auditrun-missing-stage")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": 0,
                        "run_id": "auditrun-missing-stage",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-missing-stage",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-missing-stage",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertFalse(payload["certification_complete"])
            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertIn("missing-mandatory-stage-passes", payload["certification_blockers"])
            self.assertIn("mcp-preflight", payload["missing_mandatory_stage_passes"])

    def test_advisory_proof_stage_warn_does_not_block_certification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-stage-warn")
            _write_g15_sidecar(ws, run_id="auditrun-stage-warn")
            rows = [
                {
                    "event": "start",
                    "max_functions": 0,
                    "run_id": "auditrun-stage-warn",
                    "timestamp_utc": "2026-05-30T10:00:00Z",
                    "workspace": str(ws),
                    "schema": "auditooor.audit_run_full_manifest.v1",
                },
                *_mandatory_stage_pass_rows("auditrun-stage-warn"),
                {
                    "event": "stage-warn",
                    "stage": "prove-top-leads",
                    "run_id": "auditrun-stage-warn",
                    "rc": 7,
                    "enforce_autonomous_proof_conversion": "0",
                    "schema": "auditooor.audit_run_full_manifest.v1",
                },
                {
                    "event": "stage-pass",
                    "stage": "deep-freshness",
                    "run_id": "auditrun-stage-warn",
                    "schema": "auditooor.audit_run_full_manifest.v1",
                },
                {
                    "event": "complete",
                    "run_id": "auditrun-stage-warn",
                    "workspace": str(ws),
                    "deep_engine_completion_mode": "fresh-manifest",
                    "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                    "fresh_manifest_paths": [
                        str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                    ],
                    "schema": "auditooor.audit_run_full_manifest.v1",
                },
            ]
            _write_manifest(ws, rows)

            payload = STATUS.summarize_manifest(ws)

            self.assertTrue(payload["certification_complete"])
            self.assertNotIn("stage-warn-present", payload["certification_blockers"])
            self.assertNotIn("missing-mandatory-stage-passes", payload["certification_blockers"])
            self.assertEqual(payload["stage_statuses"]["prove-top-leads"], "stage-warn")
            self.assertEqual(payload["stage_warnings"][0]["stage"], "prove-top-leads")
            self.assertEqual(payload["advisory_proof_warnings"][0]["stage"], "prove-top-leads")
            self.assertEqual(payload["blocking_stage_warnings"], [])

    def test_non_proof_stage_warn_blocks_certification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-stage-warn-hard")
            _write_g15_sidecar(ws, run_id="auditrun-stage-warn-hard")
            rows = [
                {
                    "event": "start",
                    "max_functions": 0,
                    "run_id": "auditrun-stage-warn-hard",
                    "schema": "auditooor.audit_run_full_manifest.v1",
                },
                *_mandatory_stage_pass_rows("auditrun-stage-warn-hard"),
                {
                    "event": "stage-warn",
                    "stage": "cvl-spec-risk-scan",
                    "run_id": "auditrun-stage-warn-hard",
                    "rc": 7,
                    "schema": "auditooor.audit_run_full_manifest.v1",
                },
                {
                    "event": "stage-pass",
                    "stage": "deep-freshness",
                    "run_id": "auditrun-stage-warn-hard",
                    "schema": "auditooor.audit_run_full_manifest.v1",
                },
                {
                    "event": "complete",
                    "run_id": "auditrun-stage-warn-hard",
                    "workspace": str(ws),
                    "deep_engine_completion_mode": "fresh-manifest",
                    "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                    "fresh_manifest_paths": [
                        str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                    ],
                    "schema": "auditooor.audit_run_full_manifest.v1",
                },
            ]
            _write_manifest(ws, rows)

            payload = STATUS.summarize_manifest(ws)

            self.assertFalse(payload["certification_complete"])
            self.assertIn("stage-warn-present", payload["certification_blockers"])
            self.assertIn("missing-mandatory-stage-passes", payload["certification_blockers"])
            self.assertEqual(payload["stage_statuses"]["cvl-spec-risk-scan"], "stage-warn")
            self.assertEqual(payload["blocking_stage_warnings"][0]["stage"], "cvl-spec-risk-scan")
            self.assertEqual(payload["advisory_proof_warnings"], [])

    def test_stale_or_failing_g15_blocks_certification(self) -> None:
        for sidecar_run_id, verdict, expected_blocker in (
            ("auditrun-old", "pass-coverage-met", "stale-g15-hunt-coverage-result"),
            ("auditrun-g15", "fail-coverage-below-threshold", "failing-g15-hunt-coverage-result"),
        ):
            with self.subTest(expected_blocker=expected_blocker):
                with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
                    ws = Path(tmp)
                    _write_live_solidity_deep_manifest(ws, run_id="auditrun-g15")
                    _write_g15_sidecar(ws, run_id=sidecar_run_id, verdict=verdict)
                    _write_manifest(
                        ws,
                        [
                            {
                                "event": "start",
                                "max_functions": 0,
                                "run_id": "auditrun-g15",
                                "schema": "auditooor.audit_run_full_manifest.v1",
                            },
                            *_mandatory_stage_pass_rows("auditrun-g15"),
                            {
                                "event": "stage-pass",
                                "stage": "deep-freshness",
                                "run_id": "auditrun-g15",
                                "schema": "auditooor.audit_run_full_manifest.v1",
                            },
                            {
                                "event": "complete",
                                "run_id": "auditrun-g15",
                                "workspace": str(ws),
                                "deep_engine_completion_mode": "fresh-manifest",
                                "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                                "fresh_manifest_paths": [
                                    str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                                ],
                                "schema": "auditooor.audit_run_full_manifest.v1",
                            },
                        ],
                    )

                    payload = STATUS.summarize_manifest(ws)

                    self.assertFalse(payload["certification_complete"])
                    self.assertIn(expected_blocker, payload["certification_blockers"])

    def test_zero_g15_denominator_blocks_certification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-zero-g15")
            _write_g15_sidecar(
                ws,
                run_id="auditrun-zero-g15",
                verdict="pass-coverage-met",
                total_units=0,
            )
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": 0,
                        "run_id": "auditrun-zero-g15",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows("auditrun-zero-g15"),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-zero-g15",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-zero-g15",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertTrue(payload["terminal_complete"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("zero-g15-coverage-denominator", payload["certification_blockers"])

    def test_malformed_g15_pass_sidecar_blocks_certification(self) -> None:
        cases = {
            "strict-disabled": {"strict": False},
            "nonfull-min-coverage": {"min_coverage": 0.95},
            "nonfull-coverage-fraction": {"coverage_fraction": 0.99},
            "covered-mismatch": {"covered": 11},
            "queued-not-scanned": {"queued_not_scanned": ["Midnight.sol::multicall"]},
            "detector-only-not-queued": {"detector_only_not_queued": ["detector-only-hit"]},
            "unlogged-uncovered": {"unlogged_uncovered": ["unlogged-unit"]},
        }
        for name, mutation in cases.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
                    ws = Path(tmp)
                    run_id = f"auditrun-malformed-g15-{name}"
                    _write_live_solidity_deep_manifest(ws, run_id=run_id)
                    _write_g15_sidecar(ws, run_id=run_id)
                    g15_path = ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
                    g15_payload = json.loads(g15_path.read_text(encoding="utf-8"))
                    g15_payload.update(mutation)
                    g15_path.write_text(json.dumps(g15_payload, sort_keys=True) + "\n", encoding="utf-8")
                    _write_manifest(
                        ws,
                        [
                            {
                                "event": "start",
                                "max_functions": 0,
                                "run_id": run_id,
                                "schema": "auditooor.audit_run_full_manifest.v1",
                            },
                            *_mandatory_stage_pass_rows(run_id),
                            {
                                "event": "stage-pass",
                                "stage": "deep-freshness",
                                "run_id": run_id,
                                "schema": "auditooor.audit_run_full_manifest.v1",
                            },
                            {
                                "event": "complete",
                                "run_id": run_id,
                                "workspace": str(ws),
                                "deep_engine_completion_mode": "fresh-manifest",
                                "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                                "fresh_manifest_paths": [
                                    str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                                ],
                                "schema": "auditooor.audit_run_full_manifest.v1",
                            },
                        ],
                    )

                    payload = STATUS.summarize_manifest(ws)

                    self.assertEqual(payload["status"], "uncertified-complete")
                    self.assertFalse(payload["certification_complete"])
                    self.assertIn("failing-g15-hunt-coverage-result", payload["certification_blockers"])

    def test_g15_rebuttal_pass_does_not_require_denominator(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            run_id = "auditrun-g15-rebuttal"
            _write_live_solidity_deep_manifest(ws, run_id=run_id)
            _write_g15_sidecar(
                ws,
                run_id=run_id,
                verdict="ok-rebuttal",
                total_units=0,
            )
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": 0,
                        "run_id": run_id,
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows(run_id),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": run_id,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": run_id,
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "complete")
            self.assertTrue(payload["certification_complete"])
            self.assertNotIn("zero-g15-coverage-denominator", payload["certification_blockers"])

    def test_complete_without_deep_proof_is_not_certification_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-no-proof",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-no-proof",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertTrue(payload["terminal_complete"])
            self.assertFalse(payload["current_run_deep_proof"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("missing-current-run-deep-proof", payload["certification_blockers"])

    def test_complete_with_claimed_deep_proof_requires_live_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-claimed-only",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-claimed-only",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertFalse(payload["current_run_deep_proof"])
            self.assertFalse(payload["terminal_deep_proof"])
            self.assertFalse(payload["certification_complete"])
            self.assertEqual(payload["live_deep_freshness"]["verdict"], "fail-no-deep-manifest")
            self.assertFalse(payload["live_deep_proof"])
            self.assertIn("missing-current-run-deep-proof", payload["certification_blockers"])
            self.assertIn("live-current-run-deep-proof-failed", payload["certification_blockers"])

    def test_complete_with_stale_audit_deep_manifest_is_uncertified_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_audit_deep_all_manifest(
                ws,
                run_id="auditrun-stale",
                timestamp_utc="2026-05-30T09:59:00Z",
            )
            _write_g15_sidecar(ws, run_id="auditrun-stale")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-stale",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows("auditrun-stale"),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-stale",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-stale",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".audit_logs" / "audit_deep_all_manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertTrue(payload["terminal_complete"])
            self.assertFalse(payload["current_run_deep_proof"])
            self.assertFalse(payload["terminal_deep_proof"])
            self.assertFalse(payload["certification_complete"])
            self.assertEqual(payload["live_deep_freshness"]["verdict"], "fail-conflicting-deep-manifest")
            self.assertIn("missing-current-run-deep-proof", payload["certification_blockers"])
            self.assertIn("live-current-run-deep-proof-failed", payload["certification_blockers"])

    def test_complete_row_run_id_mismatch_after_latest_start_is_uncertified(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-current")
            _write_g15_sidecar(ws, run_id="auditrun-current")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-current",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows("auditrun-current"),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-current",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-old",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            ".auditooor/solidity-deep-audit/manifest.json"
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["latest_run_id"], "auditrun-current")
            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertFalse(payload["terminal_run_id_matches_latest"])
            self.assertFalse(payload["current_run_deep_proof"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("terminal-run-id-mismatch", payload["certification_blockers"])
            self.assertIn("missing-current-run-deep-proof", payload["certification_blockers"])

    def test_complete_fresh_manifest_paths_must_match_live_fresh_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-paths")
            _write_g15_sidecar(ws, run_id="auditrun-paths")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-paths",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows("auditrun-paths"),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-paths",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-paths",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            ".audit_logs/audit_deep_all_manifest.json"
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertTrue(payload["terminal_run_id_matches_latest"])
            self.assertFalse(payload["terminal_deep_proof_matches_live"])
            self.assertFalse(payload["current_run_deep_proof"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("terminal-deep-proof-live-mismatch", payload["certification_blockers"])
            self.assertIn("missing-current-run-deep-proof", payload["certification_blockers"])

    def test_live_deep_freshness_returned_run_id_must_match_latest_run_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_g15_sidecar(ws, run_id="auditrun-live-current")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-live-current",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows("auditrun-live-current"),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-live-current",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-live-current",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            ".auditooor/solidity-deep-audit/manifest.json"
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )
            original = STATUS._live_deep_freshness

            def fake_live_deep_freshness(workspace, manifest_path, run_id):
                return {
                    "ok": True,
                    "verdict": "pass-fresh-deep-manifest",
                    "run_id": "auditrun-live-old",
                    "fresh_manifest_paths": [
                        ".auditooor/solidity-deep-audit/manifest.json"
                    ],
                    "blocking_manifest_paths": [],
                    "source_manifest_summaries": [],
                    "runner_artifact_error_count": 0,
                    "runner_artifact_errors": [],
                }

            try:
                STATUS._live_deep_freshness = fake_live_deep_freshness
                payload = STATUS.summarize_manifest(ws)
            finally:
                STATUS._live_deep_freshness = original

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertFalse(payload["live_deep_proof"])
            self.assertFalse(payload["current_run_deep_proof"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("live-current-run-deep-proof-failed", payload["certification_blockers"])

    def test_latest_run_is_selected_and_reports_active_stage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-old",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-old",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [str(ws / ".audit_logs" / "old.json")],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "start",
                        "max_functions": "12",
                        "run_id": "auditrun-current",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-start",
                        "run_id": "auditrun-current",
                        "stage": "hunt-full",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["latest_run_id"], "auditrun-current")
            self.assertEqual(payload["status"], "running")
            self.assertEqual(payload["current_stage"], "hunt-full")
            self.assertEqual(payload["active_stage"], "hunt-full")
            self.assertFalse(payload["terminal_complete"])
            self.assertFalse(payload["certification_complete"])

    def test_latest_run_with_old_stage_start_and_no_terminal_is_stale_running(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-old",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-old",
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [str(ws / ".audit_logs" / "old.json")],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-stale-current",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-start",
                        "run_id": "auditrun-stale-current",
                        "stage": "hunt-full",
                        "timestamp_utc": "2000-01-01T00:00:00Z",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["latest_run_id"], "auditrun-stale-current")
            self.assertEqual(payload["status"], STATUS.STALE_RUNNING_STATUS)
            self.assertNotEqual(payload["status"], "running")
            self.assertEqual(payload["current_stage"], "hunt-full")
            self.assertEqual(payload["active_stage"], "hunt-full")
            self.assertTrue(payload["stale_running"]["stale"])
            self.assertGreater(
                payload["stale_running"]["age_seconds"],
                payload["stale_running"]["threshold_seconds"],
            )
            self.assertFalse(payload["terminal_complete"])
            self.assertFalse(payload["certification_complete"])

    def test_live_deep_engine_suppresses_stale_running_status(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-active-engine",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-start",
                        "run_id": "auditrun-active-engine",
                        "stage": "hunt-full",
                        "timestamp_utc": "2000-01-01T00:00:00Z",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            original = STATUS._live_deep_engine_processes
            STATUS._live_deep_engine_processes = lambda workspace: [
                {
                    "pid": 123,
                    "ppid": 1,
                    "marker": "halmos",
                    "command": f"halmos --root {workspace}/poc-tests/TickLib-engine-harness",
                }
            ]
            try:
                payload = STATUS.summarize_manifest(ws)
            finally:
                STATUS._live_deep_engine_processes = original

            self.assertEqual(payload["latest_run_id"], "auditrun-active-engine")
            self.assertEqual(payload["status"], "running")
            self.assertFalse(payload["stale_running"]["stale"])
            self.assertTrue(payload["stale_running"]["suppressed_by_live_deep_engine"])
            self.assertEqual(payload["stale_running"]["live_deep_engine_processes"][0]["marker"], "halmos")
            self.assertIn("latest-run-not-terminal-complete", payload["certification_blockers"])

    def test_live_deep_engine_does_not_suppress_stale_nondeep_stage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-stale-preflight",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-start",
                        "run_id": "auditrun-stale-preflight",
                        "stage": "mcp-preflight",
                        "timestamp_utc": "2000-01-01T00:00:00Z",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            original = STATUS._live_deep_engine_processes
            STATUS._live_deep_engine_processes = lambda workspace: [
                {
                    "pid": 123,
                    "ppid": 1,
                    "marker": "halmos",
                    "command": f"halmos --root {workspace}/poc-tests/TickLib-engine-harness",
                }
            ]
            try:
                payload = STATUS.summarize_manifest(ws)
            finally:
                STATUS._live_deep_engine_processes = original

            self.assertEqual(payload["status"], STATUS.STALE_RUNNING_STATUS)
            self.assertTrue(payload["stale_running"]["stale"])
            self.assertFalse(payload["stale_running"]["suppressed_by_live_deep_engine"])
            self.assertEqual(payload["stale_running"]["live_deep_engine_processes"], [])

    def test_terminal_complete_clears_unclosed_active_stage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            run_id = "auditrun-terminal-clears-active"
            _write_live_solidity_deep_manifest(ws, run_id=run_id)
            _write_g15_sidecar(ws, run_id=run_id)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": run_id,
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows(run_id),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": run_id,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-start",
                        "stage": "deep-freshness",
                        "run_id": run_id,
                        "timestamp_utc": "2000-01-01T00:00:00Z",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": run_id,
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "complete")
            self.assertIsNone(payload["active_stage"])
            self.assertFalse(payload["stale_running"]["stale"])
            self.assertNotIn("stale-running-active-stage", payload["certification_blockers"])

    def test_failed_stage_is_terminal_but_not_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-fail",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-fail",
                        "run_id": "auditrun-fail",
                        "stage": "hunt-full",
                        "rc": 2,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "failed")
            self.assertEqual(payload["terminal_event"], "stage-fail")
            self.assertEqual(payload["terminal_stage"], "hunt-full")
            self.assertFalse(payload["terminal_complete"])
            self.assertFalse(payload["certification_complete"])

    def test_failed_later_stage_preserves_observed_deep_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-late-fail")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-late-fail",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-pass",
                        "stage": "hunt-full",
                        "run_id": "auditrun-late-fail",
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-fail",
                        "stage": "hunt-coverage",
                        "run_id": "auditrun-late-fail",
                        "rc": 2,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "failed")
            self.assertEqual(payload["terminal_event"], "stage-fail")
            self.assertEqual(payload["terminal_stage"], "hunt-coverage")
            self.assertFalse(payload["current_run_deep_proof"])
            self.assertFalse(payload["terminal_deep_proof"])
            self.assertTrue(payload["stage_deep_proof"])
            self.assertEqual(payload["stage_deep_proof_stage"], "hunt-full")
            self.assertEqual(payload["stage_deep_engine_completion_mode"], "fresh-manifest")
            self.assertIsNone(payload["deep_engine_completion_mode"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("latest-run-not-terminal-complete", payload["certification_blockers"])

    def test_failed_stage_surfaces_live_runner_artifact_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_failed_solidity_runner_manifest(ws, run_id="auditrun-runner-fail")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-runner-fail",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-pass",
                        "stage": "hunt-full",
                        "run_id": "auditrun-runner-fail",
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-fail",
                        "stage": "hunt-coverage",
                        "run_id": "auditrun-runner-fail",
                        "rc": 2,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)
            live = payload["live_deep_freshness"]

            self.assertEqual(payload["status"], "failed")
            self.assertFalse(payload["stage_deep_proof"])
            self.assertEqual(live["verdict"], "fail-conflicting-deep-manifest")
            self.assertEqual(live["runner_artifact_error_count"], 1)
            self.assertEqual(live["runner_artifact_errors"][0]["tool"], "echidna-campaign")
            self.assertEqual(live["runner_artifact_errors"][0]["artifact"], ".auditooor/echidna/artifact.json")
            self.assertIn("status_skipped", live["runner_artifact_errors"][0]["reasons"])
            self.assertIn("live-stage-deep-proof-failed", payload["certification_blockers"])

    def test_failed_before_deep_stage_still_reports_live_deep_freshness(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_audit_deep_all_manifest(
                ws,
                run_id="auditrun-early-fail",
                timestamp_utc="2026-05-30T10:01:00Z",
            )
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "12",
                        "run_id": "auditrun-early-fail",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-fail",
                        "stage": "hunt-full",
                        "run_id": "auditrun-early-fail",
                        "rc": 2,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "failed")
            self.assertFalse(payload["stage_deep_proof_claimed"])
            self.assertFalse(payload["current_run_deep_proof"])
            self.assertEqual(payload["live_deep_freshness"]["verdict"], "pass-fresh-deep-manifest")
            self.assertTrue(payload["live_deep_proof"])

    def test_live_deep_proof_rejects_summary_only_audit_deep_all_even_if_live_verdict_is_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            run_id = "auditrun-summary-only-pass"
            _write_g15_sidecar(ws, run_id=run_id)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": run_id,
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows(run_id),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": run_id,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": run_id,
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [".audit_logs/audit_deep_all_manifest.json"],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )
            original = STATUS._live_deep_freshness

            def fake_live_deep_freshness(workspace, manifest_path, requested_run_id):
                return {
                    "ok": True,
                    "verdict": "pass-fresh-deep-manifest",
                    "reason": "forged summary-only pass",
                    "run_id": requested_run_id,
                    "fresh_manifest_paths": [".audit_logs/audit_deep_all_manifest.json"],
                    "blocking_manifest_paths": [],
                    "source_manifest_summaries": [
                        {
                            "path": ".audit_logs/audit_deep_all_manifest.json",
                            "kind": "audit-deep-all-manifest",
                            "fresh": True,
                            "run_id": requested_run_id,
                            "run_id_matches_current": True,
                            "run_id_mismatch": False,
                            "run_id_missing": False,
                            "workspace_matches": True,
                            "schema_matches": True,
                            "completion_source_eligible": False,
                            "execution_ok": True,
                            "execution_reason": "summary manifest only",
                        }
                    ],
                    "runner_artifact_error_count": 0,
                    "runner_artifact_errors": [],
                }

            try:
                STATUS._live_deep_freshness = fake_live_deep_freshness
                payload = STATUS.summarize_manifest(ws)
            finally:
                STATUS._live_deep_freshness = original

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertFalse(payload["live_deep_proof"])
            self.assertFalse(payload["terminal_deep_proof"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("live-current-run-deep-proof-failed", payload["certification_blockers"])

    def test_live_deep_proof_rejects_no_target_engine_summary_even_if_live_verdict_is_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            run_id = "auditrun-no-target-pass"
            _write_g15_sidecar(ws, run_id=run_id)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": run_id,
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows(run_id),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": run_id,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": run_id,
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [".auditooor/solidity-deep-audit/manifest.json"],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )
            original = STATUS._live_deep_freshness

            def fake_live_deep_freshness(workspace, manifest_path, requested_run_id):
                return {
                    "ok": True,
                    "verdict": "pass-fresh-deep-manifest",
                    "reason": "forged no-target pass",
                    "run_id": requested_run_id,
                    "fresh_manifest_paths": [".auditooor/solidity-deep-audit/manifest.json"],
                    "blocking_manifest_paths": [],
                    "source_manifest_summaries": [
                        {
                            "path": ".auditooor/solidity-deep-audit/manifest.json",
                            "kind": "solidity-deep-manifest",
                            "fresh": True,
                            "run_id": requested_run_id,
                            "run_id_matches_current": True,
                            "run_id_mismatch": False,
                            "run_id_missing": False,
                            "workspace_matches": True,
                            "schema_matches": True,
                            "completion_source_eligible": True,
                            "execution_ok": False,
                            "execution_reason": "solidity deep manifest has no load-bearing deep-engine proof artifact",
                        }
                    ],
                    "runner_artifact_error_count": 0,
                    "runner_artifact_errors": [],
                }

            try:
                STATUS._live_deep_freshness = fake_live_deep_freshness
                payload = STATUS.summarize_manifest(ws)
            finally:
                STATUS._live_deep_freshness = original

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertFalse(payload["live_deep_proof"])
            self.assertFalse(payload["terminal_deep_proof"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("live-current-run-deep-proof-failed", payload["certification_blockers"])

    def test_complete_without_terminal_deep_proof_is_not_certified_even_if_stage_had_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-legacy-stage-proof")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-legacy-stage-proof",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-legacy-stage-proof",
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": "auditrun-legacy-stage-proof",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertTrue(payload["terminal_complete"])
            self.assertFalse(payload["current_run_deep_proof"])
            self.assertFalse(payload["terminal_deep_proof"])
            self.assertTrue(payload["stage_deep_proof"])
            self.assertEqual(payload["stage_deep_proof_stage"], "deep-freshness")
            self.assertFalse(payload["certification_complete"])
            self.assertIn("missing-current-run-deep-proof", payload["certification_blockers"])

    def test_complete_with_partial_invariant_denominator_is_explicitly_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            run_id = "auditrun-partial-invariant-denominator"
            _write_live_solidity_deep_manifest(
                ws,
                run_id=run_id,
                extra_fields={
                    "generated_per_function_harness_count": 2,
                    "executed_generated_harness_count": 1,
                },
            )
            _write_g15_sidecar(ws, run_id=run_id)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": 0,
                        "run_id": run_id,
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    *_mandatory_stage_pass_rows(run_id),
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": run_id,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "complete",
                        "run_id": run_id,
                        "workspace": str(ws),
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "uncertified-complete")
            self.assertFalse(payload["certification_complete"])
            self.assertFalse(payload["current_run_deep_proof"])
            self.assertIn(
                "invariant-denominator-partial-execution",
                payload["certification_blockers"],
            )
            self.assertIn(
                "live-current-run-deep-proof-failed",
                payload["certification_blockers"],
            )
            self.assertTrue(payload["invariant_denominator_warnings"])
            self.assertEqual(
                payload["invariant_denominator_warnings"][0]["reason"],
                "denominator_exceeds_executed",
            )
            self.assertEqual(
                payload["invariant_denominator_warnings"][0]["denominator_field"],
                "generated_per_function_harness_count",
            )

    def test_running_status_surfaces_partial_invariant_denominator_as_warning_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            run_id = "auditrun-running-partial-invariant-denominator"
            _write_live_solidity_deep_manifest(
                ws,
                run_id=run_id,
                extra_fields={
                    "generated_per_function_harness_count": 3,
                    "executed_generated_harness_count": 1,
                },
            )
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": 0,
                        "run_id": run_id,
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-start",
                        "stage": "hunt-full",
                        "run_id": run_id,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "running")
            self.assertIn("latest-run-not-terminal-complete", payload["certification_blockers"])
            self.assertNotIn(
                "invariant-denominator-partial-execution",
                payload["certification_blockers"],
            )
            self.assertTrue(payload["invariant_denominator_warnings"])
            self.assertEqual(
                payload["invariant_denominator_warnings"][0]["reason"],
                "denominator_exceeds_executed",
            )

    def test_failed_hunt_coverage_surfaces_matching_g15_last_result(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            run_id = "auditrun-g15-fail"
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": run_id,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-pass",
                        "stage": "hunt-full",
                        "run_id": run_id,
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-fail",
                        "stage": "hunt-coverage",
                        "run_id": run_id,
                        "rc": 2,
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )
            sidecar = ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
            sidecar.write_text(
                json.dumps({
                    "schema": "auditooor.g15_hunt_coverage_gate.v1",
                    "run_id": run_id,
                    "generated_at_utc": "2026-05-31T13:07:07Z",
                    "strict": True,
                    "min_coverage": 1.0,
                    "verdict": "fail-queued-not-scanned",
                    "reason": "6 queued units have no scan artifact",
                    "covered": 134,
                    "total_units": 185,
                    "coverage_fraction": 0.724324,
                    "queued_not_scanned": ["Midnight.sol::multicall"],
                    "detector_only_not_queued": [],
                    "unlogged_uncovered": [],
                }),
                encoding="utf-8",
            )

            payload = STATUS.summarize_manifest(ws)
            g15 = payload["g15_hunt_coverage"]

            self.assertEqual(payload["status"], "failed")
            self.assertTrue(g15["present"])
            self.assertTrue(g15["matches_latest_run"])
            self.assertEqual(g15["verdict"], "fail-queued-not-scanned")
            self.assertEqual(g15["reason"], "6 queued units have no scan artifact")
            self.assertEqual(g15["queued_not_scanned_count"], 1)
            self.assertEqual(g15["covered"], 134)
            self.assertEqual(g15["total_units"], 185)
            self.assertIn("live-stage-deep-proof-failed", payload["certification_blockers"])

    def test_g15_last_result_reports_stale_run_id_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-current",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-start",
                        "stage": "hunt-coverage",
                        "run_id": "auditrun-current",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )
            sidecar = ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
            sidecar.write_text(
                json.dumps({
                    "schema": "auditooor.g15_hunt_coverage_gate.v1",
                    "run_id": "auditrun-old",
                    "verdict": "fail-coverage-below-threshold",
                }),
                encoding="utf-8",
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertFalse(payload["g15_hunt_coverage"]["matches_latest_run"])
            self.assertEqual(payload["g15_hunt_coverage"]["run_id"], "auditrun-old")

    def test_bounded_complete_uses_deep_freshness_stage_for_stage_deep_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_live_solidity_deep_manifest(ws, run_id="auditrun-bounded-stage-proof")
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "12",
                        "run_id": "auditrun-bounded-stage-proof",
                        "timestamp_utc": "2026-05-30T10:00:00Z",
                        "workspace": str(ws),
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "stage-pass",
                        "stage": "deep-freshness",
                        "run_id": "auditrun-bounded-stage-proof",
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "bounded-complete",
                        "run_id": "auditrun-bounded-stage-proof",
                        "workspace": str(ws),
                        "max_functions": "12",
                        "deep_engine_completion_mode": "fresh-manifest",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                        "fresh_manifest_paths": [
                            str(ws / ".auditooor" / "solidity-deep-audit" / "manifest.json")
                        ],
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "bounded-complete")
            self.assertTrue(payload["successful_terminal"])
            self.assertTrue(payload["stage_deep_proof"])
            self.assertEqual(payload["stage_deep_proof_event"], "stage-pass")
            self.assertEqual(payload["stage_deep_proof_stage"], "deep-freshness")
            self.assertFalse(payload["current_run_deep_proof"])
            self.assertFalse(payload["terminal_deep_proof"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("bounded-terminal-not-certifying", payload["certification_blockers"])
            self.assertNotIn("latest-run-not-terminal-complete", payload["certification_blockers"])

    def test_full_scope_bounded_complete_is_terminal_but_not_certifying(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "0",
                        "run_id": "auditrun-full-scope-bounded",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                    {
                        "event": "bounded-complete",
                        "run_id": "auditrun-full-scope-bounded",
                        "workspace": str(ws),
                        "max_functions": "0",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    },
                ],
            )

            payload = STATUS.summarize_manifest(ws)

            self.assertEqual(payload["status"], "bounded-complete")
            self.assertTrue(payload["successful_terminal"])
            self.assertTrue(payload["full_scope"])
            self.assertFalse(payload["terminal_complete"])
            self.assertFalse(payload["certification_complete"])
            self.assertIn("bounded-terminal-not-certifying", payload["certification_blockers"])
            self.assertNotIn("bounded-run", payload["certification_blockers"])
            self.assertNotIn("latest-run-not-terminal-complete", payload["certification_blockers"])

    def test_cli_outputs_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_status_") as tmp:
            ws = Path(tmp)
            _write_manifest(
                ws,
                [
                    {
                        "event": "start",
                        "max_functions": "12",
                        "run_id": "auditrun-cli",
                        "schema": "auditooor.audit_run_full_manifest.v1",
                    }
                ],
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), str(ws)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema"], "auditooor.audit_run_full_status.v1")
            self.assertEqual(payload["latest_run_id"], "auditrun-cli")


if __name__ == "__main__":
    unittest.main()
