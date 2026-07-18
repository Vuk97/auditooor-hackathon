#!/usr/bin/env python3
"""Tests for tools/audit-closeout-check.py — the close-out gate.

Stdlib-only, hermetic via ``tempfile.TemporaryDirectory``. Each test
scaffolds a workspace tree that exercises one shape:

  1. fully healthy            -> overall PASS (no FAIL rows)
  2. missing deep manifest    -> WARN by default, FAIL with --require-deep
  3. HYPOTHESIS_PROMPT only   -> FAIL on the hypotheses check (Gap-23)
  4. no pattern mining + no skip marker -> FAIL on pattern-mining
  5. no pattern mining + skip marker    -> WARN (with marker reason in row)
  6. agent_outputs/ but no synthesis JSON -> WARN on agent-synthesize
  7. staging draft, no packaged bundle, no production-path -> FAIL when
     draft is High/Critical (FAIL on pre-submit) OR WARN otherwise
  8. P0 items in gaps doc, no follow-up tracking -> WARN on p0-followups

The tool import path is loaded via ``importlib`` because the script name
contains a hyphen (``audit-closeout-check.py``).
"""
from __future__ import annotations

import importlib.util
import io
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "audit-closeout-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "audit_closeout_check", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Python 3.14 dataclass machinery looks the class's module up via
    # ``sys.modules[cls.__module__].__dict__`` — register the module before
    # exec'ing so ``@dataclass`` doesn't crash on KW_ONLY detection.
    sys.modules["audit_closeout_check"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _scaffold_healthy(ws: Path) -> None:
    """Write the artifact tree a healthy ``make audit`` run leaves behind."""
    (ws / ".audit_logs").mkdir(parents=True, exist_ok=True)
    (ws / "swarm" / "mining_briefs").mkdir(parents=True, exist_ok=True)
    (ws / "swarm" / "mining_briefs" / "brief_001.md").write_text("# brief\n")
    (ws / "swarm" / "mining_priorities.json").write_text("[]\n")
    # Synthesis JSON must be substantive (non-empty) — the closeout tool
    # rejects empty `[]` to defeat fabricated completion (Minimax Gap 4).
    (ws / "swarm" / "brief_candidates.json").write_text(
        json.dumps([{"id": "B1", "candidate": "demo"}]) + "\n"
    )
    (ws / "swarm" / "agent_verdicts.json").write_text(
        json.dumps([{"id": "V1", "verdict": "pending"}]) + "\n"
    )
    (ws / "submissions" / "packaged").mkdir(parents=True, exist_ok=True)
    # Real packaged bundles are subdirectories per submission; a stray
    # placeholder file does not count (Kimi Bug 1).
    (ws / "submissions" / "packaged" / "demo_bundle").mkdir()
    (ws / "submissions" / "packaged" / "demo_bundle" / "manifest.json").write_text(
        json.dumps({"production_path": {"items": ["item-1"]}}) + "\n"
    )
    (ws / "engage_report.md").write_text("# engage report\n")
    (ws / "INTAKE_BASELINE.json").write_text('{"ok": true}\n')
    (ws / "SCAN_REPORT.md").write_text("# scan\n")
    (ws / "PATTERN_HITS.md").write_text("# patterns\n")
    (ws / "cross_ws_patterns.md").write_text("# cross\n")
    (ws / "detector_environment_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "auditooor.detector_environment.v1",
                "workspace": str(ws),
                "versions": {
                    "python": "test",
                    "slither": "missing",
                    "solc": "missing",
                    "solc-select": "missing",
                },
                "tool_status": {"detectors/run_custom.py": "SKIPPED (no .sol)"},
                "skipped_compilation_counts": {
                    "skipped_tools": 0,
                    "compile_failure_markers": 0,
                    "modules_failed": 0,
                    "total": 0,
                },
            }
        )
        + "\n"
    )
    (ws / "HYPOTHESIS_PROMPT.md").write_text("# prompt\n")
    (ws / "HYPOTHESES.md").write_text("# final\n")
    # Deep manifest with all 4 child profiles success.
    deep = {
        "schema": "auditooor.audit_deep_all.v1",
        "workspace": str(ws),
        "profiles": [
            {"profile": "default", "status": "success", "exit_code": 0,
             "log": None, "captured_report": None},
            {"profile": "math", "status": "success", "exit_code": 0,
             "log": None, "captured_report": None},
            {"profile": "econ", "status": "skipped_budget", "exit_code": 0,
             "log": None, "captured_report": None},
            {"profile": "crypto", "status": "skipped_inapplicable",
             "exit_code": 0, "log": None, "captured_report": None},
        ],
    }
    (ws / ".audit_logs" / "audit_deep_all_manifest.json").write_text(
        json.dumps(deep, indent=2) + "\n"
    )


def _write_deep_engine_truth_manifest(
    ws: Path,
    *,
    truth_label: str,
    truth_reason: str,
    engine_executed: bool | None,
    targets_discovered: bool | None,
    parser_status: str,
    status: str = "recorded",
) -> Path:
    deep_dir = ws / "deep_counterexamples"
    deep_dir.mkdir(parents=True, exist_ok=True)
    manifest = deep_dir / "recon_log_bridge_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "auditooor.recon_log_bridge.v1",
                "workspace": str(ws),
                "engine": "halmos",
                "source_log": str(ws / "logs" / "recon.log"),
                "status": status,
                "truth_label": truth_label,
                "truth_reason": truth_reason,
                "engine_executed": engine_executed,
                "targets_discovered": targets_discovered,
                "parser_status": parser_status,
                "parser": "stdlib-fallback",
                "parser_version": "",
                "records": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def _write_memory_context_fixture(
    ws: Path,
    *,
    fresh_after_refs: list[str] | None = None,
    write_receipt: bool = True,
    receipt_proof_mode: str = "missing",
    generated_at: str = "1999-12-31T23:59:00Z",
    loaded_at: str = "2000-01-01T00:00:00Z",
) -> None:
    aud = ws / ".auditooor"
    packs = aud / "memory_context_packs"
    packs.mkdir(parents=True, exist_ok=True)
    req = {
        "schema": "auditooor.workspace_memory_requirements.v1",
        "workspace": "demo",
        "workspace_path": str(ws),
        "generated_at": generated_at,
        "generator": "tools/memory-auto-link.py",
        "workspace_facts": {
            "languages": ["unknown"],
            "artifact_predicates": [],
            "newest_input_mtime": None,
        },
        "requirements": [
            {
                "requirement_id": "base.resume",
                "context_kind": "resume",
                "tool": "vault_resume_context",
                "args": {"workspace_path": str(ws), "limit": 8},
                "required_by": ["flow-gate", "closeout"],
                "reason": "resume",
                "matched_predicates": ["workspace_exists"],
                "fresh_after_refs": fresh_after_refs or [],
                "strictness": "warn_default",
            }
        ],
    }
    req_path = aud / "memory_requirements.json"
    req_path.write_text(json.dumps(req, indent=2, sort_keys=True) + "\n")
    pack_body = {
        "schema": "auditooor.vault_context_pack.v1",
        "kind": "resume",
        "source_refs": ["docs/VAULT_MCP_SERVER.md"],
        "knowledge_gap_refs": [],
    }
    digest = hashlib.sha256(
        json.dumps(
            pack_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()
    pack = {
        "context_pack_id": f"auditooor.vault_context_pack.v1:resume:{digest[:16]}",
        "context_pack_hash": digest,
        **pack_body,
    }
    pack_path = packs / f"{pack['context_pack_id']}.json"
    pack_path.write_text(json.dumps(pack, indent=2, sort_keys=True) + "\n")
    if not write_receipt:
        return
    args_hash = hashlib.sha256(
        json.dumps(
            req["requirements"][0]["args"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    receipt = {
        "schema": "auditooor.memory_context_receipt.v1",
        "workspace": "demo",
        "workspace_path": str(ws),
        "generated_at": "2026-05-06T00:01:00Z",
        "loader": {
            "tool": "tools/memory-context-load.py",
            "command": "python3 tools/memory-context-load.py --workspace demo --from-requirements --write-receipt",
            "argv_hash": "0" * 64,
        },
        "requirements_path": str(req_path),
        "requirements_hash": hashlib.sha256(req_path.read_bytes()).hexdigest(),
        "loaded_contexts": [
            {
                "requirement_id": "base.resume",
                "context_kind": "resume",
                "tool": "vault_resume_context",
                "args_hash": args_hash,
                "context_pack_id": pack["context_pack_id"],
                "context_pack_hash": pack["context_pack_hash"],
                "pack_path": str(pack_path),
                "pack_schema": pack["schema"],
                "loaded_at": loaded_at,
                "status": "loaded",
                "source_refs": ["docs/VAULT_MCP_SERVER.md"],
                "knowledge_gap_refs": [],
            }
        ],
        "missing_contexts": [],
        "summary": {
            "required_count": 1,
            "loaded_count": 1,
            "missing_count": 0,
            "stale_count": 0,
            "strict_ready": True,
        },
    }
    receipt_body = dict(receipt)
    if receipt_proof_mode == "valid":
        receipt["receipt_proof"] = hashlib.sha256(
            json.dumps(
                receipt_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest()
    elif receipt_proof_mode == "invalid":
        receipt["receipt_proof"] = "f" * 64
    elif receipt_proof_mode != "missing":
        raise ValueError(f"unsupported receipt_proof_mode: {receipt_proof_mode}")
    (aud / "memory_context_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    )


def _by_check(results) -> dict:
    return {r.check: r for r in results}


def _write_hacker_question_obligation(ws: Path, *, state: str = "open") -> None:
    path = ws / ".auditooor" / "hacker_question_obligations.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "schema": "auditooor.hacker_question_obligation.v1",
        "obligation_id": "hqcloseout01",
        "workspace": str(ws),
        "file": "src/Vault.sol",
        "function_signature": "function withdraw(uint256 amount) external",
        "function_name": "withdraw",
        "attack_class": "reentrancy",
        "question": "Can withdraw re-enter before accounting is finalized?",
        "state": state,
    }
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")


def _write_go_dlt_enforcement_manifest(
    ws: Path,
    *,
    status: str = "pass",
    reason: str = "canonical make audit evidence present before Go/DLT audit-deep step",
    marker_exists: bool = True,
    marker_fresh: bool = True,
    check_rc: int = 0,
) -> Path:
    manifest = ws / ".audit_logs" / "go_dlt_audit_enforcement.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps(
            {
                "schema": "auditooor.go_dlt_audit_enforcement.v1",
                "workspace": str(ws),
                "timestamp_utc": "2026-05-06T00:00:00Z",
                "profile": "all",
                "dry_run": True,
                "status": status,
                "reason": reason,
                "required_commands": [
                    "make audit WS=<workspace>",
                    "make audit-deep WS=<workspace>",
                ],
                "audit_completion": {
                    "path": str(ws / ".audit_logs" / "audit_completion.json"),
                    "exists": marker_exists,
                    "fresh_for_workspace": marker_fresh,
                    "check_rc": check_rc,
                    "check_stdout": "ok" if check_rc == 0 else "stale",
                },
                "audit_deep_report": str(ws / ".audit_logs" / "audit_deep_report.md"),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


class FullyHealthyTest(unittest.TestCase):
    """Case 1: a fully scaffolded workspace produces no FAIL rows."""

    def test_healthy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            results = MOD.run_all(ws, require_deep=False)
            by = _by_check(results)
            statuses = {k: v.status for k, v in by.items()}
            n_fail = sum(1 for r in results if r.status == MOD.FAIL)
            self.assertEqual(
                n_fail, 0,
                f"expected zero FAIL rows; got statuses={statuses}",
            )

    def test_deep_candidates_without_promotion_report_warn(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            (ws / "deep_candidates").mkdir()
            (ws / "deep_candidates" / "source_mine_001.json").write_text(
                json.dumps({"schema_version": "deep_candidate.v1"}) + "\n"
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["audit-deep-all"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("typed_candidate_promotions.json is missing", row.reason)
            self.assertEqual(row.detail["deep_candidate_count"], 1)

    def test_deep_candidates_with_promotion_report_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            (ws / "deep_candidates").mkdir()
            (ws / "deep_candidates" / "source_mine_001.json").write_text(
                json.dumps({"schema_version": "deep_candidate.v1"}) + "\n"
            )
            (ws / ".audit_logs" / "typed_candidate_promotions.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.promote_typed_candidate.v1",
                        "candidate_count": 1,
                        "decision_counts": {
                            "poc_ready": 0,
                            "needs_poc": 1,
                            "rejected": 0,
                        },
                        "blocker_counts": {"production_path_missing": 1},
                        "work_items": [{"candidate_id": "source-mine-1"}],
                    }
                )
                + "\n"
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["audit-deep-all"]
            self.assertEqual(row.status, MOD.PASS)
            self.assertIn("typed candidate promotion report present", row.reason)
            self.assertIn("blockers: production_path_missing=1", row.reason)
            self.assertEqual(row.detail["promotion_candidate_count"], 1)
            self.assertEqual(row.detail["promotion_blocker_counts"], {"production_path_missing": 1})
            self.assertEqual(row.detail["promotion_work_item_count"], 1)
            by = _by_check(results)
            # Spot-check: canonical-audit and audit-deep-all must be PASS.
            self.assertEqual(by["canonical-audit"].status, MOD.PASS)
            self.assertEqual(by["audit-deep-all"].status, MOD.PASS)
            self.assertEqual(by["pattern-mining"].status, MOD.PASS)
            self.assertEqual(by["hypotheses"].status, MOD.PASS)
            self.assertEqual(by["agent-synthesize"].status, MOD.PASS)

    def test_detector_environment_manifest_passes_when_clean(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            row = MOD.check_detector_environment(ws)
            self.assertEqual(row.status, MOD.PASS)
            self.assertIn("manifest present", row.reason)
            self.assertEqual(row.detail["skipped_compilation_counts"]["total"], 0)

    def test_detector_environment_manifest_missing_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            (ws / "detector_environment_manifest.json").unlink()
            row = MOD.check_detector_environment(ws)
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("detector_environment_manifest.json missing", row.reason)

    def test_go_dlt_enforcement_missing_is_pass_for_non_go_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            row = MOD.check_go_dlt_audit_enforcement(ws)
            self.assertEqual(row.status, MOD.PASS)
            self.assertIn("no non-vendor Go files detected", row.reason)
            self.assertFalse(row.detail["go_files_detected"])
            self.assertFalse(row.detail["machine_summary"]["manifest_present"])

    def test_go_dlt_enforcement_missing_warns_for_go_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            (ws / "cmd").mkdir()
            (ws / "cmd" / "main.go").write_text("package main\n", encoding="utf-8")
            row = MOD.check_go_dlt_audit_enforcement(ws)
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("go_dlt_audit_enforcement.json missing", row.reason)
            self.assertTrue(row.detail["go_files_detected"])

    def test_go_dlt_enforcement_pass_manifest_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            (ws / "cmd").mkdir()
            (ws / "cmd" / "main.go").write_text("package main\n", encoding="utf-8")
            manifest = _write_go_dlt_enforcement_manifest(ws)
            row = MOD.check_go_dlt_audit_enforcement(ws)
            self.assertEqual(row.status, MOD.PASS)
            self.assertIn("audit completion marker is fresh", row.reason)
            self.assertEqual(row.artifacts, [str(manifest)])
            self.assertTrue(row.detail["machine_summary"]["audit_completion_exists"])
            self.assertTrue(
                row.detail["machine_summary"]["audit_completion_fresh_for_workspace"]
            )

    def test_go_dlt_enforcement_stale_pass_manifest_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            _write_go_dlt_enforcement_manifest(
                ws,
                marker_exists=True,
                marker_fresh=False,
                check_rc=1,
            )
            row = MOD.check_go_dlt_audit_enforcement(ws)
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("not fresh for this workspace", row.reason)
            self.assertEqual(row.detail["machine_summary"]["manifest_status"], "pass")

    def test_go_dlt_enforcement_fail_manifest_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            _write_go_dlt_enforcement_manifest(
                ws,
                status="fail",
                reason="run make audit WS=<workspace> before audit-deep",
                marker_exists=False,
                marker_fresh=False,
                check_rc=1,
            )
            row = MOD.check_go_dlt_audit_enforcement(ws)
            self.assertEqual(row.status, MOD.FAIL)
            self.assertIn("run make audit", row.reason)
            self.assertFalse(row.detail["machine_summary"]["audit_completion_exists"])

    def test_detector_environment_manifest_skipped_counts_warn(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            manifest = ws / "detector_environment_manifest.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["skipped_compilation_counts"] = {
                "skipped_tools": 1,
                "compile_failure_markers": 2,
                "modules_failed": 3,
                "total": 6,
            }
            manifest.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            row = MOD.check_detector_environment(ws)
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("skipped/failed detector coverage", row.reason)
            self.assertIn("compile_failure_markers=2", row.reason)
            self.assertEqual(row.detail["skipped_compilation_counts"]["total"], 6)
            machine = row.detail["machine_summary"]
            self.assertEqual(
                machine["schema_version"],
                "auditooor.detector_environment_closeout_summary.v1",
            )
            self.assertTrue(machine["manifest_valid"])
            self.assertTrue(machine["has_skip_failures"])
            self.assertEqual(machine["skip_fail_total"], 6)
            self.assertEqual(machine["skip_fail_counts"]["modules_failed"], 3)
            self.assertEqual(machine["tool_status_counts"]["SKIPPED"], 1)

    def test_pre_submit_surfaces_detector_environment_skips(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "demo_bundle.md").write_text(
                "## Summary\n\nSeverity: Medium\n\n## Production Path\n\nsource path\n",
                encoding="utf-8",
            )
            manifest = ws / "detector_environment_manifest.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["skipped_compilation_counts"] = {
                "skipped_tools": 0,
                "compile_failure_markers": 1,
                "modules_failed": 2,
                "total": 3,
            }
            manifest.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            row = MOD.check_pre_submit(ws)
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("detector environment manifest reports skipped/failed", row.reason)
            self.assertIn("compile_failure_markers=1", row.reason)
            self.assertEqual(
                row.detail["detector_environment"]["skipped_compilation_total"],
                3,
            )
            machine = row.detail["detector_environment"]["machine_summary"]
            self.assertEqual(machine["skip_fail_total"], 3)
            self.assertTrue(machine["has_skip_failures"])

    def test_pre_submit_warns_when_detector_environment_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "demo_bundle.md").write_text(
                "## Summary\n\nSeverity: Medium\n\n## Production Path\n\nsource path\n",
                encoding="utf-8",
            )
            (ws / "detector_environment_manifest.json").unlink()
            row = MOD.check_pre_submit(ws)
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("detector_environment_manifest.json missing", row.reason)
            self.assertFalse(row.detail["detector_environment"]["present"])
            self.assertFalse(row.detail["detector_environment"]["machine_summary"]["manifest_present"])

    def test_poc_briefs_without_execution_manifest_warn(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            brief_dir = ws / "source_mining" / "run-1" / "poc_task_briefs"
            brief_dir.mkdir(parents=True)
            (brief_dir / "001-cand.md").write_text("# PoC Dispatch Brief\n", encoding="utf-8")
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertEqual(row.detail["brief_count"], 1)
            self.assertEqual(row.detail["execution_manifest_count"], 0)

    def test_poc_brief_warn_reports_oldest_unexecuted_queue_item(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            brief_dir = ws / "source_mining" / "run-1" / "poc_task_briefs"
            brief_dir.mkdir(parents=True)
            oldest = brief_dir / "001-old.md"
            newest = brief_dir / "002-new.md"
            oldest.write_text("# old PoC Dispatch Brief\n", encoding="utf-8")
            newest.write_text("# new PoC Dispatch Brief\n", encoding="utf-8")
            # Use fresh mtimes (relative to ``time.time()``) so the row stays
            # WARN — we only want to verify that the oldest-item reason text
            # threads through. The P2-4 age-staleness FAIL promotion has its
            # own dedicated test below.
            now = time.time()
            os.utime(oldest, (now - 2 * 86400, now - 2 * 86400))
            os.utime(newest, (now - 1 * 86400, now - 1 * 86400))

            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("oldest unexecuted queue item", row.reason)
            self.assertIn(str(oldest), row.reason)
            self.assertEqual(row.detail["unexecuted_queue_item_count"], 2)
            self.assertEqual(row.detail["oldest_unexecuted_queue_item"]["kind"], "poc_task_brief")
            self.assertEqual(row.detail["oldest_unexecuted_queue_item"]["path"], str(oldest))
            self.assertEqual(row.detail["oldest_unexecuted_queue_item"]["owner"], "poc-execution")
            # P2-4: per-queue summaries appear in the detail and the reason.
            self.assertIn("per-queue", row.reason)
            per_queue = {b["queue"]: b for b in row.detail["per_queue_summaries"]}
            self.assertIn("poc_task_brief", per_queue)
            self.assertEqual(per_queue["poc_task_brief"]["count"], 2)
            self.assertEqual(per_queue["poc_task_brief"]["status"], MOD.PASS)
            self.assertEqual(row.detail["queue_age_warn_days"], 7)
            self.assertEqual(row.detail["queue_age_fail_days"], 30)

    def test_poc_brief_age_threshold_fail_promotes_warn_to_fail(self) -> None:
        """P2-4: a queue item older than ``AUDITOOOR_QUEUE_FAIL_DAYS``
        (default 30) promotes the poc-execution WARN row to FAIL."""
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            brief_dir = ws / "source_mining" / "run-1" / "poc_task_briefs"
            brief_dir.mkdir(parents=True)
            stale = brief_dir / "001-stale.md"
            stale.write_text("# stale PoC Dispatch Brief\n", encoding="utf-8")
            now = time.time()
            os.utime(stale, (now - 60 * 86400, now - 60 * 86400))

            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.FAIL)
            self.assertEqual(row.detail["queue_age_status"], MOD.FAIL)
            per_queue = {b["queue"]: b for b in row.detail["per_queue_summaries"]}
            self.assertEqual(per_queue["poc_task_brief"]["status"], MOD.FAIL)
            self.assertGreater(per_queue["poc_task_brief"]["oldest_age_days"], 30)

    def test_poc_brief_require_no_stale_queues_promotes_warn_to_fail(self) -> None:
        """P2-4: ``REQUIRE_NO_STALE_QUEUES=1`` promotes a WARN-aged queue
        item (>= 7d, < 30d) all the way to FAIL."""
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            brief_dir = ws / "source_mining" / "run-1" / "poc_task_briefs"
            brief_dir.mkdir(parents=True)
            warning = brief_dir / "001-warn.md"
            warning.write_text("# WARN-aged PoC Dispatch Brief\n", encoding="utf-8")
            now = time.time()
            os.utime(warning, (now - 10 * 86400, now - 10 * 86400))

            with mock.patch.dict(os.environ, {"REQUIRE_NO_STALE_QUEUES": "1"}):
                results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.FAIL)
            self.assertTrue(row.detail["queue_age_require_no_stale"])

    def test_poc_brief_warn_reports_owner_counts_and_threshold(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            brief_dir = ws / "source_mining" / "run-1" / "poc_task_briefs"
            brief_dir.mkdir(parents=True)
            for index in range(5):
                (brief_dir / f"{index:03d}-cand.md").write_text(
                    "# PoC Dispatch Brief\n",
                    encoding="utf-8",
                )

            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("stale queue threshold exceeded", row.reason)
            self.assertIn("owners: poc-execution=5", row.reason)
            self.assertEqual(row.detail["unexecuted_queue_owner_counts"], {"poc-execution": 5})
            self.assertEqual(row.detail["unexecuted_queue_count_review_threshold"], 5)
            self.assertTrue(row.detail["unexecuted_queue_count_threshold_exceeded"])

    def test_poc_briefs_with_execution_manifest_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            brief_dir = ws / "source_mining" / "run-1" / "poc_task_briefs"
            brief_dir.mkdir(parents=True)
            (brief_dir / "001-cand.md").write_text("# PoC Dispatch Brief\n", encoding="utf-8")
            manifest = ws / "poc_execution" / "cand" / "execution_manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps({
                    "candidate_id": "cand",
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "foundry_version_inventory": {
                        "planned_target": {"foundry_version": "v1.7.1"}
                    },
                })
                + "\n",
                encoding="utf-8",
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.PASS)
            self.assertEqual(row.detail["brief_count"], 1)
            self.assertEqual(row.detail["execution_manifest_count"], 1)

    def test_poc_execution_manifest_missing_brief_path_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            brief_dir = ws / "source_mining" / "run-1" / "poc_task_briefs"
            brief_dir.mkdir(parents=True)
            brief = brief_dir / "001-cand.md"
            brief.write_text("# PoC Dispatch Brief\n", encoding="utf-8")
            manifest = ws / "poc_execution" / "cand" / "execution_manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps({
                    "candidate_id": "cand",
                    "brief_path": str(brief),
                    "final_result": "disproved",
                    "impact_assertion": "not_demonstrated",
                    "commands_attempted": [{"command": "forge test", "exit_code": 0}],
                })
                + "\n",
                encoding="utf-8",
            )
            brief.unlink()
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("missing brief_path", row.reason)
            self.assertEqual(row.detail["execution_manifest_count"], 1)
            self.assertFalse(row.detail["manifest_rows"][0]["brief_path_exists"])

    def test_poc_execution_manifest_needs_human_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            brief_dir = ws / "source_mining" / "run-1" / "poc_task_briefs"
            brief_dir.mkdir(parents=True)
            (brief_dir / "001-cand.md").write_text("# PoC Dispatch Brief\n", encoding="utf-8")
            manifest = ws / "poc_execution" / "cand" / "execution_manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps({"candidate_id": "cand", "final_result": "needs_human"}) + "\n",
                encoding="utf-8",
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("needs_human", row.reason)

    def test_poc_execution_manifest_proved_without_impact_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            brief_dir = ws / "source_mining" / "run-1" / "poc_task_briefs"
            brief_dir.mkdir(parents=True)
            (brief_dir / "001-cand.md").write_text("# PoC Dispatch Brief\n", encoding="utf-8")
            manifest = ws / "poc_execution" / "cand" / "execution_manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps({
                    "candidate_id": "cand",
                    "final_result": "proved",
                    "impact_assertion": "setup_or_branch_only",
                })
                + "\n",
                encoding="utf-8",
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.FAIL)
            self.assertIn("without impact_assertion", row.reason)

    def test_poc_execution_manifest_without_foundry_inventory_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            brief_dir = ws / "source_mining" / "run-1" / "poc_task_briefs"
            brief_dir.mkdir(parents=True)
            (brief_dir / "001-cand.md").write_text("# PoC Dispatch Brief\n", encoding="utf-8")
            manifest = ws / "poc_execution" / "cand" / "execution_manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps({
                    "candidate_id": "cand",
                    "final_result": "disproved",
                    "impact_assertion": "not_demonstrated",
                })
                + "\n",
                encoding="utf-8",
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("foundry_version_inventory", row.reason)
            self.assertEqual(row.detail["missing_foundry_inventory_count"], 1)

    def test_deep_counterexample_without_execution_manifest_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            record = ws / "deep_counterexamples" / "halmos-vault.deep_counterexample.v1.json"
            record.parent.mkdir(parents=True)
            record.write_text(
                json.dumps({
                    "schema_version": "auditooor.deep_counterexample.v1",
                    "engine": "halmos",
                    "target_function": "Vault.withdraw",
                    "expected_invariant": "shares decrease",
                    "observed_violation": "shares unchanged",
                    "replay_impossible_reason": "runner trace has no Forge replay yet",
                    "promotes_to_poc_work": False,
                })
                + "\n",
                encoding="utf-8",
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertEqual(row.detail["brief_count"], 0)
            self.assertEqual(row.detail["deep_counterexample_count"], 1)
            self.assertIn("deep counterexample", row.reason)

    def test_deep_counterexample_queue_owner_flows_to_closeout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            record = ws / "deep_counterexamples" / "halmos-vault.deep_counterexample.v1.json"
            record.parent.mkdir(parents=True)
            record.write_text(
                json.dumps({
                    "schema_version": "auditooor.deep_counterexample.v1",
                    "engine": "halmos",
                    "target_function": "Vault.withdraw",
                    "expected_invariant": "shares decrease",
                    "observed_violation": "shares unchanged",
                    "replay_impossible_reason": "runner trace has no Forge replay yet",
                    "promotes_to_poc_work": False,
                })
                + "\n",
                encoding="utf-8",
            )
            (record.parent / "execution_queue.json").write_text(
                json.dumps({
                    "schema_version": "auditooor.deep_counterexample_queue.v1",
                    "items": [
                        {
                            "record_path": str(record),
                            "assigned_model": "kimi+minimax",
                        }
                    ],
                })
                + "\n",
                encoding="utf-8",
            )

            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("owner=kimi+minimax", row.reason)
            self.assertEqual(row.detail["oldest_unexecuted_queue_item"]["owner"], "kimi+minimax")
            self.assertEqual(row.detail["unexecuted_queue_owner_counts"], {"kimi+minimax": 1})

    def test_deep_counterexample_with_execution_manifest_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            record = ws / "deep_counterexamples" / "halmos-vault.deep_counterexample.v1.json"
            record.parent.mkdir(parents=True)
            record.write_text(
                json.dumps({
                    "schema_version": "auditooor.deep_counterexample.v1",
                    "engine": "halmos",
                    "target_function": "Vault.withdraw",
                    "expected_invariant": "shares decrease",
                    "observed_violation": "shares unchanged",
                    "replay_command": "forge test --match-test test_replay",
                    "generated_forge_test_path": "poc-tests/VaultReplay.t.sol",
                    "promotes_to_poc_work": True,
                })
                + "\n",
                encoding="utf-8",
            )
            manifest = ws / "poc_execution" / "halmos-vault" / "execution_manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps({
                    "candidate_id": "halmos-vault",
                    "final_result": "disproved",
                    "impact_assertion": "not_demonstrated",
                    "foundry_version_inventory": {
                        "planned_target": {"foundry_version": "v1.7.1"}
                    },
                })
                + "\n",
                encoding="utf-8",
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.PASS)
            self.assertEqual(row.detail["brief_count"], 0)
            self.assertEqual(row.detail["deep_counterexample_count"], 1)

    def test_deep_engine_truth_label_non_clean_runs_warn(self) -> None:
        cases = [
            (
                "setup_failure",
                "Foundry setUp aborted before any target execution",
                False,
                None,
                "recorded",
            ),
            (
                "tooling_failure",
                "engine binary failed before fuzzing started",
                False,
                None,
                "recorded",
            ),
            (
                "no_targets",
                "No contracts or properties were discovered",
                False,
                False,
                "recorded",
            ),
            (
                "zero_execution",
                "runs=0 and calls=0; no execution happened",
                False,
                None,
                "recorded",
            ),
            (
                "parser_failure",
                "parser could not decode the native log output",
                None,
                None,
                "error",
            ),
        ]
        for truth_label, truth_reason, engine_executed, targets_discovered, parser_status in cases:
            with self.subTest(truth_label=truth_label):
                with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
                    ws = Path(tmp)
                    _scaffold_healthy(ws)
                    _write_deep_engine_truth_manifest(
                        ws,
                        truth_label=truth_label,
                        truth_reason=truth_reason,
                        engine_executed=engine_executed,
                        targets_discovered=targets_discovered,
                        parser_status=parser_status,
                    )
                    results = MOD.run_all(ws, require_deep=False)
                    row = _by_check(results)["poc-execution"]
                    self.assertEqual(row.status, MOD.WARN)
                    self.assertIn("deep-engine truth", row.reason)
                    truth = row.detail["deep_engine_truth"]
                    self.assertTrue(truth["manifest_present"])
                    self.assertEqual(truth["status"], "warn")
                    self.assertEqual(truth["truth_label_counts"][truth_label], 1)
                    self.assertEqual(truth["rows"][0]["truth_label"], truth_label)
                    self.assertEqual(truth["rows"][0]["classification"], "non_clean")

    def test_deep_engine_truth_label_counterexample_remains_evidence_bearing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            _write_deep_engine_truth_manifest(
                ws,
                truth_label="counterexample",
                truth_reason="parser recorded a failing property",
                engine_executed=True,
                targets_discovered=True,
                parser_status="ok",
            )
            record = ws / "deep_counterexamples" / "halmos-vault.deep_counterexample.v1.json"
            record.parent.mkdir(parents=True, exist_ok=True)
            record.write_text(
                json.dumps({
                    "schema_version": "auditooor.deep_counterexample.v1",
                    "engine": "halmos",
                    "target_function": "Vault.withdraw",
                    "expected_invariant": "shares decrease",
                    "observed_violation": "shares unchanged",
                    "replay_command": "forge test --match-test test_replay",
                    "generated_forge_test_path": "poc-tests/VaultReplay.t.sol",
                    "promotes_to_poc_work": True,
                })
                + "\n",
                encoding="utf-8",
            )
            manifest = ws / "poc_execution" / "halmos-vault" / "execution_manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps({
                    "candidate_id": "halmos-vault",
                    "final_result": "disproved",
                    "impact_assertion": "not_demonstrated",
                    "foundry_version_inventory": {
                        "planned_target": {"foundry_version": "v1.7.1"}
                    },
                })
                + "\n",
                encoding="utf-8",
            )

            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.PASS)
            truth = row.detail["deep_engine_truth"]
            self.assertEqual(truth["status"], "pass")
            self.assertEqual(truth["truth_label_counts"]["counterexample"], 1)
            self.assertEqual(truth["rows"][0]["truth_label"], "counterexample")
            self.assertEqual(truth["rows"][0]["classification"], "clean")
            self.assertIn("deep-engine truth", row.reason)

    def test_deep_engine_truth_label_no_findings_is_clean_only_when_executed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            _write_deep_engine_truth_manifest(
                ws,
                truth_label="no_findings",
                truth_reason="log parsed without a counterexample",
                engine_executed=True,
                targets_discovered=True,
                parser_status="ok",
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.PASS)
            truth = row.detail["deep_engine_truth"]
            self.assertEqual(truth["status"], "pass")
            self.assertEqual(truth["truth_label_counts"]["no_findings"], 1)
            self.assertEqual(truth["rows"][0]["truth_label"], "no_findings")
            self.assertEqual(truth["rows"][0]["classification"], "clean")
            self.assertIn("deep-engine truth", row.reason)

        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            _write_deep_engine_truth_manifest(
                ws,
                truth_label="no_findings",
                truth_reason="no counterexample, but execution did not happen",
                engine_executed=False,
                targets_discovered=False,
                parser_status="ok",
                status="no_findings",
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            truth = row.detail["deep_engine_truth"]
            self.assertEqual(truth["status"], "warn")
            self.assertEqual(truth["rows"][0]["truth_label"], "no_findings")
            self.assertEqual(truth["rows"][0]["classification"], "non_clean")
            self.assertIn("deep-engine truth labels are non-clean", row.reason)

    def test_p1_extraction_queue_without_manifest_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            queue = ws / ".audit_logs" / "p1_fixture_extraction" / "extraction_queue.json"
            queue.parent.mkdir(parents=True, exist_ok=True)
            queue.write_text(
                json.dumps([
                    {
                        "pattern": "demo-pattern",
                        "source": "demo-source",
                        "argv": ["python3", "tools/p1-fixture-extractor.py"],
                    }
                ])
                + "\n",
                encoding="utf-8",
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("P1 fixture extraction queue", row.reason)
            self.assertIn("oldest unexecuted queue item", row.reason)
            self.assertEqual(row.detail["p1_extraction_queue_count"], 1)
            self.assertFalse(row.detail["p1_extraction_manifest_present"])
            self.assertEqual(row.detail["oldest_unexecuted_queue_item"]["kind"], "p1_extraction_queue")

    def test_p1_extraction_manifest_without_report_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            root = ws / ".audit_logs" / "p1_fixture_extraction"
            root.mkdir(parents=True, exist_ok=True)
            (root / "extraction_queue.json").write_text(
                json.dumps([{"pattern": "demo-pattern", "argv": ["python3", "tools/p1-fixture-extractor.py"]}])
                + "\n",
                encoding="utf-8",
            )
            (root / "execution_manifest.json").write_text(
                json.dumps({"selected_count": 1, "result_counts": {"ok": 1}}) + "\n",
                encoding="utf-8",
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("execution_report.md", row.reason)
            self.assertTrue(row.detail["p1_extraction_manifest_present"])
            self.assertFalse(row.detail["p1_extraction_report_present"])

    def test_p1_extraction_failed_rows_warn(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            root = ws / ".audit_logs" / "p1_fixture_extraction"
            root.mkdir(parents=True, exist_ok=True)
            (root / "extraction_queue.json").write_text(
                json.dumps([{"pattern": "demo-pattern", "argv": ["python3", "tools/p1-fixture-extractor.py"]}])
                + "\n",
                encoding="utf-8",
            )
            (root / "execution_manifest.json").write_text(
                json.dumps({"selected_count": 1, "result_counts": {"failed": 1}}) + "\n",
                encoding="utf-8",
            )
            (root / "execution_report.md").write_text("# P1 Extraction Execution Report\n", encoding="utf-8")
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("failed=1", row.reason)

    def test_p1_extraction_completed_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            root = ws / ".audit_logs" / "p1_fixture_extraction"
            root.mkdir(parents=True, exist_ok=True)
            (root / "extraction_queue.json").write_text(
                json.dumps([{"pattern": "demo-pattern", "argv": ["python3", "tools/p1-fixture-extractor.py"]}])
                + "\n",
                encoding="utf-8",
            )
            (root / "execution_manifest.json").write_text(
                json.dumps({"selected_count": 1, "result_counts": {"ok": 1}}) + "\n",
                encoding="utf-8",
            )
            (root / "execution_report.md").write_text("# P1 Extraction Execution Report\n", encoding="utf-8")
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["poc-execution"]
            self.assertEqual(row.status, MOD.PASS)
            self.assertEqual(row.detail["p1_extraction_queue_count"], 1)
            self.assertTrue(row.detail["p1_extraction_report_present"])


class MissingDeepManifestTest(unittest.TestCase):
    """Case 2: missing audit_deep_all_manifest.json -> WARN by default,
    FAIL when ``--require-deep`` is passed."""

    def test_missing_warns_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").unlink()
            results = MOD.run_all(ws, require_deep=False)
            r = _by_check(results)["audit-deep-all"]
            self.assertEqual(r.status, MOD.WARN, f"reason={r.reason!r}")

    def test_missing_fails_when_required(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").unlink()
            results = MOD.run_all(ws, require_deep=True)
            r = _by_check(results)["audit-deep-all"]
            self.assertEqual(r.status, MOD.FAIL, f"reason={r.reason!r}")


class HypothesisGap23Test(unittest.TestCase):
    """Case 3: HYPOTHESIS_PROMPT.md present, HYPOTHESES.md missing -> FAIL.

    This is V5 Gap-23: stage 16 silently emitted the prompt without
    producing the final hypotheses file.
    """

    def test_prompt_without_final_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            (ws / "HYPOTHESES.md").unlink()
            results = MOD.run_all(ws, require_deep=False)
            r = _by_check(results)["hypotheses"]
            self.assertEqual(r.status, MOD.FAIL)
            self.assertIn("Gap-23", r.reason)


class PatternMiningAbsentTest(unittest.TestCase):
    """Case 4: pattern-mining artifacts absent and no skip marker -> FAIL."""

    def test_no_artifacts_no_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            for name in (
                "PATTERN_HITS.md",
                "cross_ws_patterns.md",
            ):
                p = ws / name
                if p.exists():
                    p.unlink()
            # No pattern-mining artifacts at all and no skip marker.
            results = MOD.run_all(ws, require_deep=False)
            r = _by_check(results)["pattern-mining"]
            self.assertEqual(r.status, MOD.FAIL, f"reason={r.reason!r}")


class PatternMiningSkipMarkerTest(unittest.TestCase):
    """Case 5: pattern-mining absent + explicit skip marker -> WARN with
    the marker reason embedded in the row."""

    def test_skip_marker_warns_with_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            for name in ("PATTERN_HITS.md", "cross_ws_patterns.md"):
                p = ws / name
                if p.exists():
                    p.unlink()
            marker = ws / ".audit_logs" / "pattern_mining_skip.md"
            marker.write_text("inapplicable: novel-vector audit, no priors\n")
            results = MOD.run_all(ws, require_deep=False)
            r = _by_check(results)["pattern-mining"]
            self.assertEqual(r.status, MOD.WARN)
            self.assertIn("inapplicable", r.reason)


class AgentSynthesizeOutputsOnlyTest(unittest.TestCase):
    """Case 6: agent_outputs/* present but no synthesis JSON -> WARN."""

    def test_outputs_without_synthesis_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            # Remove synthesis JSON, add agent_outputs file.
            for name in ("brief_candidates.json", "agent_verdicts.json"):
                (ws / "swarm" / name).unlink()
            (ws / "agent_outputs").mkdir(parents=True, exist_ok=True)
            (ws / "agent_outputs" / "dispatch_001.md").write_text(
                "# dispatch\n"
            )
            results = MOD.run_all(ws, require_deep=False)
            r = _by_check(results)["agent-synthesize"]
            self.assertEqual(r.status, MOD.WARN, f"reason={r.reason!r}")


class PreSubmitStagingWithoutPackagingTest(unittest.TestCase):
    """Case 7: a staging draft exists but no packaged bundle / production
    path. High/Critical drafts FAIL; non-severity drafts WARN."""

    def test_high_severity_without_pp_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "h1_high_finding.md").write_text(
                "# Finding\n\nSeverity: High\n\nNo production path here.\n"
            )
            results = MOD.run_all(ws, require_deep=False)
            r = _by_check(results)["pre-submit"]
            self.assertEqual(r.status, MOD.FAIL, f"reason={r.reason!r}")
            self.assertIn("High/Critical", r.reason)

    def test_critical_claimed_not_submit_ready_fails_even_with_pp(self) -> None:
        """A blocked Critical draft must not close out as paste-ready.

        Spark regression: `**Severity claimed:** Critical` plus
        `NOT_SUBMIT_READY` / `EXECUTION_BLOCKED` previously parsed as
        unknown severity and downgraded to a WARN.
        """
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "spark_critical.md").write_text(
                "# Finding\n\n"
                "**Status:** `NOT_SUBMIT_READY` -- paste-ready draft pending "
                "runnable PoC execution\n\n"
                "**Severity claimed:** Critical\n\n"
                "The PoC is EXECUTION_BLOCKED on the local toolchain. "
                "Operator must execute the PoC before submission. "
                "`listed_impact_proven=false`.\n\n"
                "## Production Path\n\n"
                "1. Static path is documented but runtime execution is absent.\n",
                encoding="utf-8",
            )
            r = MOD.check_pre_submit(ws)
            self.assertEqual(r.status, MOD.FAIL, f"reason={r.reason!r}")
            self.assertIn("NOT_SUBMIT_READY", r.reason)
            self.assertEqual(r.detail["drafts"][0]["severity"], "critical")
            self.assertTrue(r.detail["drafts"][0]["not_submit_ready"])
            self.assertTrue(r.detail["drafts"][0]["execution_blocked"])
            self.assertIn(
                "listed_impact_proven=false",
                r.detail["drafts"][0]["readiness_blockers"],
            )

    def test_unknown_severity_without_packaging_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "info_001.md").write_text(
                "# Info\n\nSeverity: Informational\n\nNo PP yet.\n"
            )
            results = MOD.run_all(ws, require_deep=False)
            r = _by_check(results)["pre-submit"]
            # Not High/Critical, but no packaged bundle either -> WARN.
            self.assertEqual(r.status, MOD.WARN, f"reason={r.reason!r}")


class FinalPasteHygieneTest(unittest.TestCase):
    """Existing operator/final paste artifacts are closeout-gated even when
    they were not emitted by submission-factory."""

    def test_final_paste_hygiene_blocks_unsafe_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            out = ws / "submissions" / "paste-ready"
            out.mkdir(parents=True)
            (out / "FN1.md").write_text(
                "# High - Unsafe final paste\n\n"
                "<!-- internal marker must not reach platform paste -->\n\n"
                "## Summary\n\n"
                "Operator note: <TODO_OPERATOR: fill real impact>\n"
                "Local evidence at `/Users/wolf/audits/ws/poc-tests/FN1.t.sol`.\n\n"
                "## Proof of Concept\n\n"
                "`poc-tests/FN1.t.sol`\n",
                encoding="utf-8",
            )

            row = MOD.check_final_paste_hygiene(ws)

            self.assertEqual(row.status, MOD.FAIL, f"reason={row.reason!r}")
            counts = row.detail["violation_counts"]
            self.assertEqual(counts["html_comment"], 1)
            self.assertEqual(counts["manual_fill_placeholder"], 1)
            self.assertEqual(counts["local_absolute_path"], 1)
            self.assertEqual(counts["path_only_poc"], 1)
            self.assertIn(str(out / "FN1.md"), row.artifacts)

    def test_final_paste_hygiene_accepts_reproduction_detail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            out = ws / "submissions" / "cantina_paste"
            out.mkdir(parents=True)
            (out / "FN2.md").write_text(
                "# Medium - Safe final paste\n\n"
                "## Proof of Concept\n\n"
                "Run the repository-relative proof:\n\n"
                "```bash\n"
                "forge test --match-path poc-tests/FN2.t.sol --match-test testExploit\n"
                "```\n\n"
                "Observed output:\n\n"
                "```text\n"
                "Suite result: ok. 1 passed; 0 failed\n"
                "```\n",
                encoding="utf-8",
            )

            row = MOD.check_final_paste_hygiene(ws)

            self.assertEqual(row.status, MOD.PASS, f"reason={row.reason!r}")
            self.assertEqual(row.detail["file_count"], 1)
            self.assertEqual(row.detail["violation_counts"], {})

    def test_packaged_ready_files_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            bundle = ws / "submissions" / "packaged" / "bundle-a"
            bundle.mkdir(parents=True)
            (bundle / "cantina_ready.md").write_text(
                "# High - Unsafe packaged ready\n\n"
                "## PoC\n\n"
                "See: test/FN3.t.sol\n",
                encoding="utf-8",
            )

            row = MOD.check_final_paste_hygiene(ws)

            self.assertEqual(row.status, MOD.FAIL, f"reason={row.reason!r}")
            self.assertEqual(row.detail["violation_counts"]["path_only_poc"], 1)

    def test_root_final_cantina_paste_files_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            out = ws / "final_cantina_paste"
            out.mkdir(parents=True)
            (out / "amp-zero.md").write_text(
                "# Medium - Root final paste\n\n"
                "## Proof of Concept\n\n"
                "PoC file:\n\n"
                "```text\n"
                "external/stableswap-hooks/test/AuditooorAmpZeroPoC.t.sol\n"
                "```\n",
                encoding="utf-8",
            )

            row = MOD.check_final_paste_hygiene(ws)

            self.assertEqual(row.status, MOD.FAIL, f"reason={row.reason!r}")
            self.assertIn(str(out / "amp-zero.md"), row.artifacts)
            self.assertEqual(row.detail["violation_counts"]["path_only_poc"], 1)

    # Rank-4 (#43 mutual-exclusion): the escalate-first-required-check and
    # severity-calibration-gate rule gates DEMAND their named-rebuttal markers,
    # but the paste-hygiene whitelist previously omitted them, so a draft that
    # earned either rebuttal could never pass BOTH gates. FP-suppression must
    # not weaken the true-positive: a genuine stray HTML comment still FAILs.
    def test_escalate_and_calibration_gate_rebuttal_markers_whitelisted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            out = ws / "submissions" / "paste-ready"
            out.mkdir(parents=True)
            (out / "FN-rank4.md").write_text(
                "# Medium - Calibration-reconciled finding\n\n"
                "<!-- r-escalate-first-rebuttal: higher tier IS the filed "
                "tier; narrowing is on an OOS sub-variant -->\n"
                "<!-- r-escalate-measure-rebuttal: super-linear growth "
                "measured at N=20k; further scaling infeasible in CI -->\n"
                "<!-- severity-calibration-gate-rebuttal: low-cap text is a "
                "quoted rubric excerpt, not a self-assessment -->\n\n"
                "## Proof of Concept\n\n"
                "```bash\n"
                "forge test --match-test testExploit\n"
                "```\n\n"
                "```text\n"
                "Suite result: ok. 1 passed; 0 failed\n"
                "```\n",
                encoding="utf-8",
            )

            row = MOD.check_final_paste_hygiene(ws)

            # FP suppressed: the three sanctioned rebuttal markers produce ZERO
            # html_comment hygiene violations (and no other kind either).
            self.assertEqual(
                row.detail["violation_counts"].get("html_comment", 0),
                0,
                f"sanctioned rebuttal markers wrongly flagged: {row.detail['violations']!r}",
            )
            self.assertEqual(row.status, MOD.PASS, f"reason={row.reason!r}")

    def test_stray_html_comment_still_fails_after_rank4_whitelist(self) -> None:
        # CONTROL / true-positive: a genuine leaked operator comment that is
        # NOT a sanctioned rebuttal marker must still be flagged. This proves
        # the Rank-4 additions widened the whitelist ONLY for the three named
        # markers, not for arbitrary HTML comments.
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            out = ws / "submissions" / "paste-ready"
            out.mkdir(parents=True)
            (out / "FN-control.md").write_text(
                "# Medium - Draft with a leaked comment\n\n"
                "<!-- r-escalate-first-rebuttal: legitimately earned -->\n"
                "<!-- escalate-first: TODO ask operator to double-check this -->\n\n"
                "## Proof of Concept\n\n"
                "```bash\n"
                "forge test --match-test testExploit\n"
                "```\n\n"
                "```text\n"
                "Suite result: ok. 1 passed; 0 failed\n"
                "```\n",
                encoding="utf-8",
            )

            row = MOD.check_final_paste_hygiene(ws)

            # The bare `escalate-first:` comment (no `-rebuttal` suffix) is a
            # stray operator leak and MUST still surface exactly one violation;
            # the adjacent sanctioned marker must NOT be counted.
            self.assertEqual(
                row.detail["violation_counts"].get("html_comment", 0),
                1,
                f"expected exactly one stray-comment violation: {row.detail['violations']!r}",
            )
            self.assertEqual(row.status, MOD.FAIL, f"reason={row.reason!r}")


class P0FollowupsWarnTest(unittest.TestCase):
    """Case 8: gaps doc lists P0 items but no follow-up tracking -> WARN.

    We isolate this by pointing REPO_ROOT into the temp directory. The
    fixture writes a synthetic V5_CAPABILITY_GAPS doc with 2 P0 entries
    and no V5_P0_FOLLOWUPS.md sibling; the workspace also has no
    .audit_logs/p0_followups.json. Result: WARN.
    """

    def test_p0_in_gaps_no_tracking_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            tmp_root = Path(tmp)
            ws = tmp_root / "ws"
            (ws / ".audit_logs").mkdir(parents=True, exist_ok=True)
            # Scaffold ONLY enough for the p0 check; we don't care about
            # the other check rows for this test.
            (tmp_root / "docs").mkdir()
            (tmp_root / "docs" / "V5_CAPABILITY_GAPS_2026-04-26.md").write_text(
                "## Gap 1\n\n**Priority**: P0\n\n## Gap 2\n\nPriority: P0\n"
            )
            # Patch REPO_ROOT for the tool-module duration.
            saved = MOD.REPO_ROOT
            try:
                MOD.REPO_ROOT = tmp_root
                r = MOD.check_p0_followups(ws)
                self.assertEqual(r.status, MOD.WARN, f"reason={r.reason!r}")
                self.assertIn("P0", r.reason)
            finally:
                MOD.REPO_ROOT = saved

    def test_p0_followups_workspace_artifact_passes(self) -> None:
        """Belt-and-braces: workspace-local p0_followups.json -> PASS."""
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".audit_logs").mkdir(parents=True, exist_ok=True)
            (ws / ".audit_logs" / "p0_followups.json").write_text(
                json.dumps({"items": [{"id": "P0-1", "status": "open"}]})
            )
            r = MOD.check_p0_followups(ws)
            self.assertEqual(r.status, MOD.PASS, f"reason={r.reason!r}")


class KimiMinimaxRegressionTest(unittest.TestCase):
    """Regressions for the M14-trapped Kimi+Minimax review claims that
    turned out to be real bugs."""

    # Kimi Bug 1: empty subdirectory should not satisfy the dir-glob gate.
    def test_canonical_audit_subdir_only_does_not_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            (ws / "swarm" / "mining_briefs").mkdir(parents=True)
            # Place a stray subdirectory inside mining_briefs but no .md
            # files — previously this would have counted as "present".
            (ws / "swarm" / "mining_briefs" / "subdir").mkdir()
            (ws / "submissions" / "packaged").mkdir(parents=True)
            (ws / "submissions" / "packaged" / "_keep.txt").write_text("x\n")
            r = MOD.check_canonical_audit(ws)
            # Both "dir-glob" rows should be missing -> FAIL.
            self.assertEqual(r.status, MOD.FAIL, f"reason={r.reason!r}")
            self.assertIn("swarm/mining_briefs", r.detail["missing"])
            self.assertIn("submissions/packaged", r.detail["missing"])

    # Kimi Bug 2: empty skip marker -> FAIL (was WARN).
    def test_pattern_mining_empty_skip_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            for name in ("PATTERN_HITS.md", "cross_ws_patterns.md"):
                p = ws / name
                if p.exists():
                    p.unlink()
            (ws / ".audit_logs" / "pattern_mining_skip.md").write_text("")
            r = MOD.check_pattern_mining(ws)
            self.assertEqual(r.status, MOD.FAIL, f"reason={r.reason!r}")
            self.assertIn("empty", r.reason.lower())

    # Kimi Bug 3: YAML frontmatter severity should not override body.
    def test_pre_submit_frontmatter_severity_does_not_override(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            # Drop the demo bundle so the production-path manifest does
            # not satisfy the gate via the bundle path.
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "low_with_fm.md").write_text(
                "---\nseverity: high\n---\n\n# Finding\n\nSeverity: Low\n"
            )
            r = MOD.check_pre_submit(ws)
            # Body says Low; frontmatter ignored. We expect WARN/PASS, NOT
            # the High/Critical FAIL path.
            self.assertNotEqual(
                r.status, MOD.FAIL,
                f"frontmatter severity falsely escalated to FAIL: {r.reason!r}",
            )

    # Kimi Bug 4 / Minimax Gap 7: "## Production Path" inside HTML comment
    # or fenced code block should NOT count as evidence.
    def test_pre_submit_pp_inside_html_comment_does_not_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "h1_finding.md").write_text(
                "# Finding\n\nSeverity: High\n\n"
                "<!--\n## Production Path\nNot really.\n-->\n"
            )
            r = MOD.check_pre_submit(ws)
            self.assertEqual(r.status, MOD.FAIL, f"reason={r.reason!r}")
            self.assertIn("High/Critical", r.reason)

    def test_pre_submit_pp_real_header_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "h1_finding.md").write_text(
                "# Finding\n\nSeverity: High\n\n"
                "## Production Path\n\n1. real path step\n"
            )
            r = MOD.check_pre_submit(ws)
            # No High/Critical FAIL — has real `## Production Path` header.
            self.assertNotEqual(r.status, MOD.FAIL)

    def test_hacker_question_obligations_fail_high_draft_with_open_match(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "hq.md").write_text(
                "# Finding\n\nSeverity: Critical\n\nsrc/Vault.sol withdraw is reachable.\n",
                encoding="utf-8",
            )
            _write_hacker_question_obligation(ws)

            row = MOD.check_hacker_question_obligations(ws)

            self.assertEqual(row.status, MOD.FAIL, row.reason)
            self.assertEqual(row.detail["blocking_count"], 1)

    def test_hacker_question_obligations_pass_after_answered(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "hq.md").write_text(
                "# Finding\n\nSeverity: High\n\nsrc/Vault.sol withdraw is reachable.\n",
                encoding="utf-8",
            )
            _write_hacker_question_obligation(ws, state="answered")

            row = MOD.check_hacker_question_obligations(ws)

            self.assertEqual(row.status, MOD.PASS, row.reason)
            self.assertEqual(row.detail["blocking_count"], 0)

    def test_hacker_question_obligations_medium_draft_is_not_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "hq.md").write_text(
                "# Finding\n\nSeverity: Medium\n\nsrc/Vault.sol withdraw is reachable.\n",
                encoding="utf-8",
            )
            _write_hacker_question_obligation(ws)

            row = MOD.check_hacker_question_obligations(ws)

            self.assertEqual(row.status, MOD.PASS, row.reason)
            self.assertEqual(row.detail["blocking_count"], 0)

    def test_pre_submit_scans_paste_ready_and_final_cantina_paste(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            for lane in ("paste_ready", "final_cantina_paste"):
                d = ws / "submissions" / lane
                d.mkdir(parents=True, exist_ok=True)
                (d / f"{lane}.md").write_text(
                    "# Finding\n\nSeverity: High\n\nNo production path yet.\n",
                    encoding="utf-8",
                )
            r = MOD.check_pre_submit(ws)
            self.assertEqual(r.status, MOD.FAIL, f"reason={r.reason!r}")
            self.assertEqual(len(r.detail["drafts"]), 2)
            self.assertEqual(
                {Path(row["draft"]).parent.name for row in r.detail["drafts"]},
                {"paste_ready", "final_cantina_paste"},
            )

    # Kimi Bug 5: malformed deep manifest (wrong JSON shape) -> FAIL, not crash.
    def test_audit_deep_all_wrong_shape_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            mf = ws / ".audit_logs" / "audit_deep_all_manifest.json"
            mf.write_text("42\n")  # valid JSON, wrong shape (not a dict)
            r = MOD.check_audit_deep_all(ws, require_deep=False)
            self.assertEqual(r.status, MOD.FAIL, f"reason={r.reason!r}")
            self.assertIn("shape", r.reason.lower())

    # Kimi Bug 8: tilde expansion via main(), front-door CLI shape.
    def test_main_expands_tilde_in_workspace_arg(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            home = Path(tmp)
            ws_under_home = home / "ws"
            ws_under_home.mkdir()
            _scaffold_healthy(ws_under_home)
            # Point HOME at our temp root so `~/ws` resolves there.
            saved_home = os.environ.get("HOME")
            try:
                os.environ["HOME"] = str(home)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = MOD.main(["--workspace", "~/ws"])
                # Check that the expansion at least let the run start
                # (return code is 0 or 1 depending on other rows; what
                # matters is that we did NOT exit 2 with "not found").
                self.assertNotEqual(rc, 2, buf.getvalue())
            finally:
                if saved_home is not None:
                    os.environ["HOME"] = saved_home
                else:
                    os.environ.pop("HOME", None)

    # Minimax Gap 4: empty `[]` synthesis JSON does NOT count as substantive.
    def test_agent_synthesize_empty_json_treated_as_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            # Overwrite to empty arrays.
            (ws / "swarm" / "brief_candidates.json").write_text("[]\n")
            (ws / "swarm" / "agent_verdicts.json").write_text("[]\n")
            # Drop agent_outputs to get the FAIL branch.
            r = MOD.check_agent_synthesize(ws)
            self.assertEqual(r.status, MOD.FAIL, f"reason={r.reason!r}")


class ManifestWriteTest(unittest.TestCase):
    """``--write-manifest`` produces a JSON file under .audit_logs/."""

    def test_manifest_written(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main(
                    ["--workspace", str(ws), "--write-manifest"]
                )
            self.assertEqual(rc, 0, buf.getvalue())
            mf = ws / ".audit_logs" / "audit_closeout_manifest.json"
            self.assertTrue(mf.exists(), f"manifest not written at {mf}")
            doc = json.loads(mf.read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], "auditooor.audit_closeout.v1")
            # Pin to the same count run_all() produces; bump alongside
            # any additions / removals to that list.
            # Lane 5 closeout added ``hacker-question-obligations`` -> 28.
            # H1/H2/H3/K6 (HACKERMAN V3 Lane H + K6) added 4 checks -> 32.
            self.assertEqual(len(doc["checks"]), 32)
            detector_summary = doc["summary"]["detector_environment"]
            self.assertEqual(
                detector_summary["schema_version"],
                "auditooor.detector_environment_closeout_summary.v1",
            )
            self.assertTrue(detector_summary["manifest_present"])
            self.assertTrue(detector_summary["manifest_valid"])
            self.assertFalse(detector_summary["has_skip_failures"])
            self.assertEqual(detector_summary["skip_fail_total"], 0)
            self.assertEqual(detector_summary["skip_fail_counts"]["total"], 0)
            go_dlt_summary = doc["summary"]["go_dlt_audit_enforcement"]
            self.assertEqual(
                go_dlt_summary["schema"],
                "auditooor.go_dlt_audit_enforcement.v1",
            )
            self.assertEqual(go_dlt_summary["status"], MOD.PASS)
            self.assertFalse(go_dlt_summary["manifest_present"])
            self.assertFalse(go_dlt_summary["go_files_detected"])
            checks = {c["check"] for c in doc["checks"]}
            self.assertEqual(
                checks,
                {
                    "canonical-audit",
                    "audit-deep-all",
                    "pattern-mining",
                    "hypotheses",
                    "agent-synthesize",
                    "mcp-context",
                    "vault-mcp-self-test",
                    "pre-submit",
                    "hacker-question-obligations",
                    "final-paste-hygiene",
                    "poc-execution",
                    "poc-scaffold-ambiguity",
                    "claim-precondition",
                    "detector-environment",
                    "go-dlt-audit-enforcement",
                    "scan-go-coverage",
                    "fp-calibration",
                    "llm-budget",
                    "p0-followups",
                    "yaml-wave17-consistency",
                    "evidence-class",
                    "counterexample-execution",
                    "replay-execution-distinction",
                    "fixture-duplicates",
                    "invariant-ledger",
                    "program-impact-mapping",
                    "pr560-artifact-closure",
                    "outcome-scoreboard",
                    # H1/H2/H3/K6 (HACKERMAN V3 Lane H + K6):
                    "strict-hackerman-receipts",
                    "strict-advisory-blockers",
                    "full-audit-path",
                    "learning-gate",
                },
            )
            # P0-1 burn-down: require_replay_executed flag flows through to the
            # manifest top level so reviewers can see whether the run was
            # configured for strict replay enforcement.
            self.assertIn("require_replay_executed", doc)
            self.assertFalse(doc["require_replay_executed"])


class MCPContextCheckTest(unittest.TestCase):
    def test_mcp_context_warns_when_required_contexts_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-mcp-") as tmp:
            ws = Path(tmp)
            (ws / "AUDIT.md").write_text("# Audit\nNo MCP recall recorded.\n")

            row = MOD.check_mcp_context(ws)

            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("missing recorded MCP context", row.reason)
            self.assertEqual(
                row.detail["missing"],
                ["resume", "exploit", "harness", "knowledge_gap"],
            )

    def test_mcp_context_warns_when_only_legacy_context_ids_recorded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-mcp-") as tmp:
            ws = Path(tmp)
            (ws / "AUDIT.md").write_text(
                "\n".join(
                    [
                        "auditooor.vault_context_pack.v1:resume:40c39d68cd152239",
                        "auditooor.vault_exploit_context.v1:exploit:c898599beddb943d",
                        "auditooor.vault_harness_context.v1:harness:f41d21e119e4fb05",
                        "auditooor.vault_knowledge_gap_context.v1:knowledge_gap:602d29f7e40c4264",
                    ]
                )
                + "\n"
            )

            row = MOD.check_mcp_context(ws)

            self.assertEqual(row.status, MOD.WARN, row.reason)
            self.assertIn("legacy MCP context ids recorded", row.reason)
            self.assertEqual(row.detail["missing"], [])

    def test_mcp_context_passes_with_valid_receipt_and_pack_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-mcp-") as tmp:
            ws = Path(tmp)
            _write_memory_context_fixture(ws)

            row = MOD.check_mcp_context(ws)

            self.assertEqual(row.status, MOD.PASS, row.reason)
            self.assertIn("memory context receipt valid", row.reason)

    def test_mcp_context_missing_receipt_proof_only_blocks_strict_closeout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-mcp-") as tmp:
            ws = Path(tmp)
            poc = ws / "poc_notes" / "spark" / "lead-1.md"
            poc.parent.mkdir(parents=True, exist_ok=True)
            poc.write_text(
                "# Spark Lead 1\n\nSeverity: Medium\n\nPoC notes updated.\n",
                encoding="utf-8",
            )
            _write_memory_context_fixture(
                ws,
                fresh_after_refs=[str(poc.relative_to(ws))],
                receipt_proof_mode="missing",
            )

            row = MOD.check_mcp_context(ws)

            self.assertEqual(row.status, MOD.FAIL, row.reason)
            self.assertTrue(row.detail["strict_required"])
            self.assertEqual(row.detail["tool_rc"], 1)
            self.assertEqual(
                row.detail["summary"]["receipt_proof_status"],
                "missing",
                row.detail["summary"],
            )
            self.assertIn("receipt or pack validation failed", row.reason)
            self.assertIn("receipt_proof missing", row.reason)

    def test_mcp_context_invalid_receipt_proof_blocks_strict_closeout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-mcp-") as tmp:
            ws = Path(tmp)
            draft = ws / "submissions" / "staging" / "spark-high.md"
            draft.parent.mkdir(parents=True, exist_ok=True)
            draft.write_text(
                "## Summary\n\nSeverity: High\n\n## Production Path\n\nspark path\n",
                encoding="utf-8",
            )
            bundle = ws / "submissions" / "packaged" / draft.stem
            bundle.mkdir(parents=True, exist_ok=True)
            (bundle / "manifest.json").write_text(
                json.dumps({"production_path": {"items": ["spark"]}}) + "\n",
                encoding="utf-8",
            )
            _write_memory_context_fixture(
                ws,
                fresh_after_refs=[str(draft.relative_to(ws))],
                receipt_proof_mode="invalid",
                loaded_at="2100-01-01T00:00:00Z",
            )

            row = MOD.check_mcp_context(ws)

            self.assertEqual(row.status, MOD.FAIL, row.reason)
            self.assertTrue(row.detail["strict_required"])
            self.assertEqual(row.detail["tool_rc"], 1)
            self.assertEqual(
                row.detail["summary"]["receipt_proof_status"],
                "invalid",
                row.detail["summary"],
            )
            self.assertIn("receipt or pack validation failed", row.reason)
            self.assertIn("receipt_proof mismatch", row.reason)

    def test_mcp_context_missing_receipt_is_strict_closeout_blocker_for_medium_poc(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-mcp-") as tmp:
            ws = Path(tmp)
            poc = ws / "poc_notes" / "spark" / "lead-1.md"
            poc.parent.mkdir(parents=True, exist_ok=True)
            poc.write_text(
                "# Spark Lead 1\n\nSeverity: Medium\n\nPoC notes updated.\n",
                encoding="utf-8",
            )
            _write_memory_context_fixture(
                ws,
                fresh_after_refs=[str(poc.relative_to(ws))],
                write_receipt=False,
            )

            row = MOD.check_mcp_context(ws)

            self.assertEqual(row.status, MOD.FAIL, row.reason)
            self.assertTrue(row.detail["strict_required"])
            self.assertEqual(row.detail["tool_rc"], 2)
            resolved_ws = ws.resolve()
            self.assertIn("strict memory-context closeout blocker", row.reason)
            self.assertIn(
                f"python3 tools/memory-context-load.py --workspace {resolved_ws} --from-requirements --write-receipt",
                row.reason,
            )

    def test_mcp_context_stale_receipt_blocks_strict_closeout_for_spark_draft(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-mcp-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            draft = ws / "submissions" / "staging" / "spark-critical.md"
            draft.parent.mkdir(parents=True, exist_ok=True)
            draft.write_text(
                "## Summary\n\nSeverity: High\n\n## Production Path\n\nspark path\n",
                encoding="utf-8",
            )
            bundle = ws / "submissions" / "packaged" / draft.stem
            bundle.mkdir(parents=True, exist_ok=True)
            (bundle / "manifest.json").write_text(
                json.dumps({"production_path": {"items": ["spark"]}}) + "\n",
                encoding="utf-8",
            )
            _write_memory_context_fixture(
                ws,
                fresh_after_refs=[str(draft.relative_to(ws))],
                receipt_proof_mode="valid",
            )

            results = MOD.run_all(ws, require_deep=False)
            by = _by_check(results)
            row = by["mcp-context"]

            self.assertEqual(row.status, MOD.FAIL, row.reason)
            self.assertTrue(row.detail["strict_required"])
            self.assertEqual(row.detail["tool_rc"], 2)
            self.assertEqual(
                len(row.detail["summary"]["stale_contexts"]),
                1,
                row.detail["summary"],
            )
            resolved_ws = ws.resolve()
            self.assertIn(
                "receipt predates closeout-relevant candidate/PoC artifacts",
                row.reason,
            )
            self.assertIn(
                f"python3 tools/memory-context-load.py --workspace {resolved_ws} --from-requirements --write-receipt",
                row.reason,
            )
            self.assertEqual(by["pre-submit"].status, MOD.PASS, by["pre-submit"].reason)

    def test_json_write_manifest_stdout_matches_manifest_shape(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main(
                    ["--workspace", str(ws), "--json", "--write-manifest"]
                )
            self.assertEqual(rc, 0, buf.getvalue())
            stdout_doc = json.loads(buf.getvalue())
            mf = ws / ".audit_logs" / "audit_closeout_manifest.json"
            file_doc = json.loads(mf.read_text(encoding="utf-8"))

            self.assertEqual(stdout_doc["schema"], "auditooor.audit_closeout.v1")
            self.assertEqual(stdout_doc["summary"], file_doc["summary"])
            self.assertEqual(stdout_doc["checks"], file_doc["checks"])
            self.assertEqual(stdout_doc["manifest"], str(mf))

    def test_strict_json_write_manifest_enables_strict_wiring(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            buf = io.StringIO()
            captured: dict[str, object] = {}

            def fake_run_all(*args: object, **kwargs: object) -> list[MOD.CheckResult]:
                captured["args"] = args
                captured["kwargs"] = kwargs
                return [MOD.CheckResult("strict-wiring-sentinel", MOD.PASS, "ok")]

            with mock.patch.object(MOD, "run_all", side_effect=fake_run_all):
                with redirect_stdout(buf):
                    rc = MOD.main(
                        [
                            "--workspace",
                            str(ws),
                            "--strict",
                            "--json",
                            "--write-manifest",
                        ]
                    )
            self.assertEqual(rc, 0, buf.getvalue())
            self.assertTrue(captured["kwargs"]["strict"])
            self.assertTrue(captured["kwargs"]["require_strict_wiring"])
            stdout_doc = json.loads(buf.getvalue())
            mf = ws / ".audit_logs" / "audit_closeout_manifest.json"
            file_doc = json.loads(mf.read_text(encoding="utf-8"))

            self.assertTrue(stdout_doc["strict"])
            self.assertTrue(stdout_doc["require_strict_wiring"])
            self.assertTrue(file_doc["require_strict_wiring"])

    def test_strict_env_json_write_manifest_enables_strict_wiring(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            buf = io.StringIO()
            captured: dict[str, object] = {}

            def fake_run_all(*args: object, **kwargs: object) -> list[MOD.CheckResult]:
                captured["args"] = args
                captured["kwargs"] = kwargs
                return [MOD.CheckResult("strict-wiring-sentinel", MOD.PASS, "ok")]

            with mock.patch.dict(os.environ, {"STRICT": "1"}):
                with mock.patch.object(MOD, "run_all", side_effect=fake_run_all):
                    with redirect_stdout(buf):
                        rc = MOD.main(
                            ["--workspace", str(ws), "--json", "--write-manifest"]
                        )
            self.assertEqual(rc, 0, buf.getvalue())
            self.assertTrue(captured["kwargs"]["strict"])
            self.assertTrue(captured["kwargs"]["require_strict_wiring"])
            stdout_doc = json.loads(buf.getvalue())
            mf = ws / ".audit_logs" / "audit_closeout_manifest.json"
            file_doc = json.loads(mf.read_text(encoding="utf-8"))

            self.assertTrue(stdout_doc["strict"])
            self.assertTrue(stdout_doc["require_strict_wiring"])
            self.assertTrue(file_doc["require_strict_wiring"])

    def test_execution_manifest_commands_attempted_int_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            manifest = ws / "poc_execution" / "demo" / "execution_manifest.json"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.poc_execution_manifest.v1",
                        "candidate_id": "DEMO",
                        "evidence_class": "executed_with_manifest",
                        "commands_attempted": 3,
                        "final_result": "pass",
                        "selected_impact": "test impact",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            row = MOD.check_poc_execution(ws)
            self.assertEqual(row.status, MOD.PASS, row.reason)
            self.assertEqual(
                row.detail["manifest_rows"][0]["command_count"],
                3,
            )


class ClaimPreconditionCloseoutTest(unittest.TestCase):
    """Wave 2 capability uplift (Issue #345 follow-up). Closeout surfaces
    ``<workspace>/.auditooor/claim_precondition_results.json`` so a draft
    that hard-failed pre-submit Check #28 stays visible at audit close."""

    def _scaffold_with_manifest(self, ws: Path, payload: dict) -> Path:
        _scaffold_healthy(ws)
        out = ws / ".auditooor" / "claim_precondition_results.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2) + "\n")
        return out

    def test_no_manifest_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["claim-precondition"]
            self.assertEqual(row.status, MOD.PASS)
            self.assertIn("not present", row.reason)

    def test_match_status_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            self._scaffold_with_manifest(
                ws,
                {
                    "schema": "auditooor.claim_precondition_results.v1",
                    "draft": str(ws / "draft.md"),
                    "overall_status": "match",
                    "entries": [
                        {
                            "directive": "x.y() == 1",
                            "left": "x.y()",
                            "op": "==",
                            "expected": "1",
                            "network": "",
                            "status": "match",
                            "observed": "1",
                            "rpc_used": None,
                            "note": "",
                        }
                    ],
                },
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["claim-precondition"]
            self.assertEqual(row.status, MOD.PASS)

    def test_contradicts_status_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            self._scaffold_with_manifest(
                ws,
                {
                    "schema": "auditooor.claim_precondition_results.v1",
                    "draft": str(ws / "draft.md"),
                    "overall_status": "contradicts",
                    "entries": [
                        {
                            "directive": "isAdmin == false",
                            "left": "isAdmin",
                            "op": "==",
                            "expected": "false",
                            "network": "polygon",
                            "status": "contradicts",
                            "observed": "true",
                            "rpc_used": "https://polygon.example/rpc",
                            "note": "",
                        }
                    ],
                },
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["claim-precondition"]
            self.assertEqual(row.status, MOD.FAIL)
            self.assertIn("contradicted", row.reason)

    def test_cannot_run_status_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            self._scaffold_with_manifest(
                ws,
                {
                    "schema": "auditooor.claim_precondition_results.v1",
                    "draft": str(ws / "draft.md"),
                    "overall_status": "cannot-run",
                    "entries": [
                        {
                            "directive": "x.y() == 1",
                            "left": "x.y()",
                            "op": "==",
                            "expected": "1",
                            "network": "",
                            "status": "cannot-run",
                            "observed": None,
                            "rpc_used": None,
                            "note": "no observed value",
                        }
                    ],
                },
            )
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["claim-precondition"]
            self.assertEqual(row.status, MOD.WARN)


class YamlWave17ConsistencyTest(unittest.TestCase):
    """V5-P0-17 9th check (Codex tests #1, #2). Hermetic via temp repo
    roots. Exercises FAIL / WARN / PASS branches."""

    def _scaffold_repo(self, root: Path, *, with_py: bool, with_vuln: bool,
                       with_clean: bool) -> None:
        (root / "reference" / "patterns.dsl").mkdir(parents=True)
        (root / "detectors" / "wave17").mkdir(parents=True)
        (root / "detectors" / "test_fixtures").mkdir(parents=True)
        (root / "reference" / "patterns.dsl" / "demo-pattern.yaml").write_text(
            "id: demo-pattern\n"
        )
        if with_py:
            (root / "detectors" / "wave17" / "demo_pattern.py").write_text(
                "# detector\n"
            )
        if with_vuln:
            (root / "detectors" / "test_fixtures"
             / "demo_pattern_vulnerable.sol").write_text(
                "// SPDX\ncontract A {}\n"
            )
        if with_clean:
            (root / "detectors" / "test_fixtures"
             / "demo_pattern_clean.sol").write_text(
                "// SPDX\ncontract A {}\n"
            )
        rows: list[str] = []
        if with_vuln:
            rows.append(
                'run_test       "demo-pattern" '
                '"demo_pattern_vulnerable.sol" "demo-pattern"'
            )
        if with_clean:
            rows.append(
                'run_clean_test "demo-pattern" '
                '"demo_pattern_clean.sol" "demo-pattern (clean)"'
            )
        (root / "detectors" / "test_fixtures" / "run_tests.sh").write_text(
            "#!/usr/bin/env bash\n" + "\n".join(rows) + "\n"
        )

    def test_aligned_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-yw-") as tmp:
            root = Path(tmp)
            self._scaffold_repo(root, with_py=True, with_vuln=True,
                                with_clean=True)
            r = MOD.check_yaml_wave17_consistency(
                root, require_strict_wiring=False
            )
            self.assertEqual(r.status, MOD.PASS, f"reason={r.reason!r}")

    def test_yaml_without_py_warns_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-yw-") as tmp:
            root = Path(tmp)
            self._scaffold_repo(root, with_py=False, with_vuln=True,
                                with_clean=True)
            r = MOD.check_yaml_wave17_consistency(
                root, require_strict_wiring=False
            )
            self.assertEqual(r.status, MOD.WARN, f"reason={r.reason!r}")
            self.assertIn("V5-P0-17", r.reason)
            self.assertIn("without wave17 .py", r.reason)

    def test_yaml_without_py_fails_on_strict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-yw-") as tmp:
            root = Path(tmp)
            self._scaffold_repo(root, with_py=False, with_vuln=True,
                                with_clean=True)
            r = MOD.check_yaml_wave17_consistency(
                root, require_strict_wiring=True
            )
            self.assertEqual(r.status, MOD.FAIL, f"reason={r.reason!r}")

    def test_missing_run_tests_row_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-yw-") as tmp:
            root = Path(tmp)
            self._scaffold_repo(root, with_py=True, with_vuln=True,
                                with_clean=True)
            (root / "detectors" / "test_fixtures" / "run_tests.sh").write_text(
                "#!/usr/bin/env bash\n# (no rows)\n"
            )
            r = MOD.check_yaml_wave17_consistency(
                root, require_strict_wiring=False
            )
            self.assertEqual(r.status, MOD.WARN, f"reason={r.reason!r}")
            self.assertIn("without run_test row", r.reason)

    def test_orphan_py_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-yw-") as tmp:
            root = Path(tmp)
            self._scaffold_repo(root, with_py=True, with_vuln=True,
                                with_clean=True)
            (root / "detectors" / "wave17" / "rogue_detector.py").write_text(
                "# rogue\n"
            )
            r = MOD.check_yaml_wave17_consistency(
                root, require_strict_wiring=False
            )
            self.assertEqual(r.status, MOD.WARN, f"reason={r.reason!r}")
            self.assertIn("orphan", r.reason)

    def test_uses_pattern_id_not_yaml_filename(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-yw-") as tmp:
            root = Path(tmp)
            (root / "reference" / "patterns.dsl").mkdir(parents=True)
            (root / "detectors" / "wave17").mkdir(parents=True)
            (root / "detectors" / "test_fixtures").mkdir(parents=True)
            (root / "reference" / "patterns.dsl" / "legacy-name.yaml").write_text(
                "pattern: canonical-pattern-id\n"
            )
            (root / "detectors" / "wave17" / "canonical_pattern_id.py").write_text(
                "# detector\n"
            )
            (root / "detectors" / "test_fixtures" / "run_tests.sh").write_text(
                "#!/usr/bin/env bash\n"
            )

            r = MOD.check_yaml_wave17_consistency(
                root, require_strict_wiring=True
            )

            self.assertEqual(r.status, MOD.PASS, f"reason={r.reason!r}")

    def test_documentation_only_yaml_is_excluded_from_wave17_wiring(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-yw-") as tmp:
            root = Path(tmp)
            (root / "reference" / "patterns.dsl").mkdir(parents=True)
            (root / "detectors" / "wave17").mkdir(parents=True)
            (root / "detectors" / "test_fixtures").mkdir(parents=True)
            (root / "reference" / "patterns.dsl" / "custom-only.yaml").write_text(
                "pattern: custom-only\nstatus: documentation-only  # hand-written\n"
            )
            (root / "detectors" / "test_fixtures" / "custom_only_vulnerable.sol").write_text(
                "// SPDX\ncontract A {}\n"
            )
            (root / "detectors" / "test_fixtures" / "custom_only_clean.sol").write_text(
                "// SPDX\ncontract A {}\n"
            )
            (root / "detectors" / "test_fixtures" / "run_tests.sh").write_text(
                "#!/usr/bin/env bash\n"
            )

            r = MOD.check_yaml_wave17_consistency(
                root, require_strict_wiring=True
            )

            self.assertEqual(r.status, MOD.PASS, f"reason={r.reason!r}")
            self.assertEqual(r.detail["documentation_only_yaml_count"], 1)


class FpCalibrationManifestCheckTest(unittest.TestCase):
    """P1-4 burn-down: the close-out gate surfaces FP-calibration freshness.

    The check is repo-rooted (manifest at
    ``reference/fp_calibration_manifest.json``, registry at
    ``detectors/_tier_registry.yaml``), so the tests scaffold a synthetic
    repo root and pass it to ``check_fp_calibration_manifest`` directly
    rather than going through ``run_all`` (which uses the production
    REPO_ROOT).
    """

    def _scaffold_repo(self, root: Path) -> None:
        # Mirror the layout the check expects.
        (root / "reference").mkdir(parents=True)
        (root / "detectors").mkdir(parents=True)
        # Stub the tool path the check imports — but reuse the real one.
        (root / "tools").mkdir(parents=True)
        real_tool = REPO_ROOT / "tools" / "fp-calibration-manifest.py"
        (root / "tools" / "fp-calibration-manifest.py").write_text(
            real_tool.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    def _write_registry(self, root: Path, rows: dict) -> None:
        out = ["version: 1", "tiers:"]
        for name, tier in rows.items():
            out.append(f"  {name}:")
            out.append(f"    tier: {tier}")
            out.append("    reason: test row")
        (root / "detectors" / "_tier_registry.yaml").write_text(
            "\n".join(out) + "\n", encoding="utf-8"
        )

    def test_missing_manifest_warns_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-fp-") as tmp:
            root = Path(tmp)
            self._scaffold_repo(root)
            self._write_registry(root, {"alpha": "S"})
            r = MOD.check_fp_calibration_manifest(
                root, require_strict=False
            )
            self.assertEqual(r.status, MOD.WARN)
            self.assertIn("missing rows: 1", r.reason)

    def test_missing_manifest_fails_under_strict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-fp-") as tmp:
            root = Path(tmp)
            self._scaffold_repo(root)
            self._write_registry(root, {"alpha": "S"})
            r = MOD.check_fp_calibration_manifest(
                root, require_strict=True
            )
            self.assertEqual(r.status, MOD.FAIL)
            self.assertIn("REQUIRE_FP_CALIBRATION=1 -> FAIL", r.reason)

    def test_fresh_manifest_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-fp-") as tmp:
            root = Path(tmp)
            self._scaffold_repo(root)
            self._write_registry(root, {"alpha": "S"})
            now_iso = "2099-01-01T00:00:00Z"
            payload = {
                "schema_version": "auditooor.fp_calibration_manifest.v1",
                "patterns": {
                    "alpha": {
                        "pattern": "alpha",
                        "tier": "S",
                        "last_calibrated_iso": now_iso,
                        "clean_codebases_count": 3,
                        "clean_corpus_hash": "deadbeefcafe",
                        "precision_pct": 100.0,
                    }
                },
            }
            (root / "reference" / "fp_calibration_manifest.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
            r = MOD.check_fp_calibration_manifest(
                root, require_strict=False
            )
            self.assertEqual(r.status, MOD.PASS, msg=r.reason)
            self.assertEqual(r.detail["fresh_count"], 1)
            self.assertEqual(r.detail["missing_count"], 0)

    def test_stale_manifest_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-fp-") as tmp:
            root = Path(tmp)
            self._scaffold_repo(root)
            self._write_registry(root, {"alpha": "S"})
            payload = {
                "schema_version": "auditooor.fp_calibration_manifest.v1",
                "patterns": {
                    "alpha": {
                        "pattern": "alpha",
                        "tier": "S",
                        "last_calibrated_iso": "2000-01-01T00:00:00Z",
                        "clean_codebases_count": 3,
                        "clean_corpus_hash": "deadbeefcafe",
                        "precision_pct": 100.0,
                    }
                },
            }
            (root / "reference" / "fp_calibration_manifest.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
            r = MOD.check_fp_calibration_manifest(
                root, require_strict=False
            )
            self.assertEqual(r.status, MOD.WARN)
            self.assertIn("stale rows", r.reason)

    def test_schema_violation_always_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-fp-") as tmp:
            root = Path(tmp)
            self._scaffold_repo(root)
            self._write_registry(root, {"alpha": "S"})
            # Missing required fields -> validation failure.
            payload = {
                "schema_version": "auditooor.fp_calibration_manifest.v1",
                "patterns": {
                    "alpha": {
                        "pattern": "alpha",
                        "tier": "S",
                        # last_calibrated_iso, clean_codebases_count, ...
                        # are intentionally absent.
                    }
                },
            }
            (root / "reference" / "fp_calibration_manifest.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
            r = MOD.check_fp_calibration_manifest(
                root, require_strict=False
            )
            self.assertEqual(r.status, MOD.FAIL)
            self.assertIn("schema validation", r.reason)


class ExitCodeTest(unittest.TestCase):
    """End-to-end exit-code check: a Gap-23 workspace exits 1."""

    def test_exit_nonzero_on_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            (ws / "HYPOTHESES.md").unlink()  # induce Gap-23 FAIL
            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with redirect_stdout(buf_out), redirect_stderr(buf_err):
                rc = MOD.main(["--workspace", str(ws)])
            self.assertEqual(rc, 1, buf_out.getvalue() + buf_err.getvalue())

    def test_exit_zero_on_warn_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            # Drop the deep manifest -> WARN, not FAIL (no --require-deep).
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").unlink()
            buf_out = io.StringIO()
            with redirect_stdout(buf_out):
                rc = MOD.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0, buf_out.getvalue())


class EvidenceClassCheckTest(unittest.TestCase):
    """Item #14: closeout never counts hypotheses as proof.

    The dedicated ``evidence-class`` row PASSes when no closeout artifacts
    are present, WARNs when any artifact is missing the field, and reports
    per-class counts so reviewers can audit verified vs hypothesis rows.
    """

    def test_pass_when_no_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            r = MOD.check_evidence_class(ws)
            self.assertEqual(r.status, MOD.PASS)
            self.assertEqual(r.detail["total_rows"], 0)

    def test_warns_on_legacy_brief_candidates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            (ws / "swarm").mkdir()
            (ws / "swarm" / "brief_candidates.json").write_text(
                json.dumps(
                    {
                        "candidates": [
                            {"contract": "Vault", "angle_id": "A-RACE"},
                        ]
                    }
                )
                + "\n"
            )
            r = MOD.check_evidence_class(ws)
            self.assertEqual(r.status, MOD.WARN)
            self.assertEqual(r.detail["legacy_count"], 1)
            self.assertEqual(r.detail["aggregate_counts"]["missing"], 1)

    def test_pass_when_all_rows_have_class(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            (ws / "swarm").mkdir()
            (ws / "swarm" / "brief_candidates.json").write_text(
                json.dumps(
                    {
                        "candidates": [
                            {
                                "contract": "Vault",
                                "angle_id": "A-RACE",
                                "evidence_class": "generated_hypothesis",
                            }
                        ]
                    }
                )
                + "\n"
            )
            (ws / "poc_execution" / "case01").mkdir(parents=True)
            (ws / "poc_execution" / "case01" / "execution_manifest.json").write_text(
                json.dumps(
                    {
                        "candidate_id": "case01",
                        "final_result": "proved",
                        "impact_assertion": "exploit_impact",
                        "evidence_class": "executed_with_manifest",
                    }
                )
                + "\n"
            )
            r = MOD.check_evidence_class(ws)
            self.assertEqual(r.status, MOD.PASS)
            self.assertEqual(r.detail["legacy_count"], 0)
            self.assertEqual(r.detail["verified_count"], 1)
            self.assertEqual(r.detail["hypothesis_count"], 1)

    def test_invalid_bound_sources_are_not_verified(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            manifest_dir = ws / "poc_execution" / "case01"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / "execution_manifest.json").write_text(
                json.dumps({
                    "candidate_id": "case01",
                    "evidence_class": "executed_with_manifest",
                    "bound_sources": [{"path": "stale.sol"}],
                })
                + "\n"
            )
            with mock.patch.object(
                MOD,
                "bound_source_validation",
                lambda manifest, workspace: {
                    "supplied": True,
                    "valid": False,
                    "errors": ["bound_source_missing"],
                },
            ):
                r = MOD.check_evidence_class(ws)
            self.assertEqual(r.detail["verified_count"], 0)
            self.assertEqual(r.detail["legacy_count"], 1)
            self.assertIn("poc_execution_manifests", r.detail["legacy_rows_sample"][0])

    def test_pr560_generated_artifacts_do_not_count_as_verified(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            audit = ws / ".auditooor"
            audit.mkdir()
            (audit / "impact_miss_offset_benchmark.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.pr560.impact_miss_offset_benchmark.v1",
                        "items": [
                            {"benchmark_id": "imo-001", "evidence_class": "generated_hypothesis"},
                            {"benchmark_id": "imo-002", "evidence_class": "generated_hypothesis"},
                        ],
                    }
                )
                + "\n"
            )
            (audit / "scanner_autonomy_plan.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_autonomy_executor.v1",
                        "tasks": [
                            {"task_id": "SAE-001", "evidence_class": "scaffolded_unverified"}
                        ],
                    }
                )
                + "\n"
            )
            (audit / "semantic_live_depth_queue.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.semantic_live_depth_queue.v1",
                        "rows": [
                            {"queue_id": "SLD-001", "evidence_class": "generated_hypothesis"}
                        ],
                    }
                )
                + "\n"
            )
            (audit / "semantic_detector_argument_resolver.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.semantic_detector_argument_resolver.v1",
                        "rows": [
                            {
                                "task_id": "SDAR-001",
                                "evidence_class": "generated_hypothesis",
                                "submit_ready": False,
                                "submission_posture": "NOT_SUBMIT_READY",
                            }
                        ],
                    }
                )
                + "\n"
            )
            (audit / "live_topology_proof_requirements.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.live_topology_proof_requirements.v1",
                        "requirements": [
                            {
                                "requirement_id": "LTR-001",
                                "evidence_class": "scaffolded_unverified",
                                "submit_ready": False,
                                "selected_impact": "same-block proof pair",
                            }
                        ],
                    }
                )
                + "\n"
            )
            (audit / "impact_proof_requirement_manifests.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.impact_proof_requirement_manifests.v1",
                        "rows": [
                            {
                                "requirement_id": "IPR-001",
                                "evidence_class": "scaffolded_unverified",
                                "submit_ready": False,
                                "selected_impact": "Critical asset custody",
                            }
                        ],
                    }
                )
                + "\n"
            )
            logs = ws / ".audit_logs" / "pr560_worker_zz"
            logs.mkdir(parents=True)
            (logs / "live_provider_result_triage.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.live_provider_result_triage.v1",
                        "rows": [
                            {
                                "task_id": "LPRT-001",
                                "evidence_class": "generated_hypothesis",
                                "submit_ready": False,
                                "submission_posture": "NOT_SUBMIT_READY",
                            }
                        ],
                    }
                )
                + "\n"
            )
            (logs / "provider_local_verification_closure.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.provider_local_verification_closure.v1",
                        "rows": [
                            {
                                "task_id": "PLV-001",
                                "evidence_class": "generated_hypothesis",
                                "submit_ready": False,
                                "selected_impact": "local source review",
                            }
                        ],
                    }
                )
                + "\n"
            )
            r = MOD.check_evidence_class(ws)
            self.assertEqual(r.status, MOD.PASS)
            self.assertEqual(r.detail["legacy_count"], 0)
            self.assertEqual(r.detail["verified_count"], 0)
            self.assertEqual(r.detail["policy_violation_count"], 0)
            self.assertEqual(r.detail["hypothesis_count"], 9)
            self.assertEqual(
                r.detail["per_artifact_counts"]["impact_miss_benchmark"]["generated_hypothesis"],
                2,
            )
            self.assertEqual(
                r.detail["per_artifact_counts"]["semantic_detector_argument_resolver"]["generated_hypothesis"],
                1,
            )
            self.assertEqual(
                r.detail["per_artifact_counts"]["live_topology_proof_requirements"]["scaffolded_unverified"],
                1,
            )
            self.assertEqual(
                r.detail["per_artifact_counts"]["live_provider_result_triage"]["generated_hypothesis"],
                1,
            )

    def test_evidence_class_warns_on_submit_ready_unverified_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-policy-") as tmp:
            ws = Path(tmp)
            audit = ws / ".auditooor"
            audit.mkdir()
            (audit / "impact_proof_requirement_manifests.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "requirement_id": "IPR-BAD",
                                "evidence_class": "scaffolded_unverified",
                                "submit_ready": True,
                                "promotion_allowed": True,
                                "selected_impact": "Critical asset custody",
                            }
                        ]
                    }
                )
                + "\n"
            )
            r = MOD.check_evidence_class(ws)

        self.assertEqual(r.status, MOD.WARN)
        self.assertEqual(r.detail["legacy_count"], 0)
        self.assertEqual(r.detail["policy_violation_count"], 2)
        self.assertIn("evidence policy violation", r.reason)
        reasons = {row["reason"] for row in r.detail["policy_violations_sample"]}
        self.assertIn("unverified_row_submit_ready_true", reasons)
        self.assertIn("unverified_row_promotion_allowed_true", reasons)

    def test_poc_execution_detail_carries_class_counts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-") as tmp:
            ws = Path(tmp)
            brief = ws / "source_mining" / "campaign_a" / "poc_task_briefs" / "001.md"
            brief.parent.mkdir(parents=True)
            brief.write_text("# brief\n")
            (ws / "poc_execution" / "case01").mkdir(parents=True)
            (ws / "poc_execution" / "case01" / "execution_manifest.json").write_text(
                json.dumps(
                    {
                        "candidate_id": "case01",
                        "final_result": "proved",
                        "impact_assertion": "exploit_impact",
                        "evidence_class": "executed_with_manifest",
                    }
                )
                + "\n"
            )
            r = MOD.check_poc_execution(ws)
            counts = r.detail["evidence_class_counts"]
            self.assertEqual(counts["executed_with_manifest"], 1)
            self.assertEqual(counts["missing"], 0)
            self.assertEqual(r.detail["verified_evidence_count"], 1)
            self.assertEqual(r.detail["hypothesis_evidence_count"], 0)


# ---------------------------------------------------------------------------
# PR #511 Slice 2 — invariant-ledger closeout row.
# ---------------------------------------------------------------------------


class InvariantLedgerCloseoutTests(unittest.TestCase):
    """check_invariant_ledger() — default WARN, strict-mode FAIL, never silent."""

    def _clean_env(self):
        return mock.patch.dict(
            os.environ,
            {"REQUIRE_INVARIANT_LEDGER": "", "REQUIRE_HIGH_IMPACT_INVARIANTS": ""},
            clear=False,
        )

    def test_missing_ledger_warns_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            with self._clean_env():
                r = MOD.check_invariant_ledger(ws)
            self.assertEqual(r.status, MOD.WARN)
            self.assertIn("invariant_ledger.json not found", r.reason)

    def test_missing_ledger_strict_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            with mock.patch.dict(os.environ, {"REQUIRE_INVARIANT_LEDGER": "1"}):
                r = MOD.check_invariant_ledger(ws)
            self.assertEqual(r.status, MOD.FAIL)

    def test_present_with_manifest_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "invariant_ledger.json").write_text(
                json.dumps({"schema": "auditooor.invariant_ledger.v1",
                            "rows": [{"id": "X-I01", "status": "executed_clean"}]})
                + "\n"
            )
            (ws / ".audit_logs").mkdir()
            (ws / ".audit_logs" / "invariant_ledger_manifest.json").write_text(
                json.dumps({
                    "schema": "auditooor.invariant_ledger_manifest.v1",
                    "row_count": 1,
                    "status_counts": {"executed_clean": 1},
                    "high_impact_total": 0,
                    "high_impact_ok": 0,
                    "issues": [],
                }) + "\n"
            )
            with self._clean_env():
                r = MOD.check_invariant_ledger(ws)
            self.assertEqual(r.status, MOD.PASS, r.reason)

    def test_high_impact_missing_warns_default_fails_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "invariant_ledger.json").write_text("{}\n")
            (ws / ".audit_logs").mkdir()
            (ws / ".audit_logs" / "invariant_ledger_manifest.json").write_text(
                json.dumps({
                    "schema": "auditooor.invariant_ledger_manifest.v1",
                    "row_count": 2,
                    "status_counts": {"missing_harness": 2},
                    "high_impact_total": 1,
                    "high_impact_ok": 0,
                    "issues": [],
                }) + "\n"
            )
            with self._clean_env():
                r_warn = MOD.check_invariant_ledger(ws)
            self.assertEqual(r_warn.status, MOD.WARN)
            with mock.patch.dict(
                os.environ, {"REQUIRE_HIGH_IMPACT_INVARIANTS": "1"}
            ):
                r_fail = MOD.check_invariant_ledger(ws)
            self.assertEqual(r_fail.status, MOD.FAIL)


# ---------------------------------------------------------------------------
# PR #513 follow-up — closeout integration must surface the new error
# paths flagged by Minimax: malformed JSON, empty array, missing keys.
# The closeout row is computed defensively (loose load + summary), so we
# check that the WARN row carries enough detail to point the operator
# at the underlying tool failure.
# ---------------------------------------------------------------------------


class InvariantLedgerCloseoutAdversarialTests(unittest.TestCase):
    """The closeout `check_invariant_ledger` should never silently no-op
    on a malformed ledger. Pre-fix the row computed `len(rows)=0` from a
    `_read_json` that swallowed `ValueError`, returning a generic WARN.
    Post-fix we still return a WARN (closeout is intentionally lenient
    so a stale ledger doesn't fail the gate by default), but the row's
    `detail` carries `row_count=0` which the named-path reason makes
    obvious to the operator. The tool side (`--check`) now hard-errors,
    which is where strict mode comes from."""

    def _clean_env(self):
        return mock.patch.dict(
            os.environ,
            {"REQUIRE_INVARIANT_LEDGER": "", "REQUIRE_HIGH_IMPACT_INVARIANTS": ""},
            clear=False,
        )

    def test_garbage_json_closeout_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "invariant_ledger.json").write_text("not json\n")
            with self._clean_env():
                r = MOD.check_invariant_ledger(ws)
            # Loose closeout doesn't crash on garbage; row count is 0
            # and the row's reason still flags the situation. The tool
            # CLI is the one that hard-errors on malformed JSON.
            self.assertIn(r.status, (MOD.WARN, MOD.FAIL))

    def test_empty_array_closeout_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "invariant_ledger.json").write_text("[]\n")
            with self._clean_env():
                r = MOD.check_invariant_ledger(ws)
            self.assertEqual(r.status, MOD.WARN)
            self.assertEqual(r.detail.get("row_count"), 0)

    def test_dict_no_rows_key_closeout_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "invariant_ledger.json").write_text(
                json.dumps({"schema": "x"}) + "\n"
            )
            with self._clean_env():
                r = MOD.check_invariant_ledger(ws)
            self.assertEqual(r.status, MOD.WARN)
            self.assertEqual(r.detail.get("row_count"), 0)


# ---------------------------------------------------------------------------
# PR #511 Slice 5 — audit-deep -> closeout manifest handoff.
# ---------------------------------------------------------------------------


class InvariantLedgerAuditDeepHandoffTests(unittest.TestCase):
    """End-to-end: audit-deep emits the manifest; closeout consumes it.

    This is the wiring contract Slice 5 promises: there is one source of
    truth (`<ws>/.audit_logs/invariant_ledger_manifest.json`) — audit-deep
    authors it, audit-closeout-check.py reads it. The Slice 5 deep-summary
    files are supplemental and live alongside.
    """

    def test_audit_deep_emits_manifest_consumed_by_closeout(self):
        import subprocess
        audit_deep = REPO_ROOT / "tools" / "audit-deep.sh"
        if not audit_deep.is_file():
            self.skipTest("tools/audit-deep.sh not present")
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "invariant_ledger.json").write_text(
                json.dumps({
                    "schema": "auditooor.invariant_ledger.v1",
                    "rows": [
                        {
                            "id": "X-I01",
                            "scope_asset": "X",
                            "invariant_family": "f",
                            "statement": "s",
                            "status": "executed_clean",
                            "required_engine": "forge",
                            "owner": "Claude",
                            "artifacts": [],
                            "source_citations": ["SCOPE.md::X"],
                            "harness_target": "test/X.t.sol",
                        },
                    ],
                }) + "\n"
            )
            # Run audit-deep with DRY_RUN=0 so Step 12 fully executes.
            res = subprocess.run(
                ["bash", str(audit_deep), str(ws)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(res.returncode, 0,
                             msg=f"audit-deep rc={res.returncode}\n{res.stdout}\n{res.stderr}")
            manifest_p = ws / ".audit_logs" / "invariant_ledger_manifest.json"
            self.assertTrue(manifest_p.is_file(),
                            "audit-deep did not write the closeout manifest")
            deep_md = ws / ".audit_logs" / "invariant_ledger_deep_summary.md"
            self.assertTrue(deep_md.is_file(),
                            "audit-deep did not write the deep summary md")

            # Closeout consumes the manifest authored by audit-deep.
            with mock.patch.dict(
                os.environ,
                {"REQUIRE_INVARIANT_LEDGER": "", "REQUIRE_HIGH_IMPACT_INVARIANTS": ""},
                clear=False,
            ):
                r = MOD.check_invariant_ledger(ws)
            self.assertEqual(r.status, MOD.PASS, r.reason)
            self.assertIn("1 row", r.reason)
            # The manifest path appears in the closeout artifacts list.
            self.assertIn(str(manifest_p), r.artifacts)


class PR560ArtifactClosureTests(unittest.TestCase):
    def _write_clean_pr560_artifacts(self, ws: Path) -> None:
        aud = ws / ".auditooor"
        aud.mkdir(parents=True, exist_ok=True)
        (aud / "agent_output_inventory.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "verification_task_id": "agent-output-verify-clean-1",
                            "local_verification_status": "verified_local",
                            "next_command": "",
                        }
                    ]
                }
            )
            + "\n"
        )
        (aud / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "candidate_id": "CLEAN-1",
                            "verdict": "in_scope_direct_submit",
                            "terminal_route": "prove_or_package",
                        }
                    ]
                }
            )
            + "\n"
        )
        (aud / "harness_tasks.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "harness_task_id": "HT-1",
                            "status": "ready_to_execute",
                            "next_command": "forge test --match-test testClean",
                        }
                    ]
                }
            )
            + "\n"
        )
        (aud / "impact_analysis_queue.json").write_text(
            json.dumps({"rows": [], "status": "empty_no_blocked_agent_recall_rows"})
            + "\n"
        )
        (aud / "source_proof_tasks.json").write_text(
            json.dumps({"rows": [], "status": "empty_no_source_proof_tasks"})
            + "\n"
        )
        (aud / "invariant_acceptance_queue.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "queue_id": "invariant-acceptance-clean",
                            "generated_invariant_id": "GEN-CLEAN",
                            "status": "advisory_killed",
                            "suggested_ledger_action": "kill_oos",
                            "exact_source_scope_text": "Reviewed OOS scope text",
                            "oos_precondition": "OOS duplicate reviewed",
                            "kill_evidence_artifact": ".auditooor/invariant_ledger_updates/GEN-CLEAN-kill.json",
                            "next_command": "make automation-closure WS=<workspace>",
                            "severity": "none",
                            "paste_ready": False,
                            "submit_ready": False,
                        }
                    ],
                    "status": "advisory_invariant_acceptance_queue_open",
                }
            )
            + "\n"
        )
        (aud / "pr560_next_actions.json").write_text(
            json.dumps({"rows": [], "status": "advisory_no_next_actions"})
            + "\n"
        )
        (ws / "source_proofs" / "CLEAN-1").mkdir(parents=True)
        (ws / "source_proofs" / "CLEAN-1" / "source_proof.json").write_text(
            json.dumps({"candidate_id": "CLEAN-1", "final_verdict": "killed"})
            + "\n"
        )
        (aud / "corpus_detectorization_inventory.json").write_text(
            json.dumps({"rows": [{"row_id": "CD-1", "terminal_state": "detectorized"}]})
            + "\n"
        )
        (aud / "known_limitations_burndown.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "limitation_id": "KL-1",
                            "terminal_state": "already_satisfied_with_citation",
                            "strict_status": "ok",
                        }
                    ]
                }
            )
            + "\n"
        )
        (aud / "pr560_next_actions.json").write_text(
            json.dumps({"rows": [], "status": "empty_no_pr560_next_actions"})
            + "\n"
        )

    def test_pr560_artifacts_missing_are_advisory_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-pr560-") as tmp:
            ws = Path(tmp)
            row = MOD.check_pr560_artifact_closure(ws, require_strict=False)
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("impact_contracts", row.reason)
            self.assertIn("advisory only", row.reason)
            self.assertEqual(
                set(row.detail["missing_artifacts"]),
                {
                    "impact_contracts",
                    "agent_output_inventory",
                    "harness_tasks",
                    "impact_analysis_queue",
                    "source_proof_tasks",
                    "invariant_acceptance_queue",
                    "pr560_next_actions",
                    "source_proofs",
                    "corpus_detectorization_inventory",
                    "known_limitations_burndown",
                    "pr560_next_actions",
                },
            )

    def test_pr560_artifacts_missing_fail_only_when_strict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-pr560-") as tmp:
            ws = Path(tmp)
            row = MOD.check_pr560_artifact_closure(ws, require_strict=True)
            self.assertEqual(row.status, MOD.FAIL)
            self.assertIn("STRICT closeout enabled", row.reason)

    def test_pr560_unresolved_rows_surface_in_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-pr560-") as tmp:
            ws = Path(tmp)
            self._write_clean_pr560_artifacts(ws)
            aud = ws / ".auditooor"
            (aud / "impact_contracts.json").write_text(
                json.dumps(
                    {
                        "contracts": [
                            {
                                "candidate_id": "SNAPPY",
                                "verdict": "NOT_SUBMIT_READY",
                                "terminal_route": "kill_or_reframe",
                                "missing_proof": ["exact Base Azul impact not proven"],
                            }
                        ]
                    }
                )
                + "\n"
            )
            (aud / "agent_output_inventory.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "verification_task_id": "agent-output-verify-snappy",
                                "stable_source_path": "<ws>/agent_outputs/snappy.md",
                                "local_verification_status": "needs_local_verification",
                                "next_command": "make agent-recall WS=<workspace> && make impact-analysis-queue WS=<workspace>",
                            }
                        ]
                    }
                )
                + "\n"
            )
            (aud / "harness_tasks.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "harness_task_id": "HT-BLOCKED",
                                "status": "blocked_missing_impact_contract",
                                "next_command": "make impact-contract-check WS=<workspace>",
                            }
                        ]
                    }
                )
                + "\n"
            )
            (aud / "corpus_detectorization_inventory.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "row_id": "CD-HARNESS",
                                "terminal_state": "harness_task",
                            }
                        ]
                    }
                )
                + "\n"
            )
            (aud / "impact_analysis_queue.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "queue_id": "impact-analysis-001",
                                "action_type": "exact_impact_candidate",
                                "next_command": "make impact-contract-check WS=<workspace>",
                            }
                        ]
                    }
                )
                + "\n"
            )
            (aud / "source_proof_tasks.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "source_proof_task_id": "source-proof-task-snappy-001",
                                "status": "blocked_missing_impact_contract",
                                "next_command": "make source-proof-record WS=<workspace> CANDIDATE=SNAPPY VERDICT=blocked_missing_impact_contract",
                            }
                        ]
                    }
                )
                + "\n"
            )
            (aud / "invariant_acceptance_queue.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "queue_id": "invariant-acceptance-gen-missing-01",
                                "generated_invariant_id": "GEN-MISSING-01",
                                "status": "advisory_needs_harness",
                                "suggested_ledger_action": "needs_harness",
                                "severity": "none",
                                "paste_ready": False,
                                "submit_ready": False,
                                "next_command": "make harness-plan WS=<workspace> ROW=GEN-MISSING-01",
                                "missing_review_evidence": [
                                    "invariant_acceptance_ledger row for GEN-MISSING-01 with action needs_harness"
                                ],
                            }
                        ]
                    }
                )
                + "\n"
            )
            (aud / "pr560_next_actions.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "next_action_id": "pr560-next-action-invariant-gen-missing-01",
                                "source_queue": "invariant_acceptance_queue",
                                "generated_invariant_id": "GEN-MISSING-01",
                                "status": "advisory_needs_harness",
                                "severity": "none",
                                "paste_ready": False,
                                "submit_ready": False,
                                "next_command": "make harness-plan WS=<workspace> ROW=GEN-MISSING-01",
                            }
                        ]
                    }
                )
                + "\n"
            )
            (aud / "known_limitations_burndown.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "limitation_id": "KL-P0",
                                "terminal_state": "deferred_with_owner",
                                "strict_status": "ok",
                                "next_command": "make harness-task-queue WS=<workspace>",
                                "stop_condition": "executed evidence lands",
                            }
                        ]
                    }
                )
                + "\n"
            )
            (aud / "pr560_next_actions.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "next_action_id": "pr560-next-001",
                                "category": "harness_impact_work",
                                "status": "harness_impact_work",
                                "exact_status": "impact_contract_suggested",
                                "next_command": "make impact-contract-check WS=<workspace> # CANDIDATE=SNAPPY",
                            }
                        ]
                    }
                )
                + "\n"
            )

            row = MOD.check_pr560_artifact_closure(ws, require_strict=False)
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("agent_output_inventory=1", row.reason)
            self.assertIn("impact_contracts=1", row.reason)
            self.assertIn("harness_tasks=1", row.reason)
            self.assertIn("corpus_detectorization_inventory=1", row.reason)
            self.assertIn("impact_analysis_queue=1", row.reason)
            self.assertIn("source_proof_tasks=1", row.reason)
            self.assertIn("invariant_acceptance_queue=1", row.reason)
            self.assertIn("pr560_next_actions=1", row.reason)
            self.assertIn("known_limitations_burndown=1", row.reason)
            self.assertEqual(row.detail["total_unresolved"], 9)
            commands = {
                example["next_command"]
                for example in row.detail["next_command_examples"]
            }
            self.assertIn("make agent-recall WS=<workspace> && make impact-analysis-queue WS=<workspace>", commands)
            self.assertIn("make impact-contract-check WS=<workspace>", commands)
            self.assertIn(
                "make source-proof-record WS=<workspace> CANDIDATE=SNAPPY VERDICT=blocked_missing_impact_contract",
                commands,
            )
            self.assertIn("make harness-plan WS=<workspace> ROW=GEN-MISSING-01", commands)
            inv_missing = row.detail["artifacts"]["invariant_acceptance_queue"]["unresolved_rows"][0]["missing_fields"]
            self.assertIn(
                "invariant_acceptance_ledger row for GEN-MISSING-01 with action needs_harness",
                inv_missing,
            )

            strict_row = MOD.check_pr560_artifact_closure(ws, require_strict=True)
            self.assertEqual(strict_row.status, MOD.FAIL)

    def test_pr560_human_output_includes_queue_next_commands(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-pr560-") as tmp:
            ws = Path(tmp)
            self._write_clean_pr560_artifacts(ws)
            aud = ws / ".auditooor"
            (aud / "impact_analysis_queue.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "queue_id": "impact-analysis-002",
                                "action_type": "source_proof_precondition",
                                "next_command": "make source-proof-record WS=<workspace> CANDIDATE=C-2",
                            }
                        ]
                    }
                )
                + "\n"
            )
            row = MOD.check_pr560_artifact_closure(ws, require_strict=False)
            rendered = MOD._format_human([row])
            self.assertIn("impact_analysis_queue:impact-analysis-002", rendered)
            self.assertIn("make source-proof-record WS=<workspace> CANDIDATE=C-2", rendered)

    def test_pr560_accepted_invariant_rows_are_advisory_not_submit_ready(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-pr560-") as tmp:
            ws = Path(tmp)
            self._write_clean_pr560_artifacts(ws)
            aud = ws / ".auditooor"
            (aud / "invariant_acceptance_queue.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "queue_id": "invariant-acceptance-gen-accepted",
                                "generated_invariant_id": "GEN-ACCEPTED",
                                "status": "advisory_accepted",
                                "review_state": "accepted",
                                "suggested_ledger_action": "accept",
                                "exact_source_scope_text": "Reviewed scope text",
                                "ledger_update_artifact": ".auditooor/invariant_ledger_updates/GEN-ACCEPTED.json",
                                "next_command": "python3 tools/invariant-ledger.py --workspace <workspace> --check",
                                "severity": "none",
                                "paste_ready": False,
                                "submit_ready": False,
                                "promotion_blockers": ["exact_impact_proof_missing"],
                            }
                        ]
                    }
                )
                + "\n"
            )
            row = MOD.check_pr560_artifact_closure(ws, require_strict=False)
            self.assertEqual(row.status, MOD.PASS)
            inv = row.detail["artifacts"]["invariant_acceptance_queue"]
            self.assertEqual(inv["unresolved_count"], 0)
            self.assertEqual(inv["row_count"], 1)

    def test_pr560_invariant_acceptance_rows_fail_closed_without_review_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-pr560-") as tmp:
            ws = Path(tmp)
            self._write_clean_pr560_artifacts(ws)
            aud = ws / ".auditooor"
            (aud / "invariant_acceptance_queue.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "queue_id": "invariant-acceptance-gen-accepted",
                                "generated_invariant_id": "GEN-ACCEPTED",
                                "status": "advisory_accepted",
                                "review_state": "accepted",
                                "suggested_ledger_action": "accept",
                                "severity": "none",
                                "paste_ready": False,
                                "submit_ready": False,
                            }
                        ]
                    }
                )
                + "\n"
            )
            row = MOD.check_pr560_artifact_closure(ws, require_strict=False)
            self.assertEqual(row.status, MOD.WARN)
            inv = row.detail["artifacts"]["invariant_acceptance_queue"]
            self.assertEqual(inv["unresolved_count"], 1)
            self.assertEqual(
                inv["unresolved_rows"][0]["missing_fields"],
                ["exact_source_scope_text", "ledger_update_artifact", "next_command"],
            )

    def test_pr560_accepted_invariant_next_action_stays_advisory_until_impact_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-pr560-") as tmp:
            ws = Path(tmp)
            self._write_clean_pr560_artifacts(ws)
            aud = ws / ".auditooor"
            (aud / "pr560_next_actions.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "next_action_id": "pr560-next-action-invariant-gen-accepted",
                                "source_queue": "invariant_acceptance_queue",
                                "generated_invariant_id": "GEN-ACCEPTED",
                                "status": "advisory_accepted",
                                "review_state": "accepted",
                                "severity": "none",
                                "paste_ready": False,
                                "submit_ready": False,
                                "promotion_blockers": ["exact_impact_proof_missing"],
                                "next_command": "make impact-contract-check WS=<workspace> ROW=GEN-ACCEPTED",
                            }
                        ]
                    }
                )
                + "\n"
            )
            row = MOD.check_pr560_artifact_closure(ws, require_strict=False)
            self.assertEqual(row.status, MOD.WARN)
            self.assertIn("pr560_next_actions=1", row.reason)
            next_actions = row.detail["artifacts"]["pr560_next_actions"]
            self.assertEqual(next_actions["unresolved_count"], 1)
            self.assertEqual(next_actions["unresolved_rows"][0]["state"], "advisory_accepted")
            self.assertEqual(
                next_actions["unresolved_rows"][0]["next_command"],
                "make impact-contract-check WS=<workspace> ROW=GEN-ACCEPTED",
            )

            strict_row = MOD.check_pr560_artifact_closure(ws, require_strict=True)
            self.assertEqual(strict_row.status, MOD.FAIL)

    def test_pr560_clean_artifacts_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-pr560-") as tmp:
            ws = Path(tmp)
            self._write_clean_pr560_artifacts(ws)
            row = MOD.check_pr560_artifact_closure(ws, require_strict=False)
            self.assertEqual(row.status, MOD.PASS)
            self.assertIn("no unresolved blocked rows", row.reason)

    def test_run_all_includes_pr560_artifact_closure_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-pr560-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            self._write_clean_pr560_artifacts(ws)
            results = MOD.run_all(ws, require_deep=False)
            row = _by_check(results)["pr560-artifact-closure"]
            self.assertEqual(row.status, MOD.PASS)


def _by_check(results: list) -> dict:
    """Index check results by check name (deduplicating with last-wins)."""
    return {r.check: r for r in results}


def _write_prove_top_leads_full_artifacts(ws: Path) -> None:
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)
    (aud / "prove_top_leads_source_mine.json").write_text(
        json.dumps({"schema": "auditooor.exploit_queue_source_miner.v1", "source_found": 1}) + "\n"
    )
    (aud / "prove_top_leads_source_mined_impact_contracts.json").write_text(
        json.dumps({"contracts": [{"candidate_id": "EQ-001"}]}) + "\n"
    )
    (aud / "prove_top_leads_prefiling_stress_test.json").write_text(
        json.dumps({"results": [{"candidate_id": "EQ-001", "questions": {}}]}) + "\n"
    )
    (aud / "prove_top_leads_candidate_judgment_packet.json").write_text(
        json.dumps({"packets": [{"candidate_id": "EQ-001"}]}) + "\n"
    )
    (aud / "prove_top_leads_outcome_lesson_gate.json").write_text(
        json.dumps({"schema": "auditooor.outcome_lesson_gate.v1", "status": "pass"}) + "\n"
    )


def _write_evm_high_queue(ws: Path) -> None:
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)
    (ws / "src").mkdir(parents=True, exist_ok=True)
    (ws / "src" / "Target.sol").write_text("contract Target {}\n")
    (aud / "exploit_queue.json").write_text(
        json.dumps({"queue": [{"likely_severity": "High", "language": "solidity"}]}) + "\n"
    )


def _write_typed_evm_proof(ws: Path, *, mutate: bool = False) -> None:
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)
    parent = ["zdo-evm", "zdr-evm"]
    queue = {
        "schema": "auditooor.exploit_queue.v1", "queue_role": "proof_tasks", "entries": [],
        "queue": [{"lead_id": "evm-lead", "obligation_id": parent[0], "revision_id": parent[1],
            "zero_day_proof_projection": {"schema": "auditooor.zero_day_proof_queue_projection.v1", "freeze_receipt_id": "a" * 64, "freeze_input_fingerprint": "b" * 64, "obligation_source_row_sha256": "c" * 64, "parent_ids": parent, "selection_ordinal": 1, "question_evidence": [{"question_id": "q0", "axis": "asset_invariant"}]},
            "zero_day_proof_admission": {"freeze_receipt_id": "a" * 64, "input_fingerprint": "b" * 64, "obligation_source_row_sha256": "c" * 64, "parent_ids": parent}}],
        "zero_day_proof_admission": {"schema": "auditooor.zero_day_proof_admission.v1", "queue_role": "proof_tasks", "admission_id": "zdpa_" + "d" * 64, "input_queue_sha256": "e" * 64, "freeze_receipt_id": "a" * 64, "freeze_input_fingerprint": "b" * 64, "admitted_count": 1, "admitted_parents": [{"obligation_id": parent[0], "revision_id": parent[1]}]},
    }
    queue_path = aud / "exploit_queue.zero_day_admitted.json"
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    envelope_tool = MOD._load_typed_envelope_tool()
    envelope = envelope_tool.materialize(ws, queue_path, aud / "zero_day_proof_envelope.json")
    if mutate:
        queue["queue"][0]["zero_day_proof_projection"]["selection_ordinal"] = 2
        queue_path.write_text(json.dumps(queue), encoding="utf-8")
    (aud / "evm_0day_proof.json").write_text(json.dumps({"schema": "auditooor.evm_0day_proof_pipeline.v1", "verdict": "proof-backed", "candidate": {"lead_id": "evm-lead", "zero_day_proof_envelope": envelope["entries"][0]}}), encoding="utf-8")


class TestTypedEvmProofBinding(unittest.TestCase):
    def test_typed_evm_proof_requires_current_envelope_binding(self) -> None:
        with tempfile.TemporaryDirectory(prefix="typed-evm-proof-") as tmp:
            ws = Path(tmp)
            _write_evm_high_queue(ws)
            _write_typed_evm_proof(ws)
            self.assertTrue(MOD._evm_0day_proof_artifact_state(ws)["proof_valid"])
            _write_typed_evm_proof(ws, mutate=True)
            state = MOD._evm_0day_proof_artifact_state(ws)
            self.assertFalse(state["proof_valid"])
            self.assertEqual(state["reason"], "typed_evm_proof_envelope_invalid")


class TestH1StrictHackermanReceipts(unittest.TestCase):
    """H1 - brain-prime/novel-vectors/conversion-loop receipts gate."""

    def _make_hc_draft(self, ws: Path) -> None:
        staging = ws / "submissions" / "staging"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "high_crit.md").write_text(
            "# Finding\nSeverity: High\n\n## Description\nBug.\n"
        )

    def test_no_hc_drafts_no_receipts_is_warn(self) -> None:
        """Without H/C drafts, missing receipts stay advisory WARN."""
        with tempfile.TemporaryDirectory(prefix="h1-") as tmp:
            ws = Path(tmp)
            result = MOD.check_strict_hackerman_receipts(ws, strict=True)
            self.assertEqual(result.status, MOD.WARN)

    def test_hc_draft_with_receipts_passes(self) -> None:
        """STRICT=1 + H/C draft + all receipts -> PASS."""
        with tempfile.TemporaryDirectory(prefix="h1-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "brain_prime_receipt.json").write_text('{"ok":true}\n')
            (aud / "novel_vectors.summary.json").write_text('{"ok":true}\n')
            (aud / "exploit_conversion_loop_manifest.json").write_text(
                '{"schema":"auditooor.exploit_conversion_loop.v1","hard_failure_count":0}\n'
            )
            _write_prove_top_leads_full_artifacts(ws)
            result = MOD.check_strict_hackerman_receipts(ws, strict=True)
            self.assertEqual(result.status, MOD.PASS)

    def test_hc_draft_missing_receipts_strict_fails(self) -> None:
        """STRICT=1 + H/C draft + missing brain-prime -> FAIL."""
        with tempfile.TemporaryDirectory(prefix="h1-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            result = MOD.check_strict_hackerman_receipts(ws, strict=True)
            self.assertEqual(result.status, MOD.FAIL)
            self.assertIn("brain-prime-receipt", result.reason)

    def test_hc_draft_missing_only_conversion_is_warn_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h1-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "brain_prime_receipt.json").write_text('{"ok":true}\n')
            (aud / "novel_vectors.summary.json").write_text('{"ok":true}\n')
            with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": ""}):
                result = MOD.check_strict_hackerman_receipts(ws, strict=True)
            self.assertEqual(result.status, MOD.WARN)
            self.assertEqual(result.detail["missing_hard"], [])
            self.assertEqual(
                result.detail["missing_advisory"],
                ["exploit-conversion-loop", "prove-top-leads"],
            )

    def test_hc_draft_missing_only_conversion_fails_when_enforced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h1-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "brain_prime_receipt.json").write_text('{"ok":true}\n')
            (aud / "novel_vectors.summary.json").write_text('{"ok":true}\n')
            _write_prove_top_leads_full_artifacts(ws)
            with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
                result = MOD.check_strict_hackerman_receipts(ws, strict=True)
            self.assertEqual(result.status, MOD.FAIL)
            self.assertEqual(result.detail["missing_hard"], ["exploit-conversion-loop"])

    def test_hc_draft_missing_only_prove_top_leads_fails_when_enforced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h1-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "brain_prime_receipt.json").write_text('{"ok":true}\n')
            (aud / "novel_vectors.summary.json").write_text('{"ok":true}\n')
            (aud / "exploit_conversion_loop_manifest.json").write_text(
                '{"schema":"auditooor.exploit_conversion_loop.v1","hard_failure_count":0}\n'
            )
            with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
                result = MOD.check_strict_hackerman_receipts(ws, strict=True)
            self.assertEqual(result.status, MOD.FAIL)
            self.assertIn("prove-top-leads", result.detail["missing_hard"])

    def test_non_strict_with_hc_draft_missing_receipts_stays_warn(self) -> None:
        """strict=False keeps WARN even when H/C draft exists."""
        with tempfile.TemporaryDirectory(prefix="h1-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            result = MOD.check_strict_hackerman_receipts(ws, strict=False)
            self.assertEqual(result.status, MOD.WARN)

    def test_run_all_includes_strict_hackerman_receipts_row(self) -> None:
        """run_all returns a strict-hackerman-receipts check row."""
        with tempfile.TemporaryDirectory(prefix="h1-run-all-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            results = MOD.run_all(ws, require_deep=False, strict=False)
            checks = _by_check(results)
            self.assertIn("strict-hackerman-receipts", checks)


class TestH2StrictAdvisoryBlockers(unittest.TestCase):
    """H2 - bridge/queue advisory failures become BLOCKERS for H/C in STRICT mode."""

    def _make_hc_draft(self, ws: Path) -> None:
        staging = ws / "submissions" / "staging"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "high_draft.md").write_text(
            "# Finding\nSeverity: Critical\n\n## Description\nCritical bug.\n"
        )

    def test_no_issues_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2-") as tmp:
            ws = Path(tmp)
            result = MOD.check_strict_advisory_blockers(ws, strict=True)
            self.assertEqual(result.status, MOD.PASS)

    def test_bridge_failure_non_strict_is_warn(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2-") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "audit_hacker_logic_bridge.json").write_text(
                '{"status":"fail","reason":"bridge error"}\n'
            )
            result = MOD.check_strict_advisory_blockers(ws, strict=False)
            self.assertEqual(result.status, MOD.WARN)

    def test_bridge_failure_strict_hc_draft_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "audit_hacker_logic_bridge.json").write_text(
                '{"status":"fail","reason":"bridge error"}\n'
            )
            result = MOD.check_strict_advisory_blockers(ws, strict=True)
            self.assertEqual(result.status, MOD.FAIL)
            self.assertIn("audit-hacker-logic-bridge", result.reason)

    def test_loop_hard_failure_strict_hc_warns_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "exploit_conversion_loop_manifest.json").write_text(
                '{"schema":"auditooor.exploit_conversion_loop.v1","hard_failure_count":3}\n'
            )
            with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": ""}):
                result = MOD.check_strict_advisory_blockers(ws, strict=True)
            self.assertEqual(result.status, MOD.WARN)
            self.assertIn("hard_failure_count=3", result.reason)
            self.assertEqual(result.detail["strict_blocker_issues"], [])

    def test_loop_hard_failure_strict_hc_fails_when_enforced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "exploit_conversion_loop_manifest.json").write_text(
                '{"schema":"auditooor.exploit_conversion_loop.v1","hard_failure_count":3}\n'
            )
            with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
                result = MOD.check_strict_advisory_blockers(ws, strict=True)
            self.assertEqual(result.status, MOD.FAIL)
            self.assertIn("hard_failure_count=3", result.reason)
            self.assertEqual(
                result.detail["strict_blocker_issues"],
                ["exploit-conversion-loop hard_failure_count=3"],
            )

    def test_loop_hard_failure_zero_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "exploit_conversion_loop_manifest.json").write_text(
                '{"schema":"auditooor.exploit_conversion_loop.v1","hard_failure_count":0}\n'
            )
            result = MOD.check_strict_advisory_blockers(ws, strict=True)
            self.assertEqual(result.status, MOD.PASS)

    def test_run_all_includes_strict_advisory_blockers_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2-run-all-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            results = MOD.run_all(ws, require_deep=False, strict=False)
            checks = _by_check(results)
            self.assertIn("strict-advisory-blockers", checks)


class TestH3FullAuditPath(unittest.TestCase):
    """H3 - enforce the full audit/deep pipeline with typed NO_<STAGE>_REASON skips."""

    def _make_hc_draft(self, ws: Path) -> None:
        staging = ws / "submissions" / "staging"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "hc.md").write_text("# Finding\nSeverity: High\n\n## Bug.\n")

    def test_no_hc_drafts_missing_stages_advisory(self) -> None:
        """Without H/C drafts, missing required stages stay advisory."""
        with tempfile.TemporaryDirectory(prefix="h3-") as tmp:
            ws = Path(tmp)
            result = MOD.check_full_audit_path(ws, strict=True)
            self.assertIn(result.status, (MOD.WARN, MOD.PASS))

    def test_hc_draft_missing_required_stages_strict_fails(self) -> None:
        """STRICT=1 + H/C + missing make-audit artifact -> FAIL."""
        with tempfile.TemporaryDirectory(prefix="h3-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            # No engage_report.md, no brain_prime_receipt, no audit_deep manifest.
            result = MOD.check_full_audit_path(ws, strict=True)
            self.assertEqual(result.status, MOD.FAIL)
            self.assertIn("make-audit", result.reason)

    def test_hc_draft_with_all_required_passes(self) -> None:
        """STRICT=1 + H/C + all required artifacts -> PASS."""
        with tempfile.TemporaryDirectory(prefix="h3-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            # Write required stage artifacts.
            (ws / "engage_report.md").write_text("# report\n")
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "brain_prime_receipt.json").write_text('{"ok":true}\n')
            (ws / ".audit_logs").mkdir(parents=True, exist_ok=True)
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").write_text(
                '{"schema":"auditooor.audit_deep_all.v1","profiles":[]}\n'
            )
            (aud / "exploit_conversion_loop_manifest.json").write_text(
                '{"schema":"auditooor.exploit_conversion_loop.v1"}\n'
            )
            result = MOD.check_full_audit_path(ws, strict=True)
            self.assertEqual(result.status, MOD.PASS)
            self.assertEqual(result.detail["missing_required_stages"], [])

    def test_hc_draft_missing_only_conversion_stage_passes_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h3-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            (ws / "engage_report.md").write_text("# report\n")
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "brain_prime_receipt.json").write_text('{"ok":true}\n')
            (ws / ".audit_logs").mkdir(parents=True, exist_ok=True)
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").write_text(
                '{"schema":"auditooor.audit_deep_all.v1","profiles":[]}\n'
            )
            with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": ""}):
                result = MOD.check_full_audit_path(ws, strict=True)
            self.assertEqual(result.status, MOD.PASS)
            self.assertNotIn(
                "exploit-conversion-loop",
                result.detail["missing_required_stages"],
            )

    def test_hc_draft_missing_only_conversion_stage_fails_when_enforced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h3-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            (ws / "engage_report.md").write_text("# report\n")
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "brain_prime_receipt.json").write_text('{"ok":true}\n')
            (ws / ".audit_logs").mkdir(parents=True, exist_ok=True)
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").write_text(
                '{"schema":"auditooor.audit_deep_all.v1","profiles":[]}\n'
            )
            _write_prove_top_leads_full_artifacts(ws)
            with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
                result = MOD.check_full_audit_path(ws, strict=True)
            self.assertEqual(result.status, MOD.FAIL)
            self.assertIn(
                "exploit-conversion-loop",
                result.detail["missing_required_stages"],
            )

    def test_hc_draft_missing_only_prove_top_leads_stage_fails_when_enforced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h3-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            (ws / "engage_report.md").write_text("# report\n")
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "brain_prime_receipt.json").write_text('{"ok":true}\n')
            (aud / "exploit_conversion_loop_manifest.json").write_text(
                '{"schema":"auditooor.exploit_conversion_loop.v1","hard_failure_count":0}\n'
            )
            (ws / ".audit_logs").mkdir(parents=True, exist_ok=True)
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").write_text(
                '{"schema":"auditooor.audit_deep_all.v1","profiles":[]}\n'
            )
            with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
                result = MOD.check_full_audit_path(ws, strict=True)
            self.assertEqual(result.status, MOD.FAIL)
            self.assertIn(
                "prove-top-leads",
                result.detail["missing_required_stages"],
            )

    def test_evm_medium_plus_missing_proof_stage_fails_when_enforced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h3-evm-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            (ws / "engage_report.md").write_text("# report\n")
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "brain_prime_receipt.json").write_text('{"ok":true}\n')
            (aud / "exploit_conversion_loop_manifest.json").write_text(
                '{"schema":"auditooor.exploit_conversion_loop.v1","hard_failure_count":0}\n'
            )
            _write_prove_top_leads_full_artifacts(ws)
            _write_evm_high_queue(ws)
            (ws / ".audit_logs").mkdir(parents=True, exist_ok=True)
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").write_text(
                '{"schema":"auditooor.audit_deep_all.v1","profiles":[]}\n'
            )
            with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
                result = MOD.check_full_audit_path(ws, strict=True)
            self.assertEqual(result.status, MOD.FAIL)
            self.assertIn("evm-0day-proof", result.detail["missing_required_stages"])

    def test_evm_status_complete_is_not_proof_backed_when_enforced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h3-evm-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            (ws / "engage_report.md").write_text("# report\n")
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            (aud / "brain_prime_receipt.json").write_text('{"ok":true}\n')
            (aud / "exploit_conversion_loop_manifest.json").write_text(
                '{"schema":"auditooor.exploit_conversion_loop.v1","hard_failure_count":0}\n'
            )
            _write_prove_top_leads_full_artifacts(ws)
            _write_evm_high_queue(ws)
            (aud / "evm_0day_proof.json").write_text('{"status":"complete"}\n')
            (ws / ".audit_logs").mkdir(parents=True, exist_ok=True)
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").write_text(
                '{"schema":"auditooor.audit_deep_all.v1","profiles":[]}\n'
            )
            with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
                result = MOD.check_full_audit_path(ws, strict=True)
            self.assertEqual(result.status, MOD.FAIL)
            self.assertIn("evm-0day-proof", result.detail["missing_required_stages"])

    def test_typed_skip_satisfies_required_stage(self) -> None:
        """A typed NO_<STAGE>_REASON in stage_skips.json satisfies the required stage."""
        with tempfile.TemporaryDirectory(prefix="h3-skip-") as tmp:
            ws = Path(tmp)
            self._make_hc_draft(ws)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            # Skip brain-prime and exploit-conversion-loop with typed reasons.
            (aud / "stage_skips.json").write_text(
                json.dumps({
                    "NO_BRAIN_PRIME_REASON": "workspace has no Solidity; brain-prime not applicable",
                    "NO_EXPLOIT_CONVERSION_REASON": "no exploit queue rows; skipped by design",
                })
            )
            # Provide make-audit artifact and audit-deep manifest.
            (ws / "engage_report.md").write_text("# report\n")
            (ws / ".audit_logs").mkdir(parents=True, exist_ok=True)
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").write_text(
                '{"schema":"auditooor.audit_deep_all.v1","profiles":[]}\n'
            )
            result = MOD.check_full_audit_path(ws, strict=True)
            # brain-prime and exploit-conversion-loop are now typed-skipped.
            missing = result.detail.get("missing_required_stages", [])
            self.assertNotIn("brain-prime", missing)
            self.assertNotIn("exploit-conversion-loop", missing)

    def test_run_all_includes_full_audit_path_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h3-run-all-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            results = MOD.run_all(ws, require_deep=False, strict=False)
            checks = _by_check(results)
            self.assertIn("full-audit-path", checks)


class TestK6LearningGate(unittest.TestCase):
    """K6 - agent-learning-gate wired into closeout; manifest carries K6 fields."""

    def test_run_all_includes_learning_gate_row(self) -> None:
        """run_all always includes a learning-gate row."""
        with tempfile.TemporaryDirectory(prefix="k6-run-all-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            results = MOD.run_all(ws, require_deep=False, strict=False)
            checks = _by_check(results)
            self.assertIn("learning-gate", checks)

    def test_learning_gate_row_has_k6_detail_fields(self) -> None:
        """learning-gate detail includes learning_gate_status and unclassified_artifact_count."""
        with tempfile.TemporaryDirectory(prefix="k6-detail-") as tmp:
            ws = Path(tmp)
            result = MOD.check_learning_gate(ws, strict=False)
            self.assertIn("learning_gate_status", result.detail)
            self.assertIn("unclassified_artifact_count", result.detail)
            self.assertIn("learning_ledger_path", result.detail)

    def test_manifest_payload_includes_learning_gate_summary(self) -> None:
        """_closeout_manifest_payload includes summary.learning_gate when row present."""
        with tempfile.TemporaryDirectory(prefix="k6-manifest-") as tmp:
            ws = Path(tmp)
            _scaffold_healthy(ws)
            results = MOD.run_all(ws, require_deep=False, strict=False)
            payload = MOD._closeout_manifest_payload(
                ws, results,
                require_deep=False,
                strict=False,
            )
            # The summary should include a learning_gate block if the row ran.
            lg_row = _by_check(results).get("learning-gate")
            if lg_row is not None and lg_row.detail.get("learning_gate_status"):
                self.assertIn("learning_gate", payload["summary"])

    def test_no_gate_tool_emits_warn(self) -> None:
        """When agent-learning-gate.py is missing, emit WARN not FAIL."""
        with tempfile.TemporaryDirectory(prefix="k6-no-tool-") as tmp:
            ws = Path(tmp)
            # Patch REPO_ROOT so the tool is not found.
            orig = MOD.REPO_ROOT
            try:
                MOD.REPO_ROOT = Path(tmp)
                result = MOD.check_learning_gate(ws, strict=False)
                self.assertEqual(result.status, MOD.WARN)
                self.assertIn("not found", result.reason)
            finally:
                MOD.REPO_ROOT = orig


if __name__ == "__main__":
    unittest.main()
