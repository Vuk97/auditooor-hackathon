#!/usr/bin/env python3
"""Regression tests for tools/audit-deep-manifest.py."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent.parent
TOOL = REPO / "tools" / "audit-deep-manifest.py"
MAKEFILE = REPO / "Makefile"


class TestAuditDeepManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("python3"):
            raise unittest.SkipTest("python3 not on PATH")
        if not shutil.which("make"):
            raise unittest.SkipTest("make not on PATH")
        if not TOOL.is_file():
            raise unittest.SkipTest(f"{TOOL} not found")
        if not MAKEFILE.is_file():
            raise unittest.SkipTest(f"{MAKEFILE} not found")

    def setUp(self) -> None:
        self.sandbox = Path(tempfile.mkdtemp(prefix="audit_deep_manifest_"))
        self.ws = self.sandbox / "audits" / "demo"
        self.ws.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.sandbox, ignore_errors=True)

    def _write(self, path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def _write_json(self, path: Path, payload: dict) -> Path:
        return self._write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def _run(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        merged["HOME"] = str(self.sandbox)
        merged.update(env or {})
        return subprocess.run(
            ["python3", str(TOOL), *args],
            cwd=REPO,
            env=merged,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _run_audit_deep_all(self, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        if not shutil.which("bash"):
            raise unittest.SkipTest("bash not on PATH")
        merged = os.environ.copy()
        merged["HOME"] = str(self.sandbox)
        merged["AUDIT_DEEP_DRY_RUN"] = "1"
        merged.update(env or {})
        return subprocess.run(
            ["bash", str(REPO / "tools" / "audit-deep.sh"), "--profile", "all", str(self.ws)],
            cwd=REPO,
            env=merged,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def _load_tool_module(self, suffix: str = "module"):
        import importlib.util

        module_name = f"audit_deep_manifest_{suffix}"
        spec = importlib.util.spec_from_file_location(module_name, TOOL)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _fresh_result_metadata(self, run_id: str = "auditrun-current") -> dict[str, object]:
        return {
            "schema": "auditooor.audit_deep_manifest_freshness_check.v1",
            "workspace": str(self.ws),
            "run_id": run_id,
            "run_start_utc": "2026-05-30T10:00:00Z",
            "run_start_line": 1,
        }

    def _eligible_audit_deep_all_source_row(self, run_id: str = "auditrun-current") -> dict[str, object]:
        return {
            "kind": "audit-deep-all-manifest",
            "path": ".audit_logs/audit_deep_all_manifest.json",
            "fresh": True,
            "completion_source_eligible": True,
            "workspace_matches": True,
            "run_id": run_id,
            "run_id_mismatch": False,
            "run_id_missing": False,
        }

    def _eligible_solidity_source_row(self, run_id: str = "auditrun-current") -> dict[str, object]:
        return {
            "kind": "solidity-deep-audit",
            "path": ".auditooor/solidity-deep-audit/manifest.json",
            "fresh": True,
            "completion_source_eligible": True,
            "workspace_matches": True,
            "schema_matches": True,
            "execution_ok": True,
            "exists": True,
            "run_id": run_id,
            "run_id_mismatch": False,
            "run_id_missing": False,
        }

    def _write_run_start(
        self,
        timestamp: str,
        *,
        workspace: str | None = None,
        run_id: str | None = "auditrun-test",
        max_functions: str | None = "0",
    ) -> Path:
        row = {
            "schema": "auditooor.audit_run_full_manifest.v1",
            "event": "start",
            "workspace": workspace or str(self.ws),
            "timestamp_utc": timestamp,
        }
        if run_id is not None:
            row["run_id"] = run_id
        if max_functions is not None:
            row["max_functions"] = max_functions
        return self._write(
            self.ws / ".auditooor" / "audit_run_full_manifest.jsonl",
            json.dumps(row, sort_keys=True) + "\n",
        )

    def _append_ready_stage_rows(self, manifest: Path, *, run_id: str) -> None:
        rows = [
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "stage-start",
                "run_id": run_id,
                "stage": "mcp-preflight",
                "timestamp_utc": "2026-05-30T10:00:30Z",
            },
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "stage-pass",
                "run_id": run_id,
                "stage": "mcp-preflight",
                "timestamp_utc": "2026-05-30T10:00:40Z",
            },
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "stage-start",
                "run_id": run_id,
                "stage": "deep-freshness",
                "timestamp_utc": "2026-05-30T10:02:00Z",
            },
        ]
        with manifest.open("a", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")

    def _set_mtime(self, path: Path, timestamp: int = 1_000) -> None:
        os.utime(path, (timestamp, timestamp))

    def _write_structured_skip(
        self,
        *,
        reason: str = "no supported deep engine for this workspace",
        timestamp: str = "2026-05-30T10:01:00Z",
        run_id: str | None = "auditrun-test",
    ) -> Path:
        entry = {
            "reason": reason,
            "timestamp_utc": timestamp,
        }
        if run_id is not None:
            entry["run_id"] = run_id
        return self._write_json(
            self.ws / ".auditooor" / "stage_skips.json",
            {"NO_AUDIT_DEEP_REASON": entry},
        )

    def _write_solidity_step_artifact(
        self,
        *,
        tool: str = "halmos-runner",
        status: str = "ok",
        returncode: int = 0,
        run_id: str = "auditrun-test",
        generated_at: str = "2026-05-30T10:01:30Z",
    ) -> Path:
        step = self.ws / ".auditooor" / "solidity-deep-audit" / f"{tool}.json"
        self._write_json(
            step,
            {
                "schema": "auditooor.solidity_deep_audit.step.v1",
                "tool": tool,
                "status": status,
                "returncode": returncode,
                "run_id": run_id,
                "generated_at": generated_at,
            },
        )
        return step

    def _write_solidity_runner_artifact(
        self,
        *,
        engine: str = "halmos",
        status: str = "ok",
        engine_rc: int | None = 0,
        created_at: str = "2026-05-30T10:01:45Z",
        run_id: str = "auditrun-test",
        workspace: str | None = None,
        reason: str = "completed",
        stdout: str = "",
        stderr: str = "",
    ) -> Path:
        artifact = self.ws / ".auditooor" / engine / "artifact.json"
        return self._write_json(
            artifact,
            {
                "schema_version": "auditooor.deep_engine_artifact.v1",
                "engine": engine,
                "status": status,
                "reason": reason,
                "engine_rc": engine_rc,
                "created_at": created_at,
                "workspace": workspace if workspace is not None else str(self.ws),
                "run_id": run_id,
                "stdout": stdout,
                "stderr": stderr,
            },
        )

    def _write_valid_solidity_deep_manifest(
        self,
        *,
        run_id: str = "auditrun-test",
        generated_at: str = "2026-05-30T10:01:00Z",
        extra_fields: dict[str, object] | None = None,
    ) -> Path:
        step = self._write_solidity_step_artifact(run_id=run_id)
        self._write_solidity_runner_artifact(run_id=run_id)
        payload: dict[str, object] = {
            "schema": "auditooor.solidity_deep_audit.v1",
            "workspace": str(self.ws),
            "run_id": run_id,
            "generated_at": generated_at,
            "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
        }
        if extra_fields:
            payload.update(extra_fields)
        return self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            payload,
        )

    def _write_strict_solidity_deep_manifest(self, *, run_id: str = "auditrun-test") -> Path:
        return self._write_valid_solidity_deep_manifest(
            run_id=run_id,
            extra_fields={
                "generated_per_function_harness_count": 0,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 0,
                "executed_engine_harness_count": 0,
            },
        )

    def _write_per_function_halmos_manifest(
        self,
        *,
        run_id: str = "auditrun-test",
        generated_at_utc: str = "2026-05-30T10:02:00Z",
        count: int = 2,
        include_harness_path: bool = True,
        advisory_harness: bool = False,
        artifact_run_id: str | None = "auditrun-test",
        artifact_created_at: str = "2026-05-30T10:02:10Z",
        artifact_reason: str = "completed",
        artifact_stdout: str = "halmos completed",
        artifact_status: str = "ok",
        artifact_engine_rc: int | None = 0,
    ) -> Path:
        invocations: list[dict[str, object]] = []
        for index in range(count):
            contract = f"Halmos_Target_{index}"
            harness_path = (
                self.ws
                / "poc-tests"
                / "per_function_invariants"
                / f"{contract}.sol"
            )
            if include_harness_path:
                if advisory_harness:
                    harness_src = f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// Auto-generated by tools/per-function-invariant-gen.py.
// This advisory scaffold is not proof.
contract {contract} {{
    function check_generated_scaffold() public pure {{
        assert(true);
    }}
}}
"""
                else:
                    harness_src = f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Counter {{
    uint256 public value;

    function bump(uint256 amount) external {{
        value += amount;
    }}
}}

contract {contract} {{
    Counter counter;
    bool negative_control_cleanPath;

    function check_counter_monotonic(uint256 amount) public {{
        uint256 beforeValue = counter.value();
        counter.bump(amount);
        uint256 afterValue = counter.value();
        assert(afterValue >= beforeValue);
    }}
}}
"""
                harness_path.parent.mkdir(parents=True, exist_ok=True)
                harness_path.write_text(harness_src, encoding="utf-8")
            artifact = (
                self.ws
                / ".auditooor"
                / "deep-engine-runs"
                / "per-function-halmos"
                / contract
                / "halmos"
                / "artifact.json"
            )
            artifact_payload: dict[str, object] = {
                "schema_version": "auditooor.deep_engine_artifact.v1",
                "engine": "halmos",
                "workspace": str(self.ws),
                "status": artifact_status,
                "reason": artifact_reason,
                "engine_rc": artifact_engine_rc,
                "created_at": artifact_created_at,
                "stdout": artifact_stdout,
                "stderr": "",
            }
            if artifact_run_id is not None:
                artifact_payload["run_id"] = artifact_run_id
            self._write_json(artifact, artifact_payload)
            invocations.append(
                {
                    "index": index,
                    "selector": f"Target.fn{index}",
                    "harness_contract": contract,
                    "status": "ok",
                    "returncode": 0,
                    "artifact": str(artifact),
                    **({"harness_path": str(harness_path)} if include_harness_path else {}),
                }
            )
        return self._write_json(
            self.ws / ".audit_logs" / "solidity_per_function_halmos_manifest.json",
            {
                "schema": "auditooor.solidity_per_function_halmos.v1",
                "workspace": str(self.ws),
                "run_id": run_id,
                "generated_at_utc": generated_at_utc,
                "status": "ok",
                "expected_invocation_count": count,
                "executed_invocation_count": count,
                "ok_invocation_count": count,
                "invocations": invocations,
            },
        )

    def _write_audit_deep_all_manifest(
        self,
        *,
        profile: str = "default",
        status: str = "success",
        exit_code: int = 0,
        run_id: str | None = "auditrun-test",
        timestamp_utc: str = "2026-05-30T10:01:00Z",
        dry_run: bool = False,
        with_log: bool = True,
        with_captured_report: bool = False,
        with_report: bool = True,
        expected_profiles: list[str] | None = None,
    ) -> Path:
        audit_logs = self.ws / ".audit_logs"
        row: dict[str, object] = {
            "profile": profile,
            "status": status,
            "exit_code": exit_code,
        }
        if with_log:
            log = self._write(
                audit_logs / f"audit_deep_all_{profile}.log",
                f"{profile} profile completed\n",
            )
            row["log"] = str(log)
        if with_captured_report:
            report = self._write(
                audit_logs / f"audit_deep_all_{profile}_report.md",
                f"# {profile} profile report\n",
            )
            row["captured_report"] = str(report)
        payload: dict[str, object] = {
            "schema": "auditooor.audit_deep_all.v1",
            "workspace": str(self.ws),
            "timestamp_utc": timestamp_utc,
            "dry_run": dry_run,
            "expected_profiles": expected_profiles or [profile],
            "profiles": [row],
        }
        if with_report:
            all_report = self._write(
                audit_logs / "audit_deep_all_report.md",
                "# audit-deep all-profile report\n",
            )
            payload["report"] = str(all_report)
        if run_id is not None:
            payload["run_id"] = run_id
        return self._write_json(
            audit_logs / "audit_deep_all_manifest.json",
            payload,
        )

    def _write_rust_source_graph_manifest(
        self,
        *,
        run_id: str = "auditrun-test",
        timestamp_utc: str = "2026-05-30T10:01:00Z",
        crate_count: int = 2,
    ) -> Path:
        return self._write_json(
            self.ws / ".auditooor" / "rust_source_graph.json",
            {
                "_meta": {
                    "schema_version": "auditooor.rust_source_graph.v1",
                    "workspace": str(self.ws),
                    "run_id": run_id,
                    "generated_at_utc": timestamp_utc,
                    "crate_count": crate_count,
                },
                "crates": [],
            },
        )

    def _write_rust_cross_crate_graph_manifest(
        self,
        *,
        run_id: str = "auditrun-test",
        timestamp_utc: str = "2026-05-30T10:01:00Z",
        crate_count: int = 2,
        edge_count: int = 1,
    ) -> Path:
        return self._write_json(
            self.ws / ".auditooor" / "rust_cross_crate_graph.json",
            {
                "_meta": {
                    "schema_version": "auditooor.rust_cross_crate_graph.v1",
                    "workspace": str(self.ws),
                    "run_id": run_id,
                    "generated_at_utc": timestamp_utc,
                    "crate_count": crate_count,
                    "edge_count": edge_count,
                },
                "edges": [],
            },
        )

    def _write_go_dlt_audit_enforcement_manifest(
        self,
        *,
        run_id: str = "auditrun-test",
        timestamp_utc: str = "2026-05-30T10:01:00Z",
        status: str = "pass",
        check_rc: int = 0,
    ) -> Path:
        report = self._write(
            self.ws / ".audit_logs" / "go_dlt_audit_report.md",
            "# go dlt audit report\n",
        )
        return self._write_json(
            self.ws / ".audit_logs" / "go_dlt_audit_enforcement.json",
            {
                "schema": "auditooor.go_dlt_audit_enforcement.v1",
                "workspace": str(self.ws),
                "run_id": run_id,
                "timestamp_utc": timestamp_utc,
                "status": status,
                "audit_completion": {
                    "exists": True,
                    "check_rc": check_rc,
                },
                "audit_deep_report": str(report),
            },
        )

    def _write_solidity_all_harnesses_manifest(
        self,
        *,
        run_id: str = "auditrun-test",
        timestamp_utc: str = "2026-05-30T10:01:00Z",
        engine_status: str = "ok",
        engine_run_id: str | None = "auditrun-test",
        engine_workspace: str | None = None,
        omit_engine: str | None = None,
        aggregate_status: str | None = None,
        harness_artifacts: list[dict[str, object]] | None = None,
        extra_fields: dict[str, object] | None = None,
    ) -> Path:
        slug = "alpha-engine-harness"
        harness_dir = self.ws / ".auditooor" / "solidity-deep-audit" / "by-harness" / slug
        runner_root = self.ws / ".auditooor" / "deep-engine-runs" / "by-harness" / slug
        harness_dir.mkdir(parents=True, exist_ok=True)
        runner_root.mkdir(parents=True, exist_ok=True)

        step_artifacts = harness_artifacts
        if step_artifacts is None:
            step_path = harness_dir / "halmos-runner.json"
            self._write_json(
                step_path,
                {
                    "schema": "auditooor.solidity_deep_audit.step.v1",
                    "tool": "halmos-runner",
                    "status": "ok",
                    "returncode": 0,
                    "run_id": run_id,
                    "generated_at": "2026-05-30T10:01:20Z",
                },
            )
            step_artifacts = [
                {"tool": "halmos-runner", "status": "ok", "artifact": str(step_path)}
            ]

        harness_manifest = self._write_json(
            harness_dir / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": run_id,
                "generated_at": "2026-05-30T10:01:25Z",
                "artifacts": step_artifacts,
            },
        )

        engine_rows = []
        for engine in ("halmos", "echidna", "medusa"):
            if engine == omit_engine:
                continue
            artifact_path = runner_root / engine / "artifact.json"
            self._write_json(
                artifact_path,
                {
                    "schema_version": "auditooor.deep_engine_artifact.v1",
                    "engine": engine,
                    "workspace": engine_workspace if engine_workspace is not None else str(self.ws),
                    "run_id": engine_run_id,
                    "status": engine_status,
                    "engine_rc": 0 if engine_status == "ok" else None,
                    "created_at": "2026-05-30T10:01:30Z",
                    "stdout": "",
                    "stderr": "",
                },
            )
            engine_rows.append(
                {
                    "engine": engine,
                    "artifact": str(artifact_path),
                    "status": engine_status,
                    "engine_rc": 0 if engine_status == "ok" else None,
                    "command": f"{engine} test",
                    "run_id": engine_run_id,
                }
            )

        payload: dict[str, object] = {
                "schema": "auditooor.solidity_deep_all_harnesses.v1",
                "workspace": str(self.ws),
                "run_id": run_id,
                "generated_at_utc": timestamp_utc,
                "status": aggregate_status
                or ("ok" if engine_status == "ok" and omit_engine is None else "blocked"),
                "expected_harness_count": 1,
                "executed_harness_count": 1,
                "harnesses": [
                    {
                        "slug": slug,
                        "root": str(self.ws / "poc-tests" / slug),
                        "status": "ok",
                        "manifest_path": str(harness_manifest),
                        "runner_artifact_root": str(runner_root),
                        "status_counts": {"ok": 5},
                        "engines": engine_rows,
                    }
                ],
        }
        if extra_fields:
            payload.update(extra_fields)
        return self._write_json(
            self.ws / ".audit_logs" / "solidity_deep_all_harnesses_manifest.json",
            payload,
        )

    def test_solidity_manifest_summary_writes_markdown_and_json(self) -> None:
        out_dir = self.ws / ".auditooor" / "solidity-deep-audit"
        manifest = {
            "schema": "auditooor.solidity_deep_audit.v1",
            "workspace": str(self.ws),
            "generated_at": "2026-05-17T00:00:00Z",
            "detection": {"hardhat": True, "foundry": False, "src_solidity": True, "is_solidity_workspace": True},
            "artifacts": [
                {
                    "tool": "workspace-detection",
                    "status": "ok",
                    "artifact": str(out_dir / "workspace-detection.json"),
                },
                {
                    "tool": "hackerman-brief",
                    "status": "ok",
                    "artifact": str(out_dir / "hackerman-brief.json"),
                },
                {
                    "tool": "slither-resilient",
                    "status": "blocked",
                    "artifact": str(out_dir / "slither-resilient.json"),
                },
                {
                    "tool": "universal-fp-runner",
                    "status": "skipped",
                    "artifact": str(out_dir / "universal-fp-runner.json"),
                },
            ],
        }
        self._write_json(out_dir / "manifest.json", manifest)
        self._write_json(
            out_dir / "workspace-detection.json",
            {
                "schema": "auditooor.solidity_deep_audit.step.v1",
                "tool": "workspace-detection",
                "status": "ok",
                "reason": "marker found",
                "returncode": 0,
                "stdout_log": str(out_dir / "workspace-detection.stdout.log"),
                "stderr_log": str(out_dir / "workspace-detection.stderr.log"),
            },
        )
        self._write_json(
            out_dir / "hackerman-brief.json",
            {
                "schema": "auditooor.solidity_deep_audit.step.v1",
                "tool": "hackerman-brief",
                "status": "ok",
                "reason": "completed",
                "returncode": 0,
                "stdout_log": str(out_dir / "hackerman-brief.stdout.log"),
                "stderr_log": str(out_dir / "hackerman-brief.stderr.log"),
            },
        )
        self._write_json(
            out_dir / "slither-resilient.json",
            {
                "schema": "auditooor.solidity_deep_audit.step.v1",
                "tool": "slither-resilient",
                "status": "blocked",
                "reason": "slither not found on PATH",
                "returncode": 127,
                "stdout_log": str(out_dir / "slither-resilient.stdout.log"),
                "stderr_log": str(out_dir / "slither-resilient.stderr.log"),
            },
        )
        self._write_json(
            out_dir / "universal-fp-runner.json",
            {
                "schema": "auditooor.solidity_deep_audit.step.v1",
                "tool": "universal-fp-runner",
                "status": "skipped",
                "reason": "not enabled",
                "returncode": None,
                "stdout_log": str(out_dir / "universal-fp-runner.stdout.log"),
                "stderr_log": str(out_dir / "universal-fp-runner.stderr.log"),
            },
        )
        self._write(self.ws / ".auditooor" / "hacker_brief.md", "# brief\n")
        self._write_json(self.ws / ".auditooor" / "hacker_brief.md.json", {"schema": "auditooor.hacker_brief.v1"})
        self._write_json(self.ws / ".auditooor" / "hacker_brief.hackerman.json", {"schema": "auditooor.hackerman_record.v1"})

        proc = self._run("--workspace", str(self.ws), "--json")
        self.assertEqual(
            proc.returncode,
            0,
            f"tool failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        payload = json.loads((self.ws / ".audit_logs" / "audit_deep_manifest_report.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.audit_deep_manifest_summary.v1")
        self.assertIn("solidity-deep-audit", [source["kind"] for source in payload["sources"]])
        solidity = next(source for source in payload["sources"] if source["kind"] == "solidity-deep-audit")
        self.assertEqual(solidity["counts"]["ran"], 2)
        self.assertEqual(solidity["counts"]["failed"], 1)
        self.assertEqual(solidity["counts"]["skipped"], 1)
        tools = [row["tool"] for row in solidity["rows"]]
        self.assertEqual(tools, ["workspace-detection", "hackerman-brief", "slither-resilient", "universal-fp-runner"])
        self.assertIn("hacker-brief", payload["bridge_outputs"])
        hacker_brief = payload["bridge_outputs"]["hacker-brief"]
        self.assertTrue(any(entry["status"] == "present" for entry in hacker_brief))
        self.assertIn("brain-prime", payload["bridge_outputs"])
        self.assertTrue(any(entry["status"] == "missing" for entry in payload["bridge_outputs"]["brain-prime"]))
        self.assertIn("hackerman-novel-vectors", payload["bridge_outputs"])
        self.assertTrue(
            any(
                entry["path"] == ".auditooor/novel_vectors.jsonl"
                for entry in payload["bridge_outputs"]["hackerman-novel-vectors"]
            )
        )

    def test_non_solidity_summary_and_make_wrapper(self) -> None:
        audit_logs = self.ws / ".audit_logs"
        self._write(
            audit_logs / "audit_deep_report.md",
            textwrap.dedent(
                """
                # audit-deep report

                ## Summary

                ### Execution Truth

                | tool | state | detail |
                |---|---|---|
                | workspace-detection | planned | no Solidity workspace markers found |
                | hackerman-brief | executed | completed |
                | slither-resilient | blocked | slither not found on PATH |

                - ran: hackerman-brief
                - skipped: workspace-detection
                - failed: slither-resilient

                ## Pointers

                - per-run log: `.audit_logs/audit_deep_20260517T000000Z.md`
                - canonical latest: `.audit_logs/audit_deep_report.md`
                - symbolic per-run manifest dir: `.audit_logs/symbolic_runs/<timestamp>/manifest.json`
                - fuzz per-run manifest dir: `.audit_logs/fuzz_runs/<timestamp>/manifest.json`
                - invariant ledger manifest: `.audit_logs/invariant_ledger_manifest.json`
                """
            ).strip()
            + "\n",
        )
        self._write_json(
            audit_logs / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "timestamp_utc": "2026-05-17T00:00:00Z",
                "dry_run": True,
                "budget_seconds": 1800,
                "report": str(audit_logs / "audit_deep_all_report.md"),
                "typed_candidate_promotion": str(audit_logs / "typed_candidate_promotions.json"),
                "cross_lane_correlations": str(audit_logs / "cross_lane_correlations.json"),
                "deep_counterexample_collection": str(self.ws / "deep_counterexamples" / "collection_manifest.json"),
                "deep_counterexample_queue": str(self.ws / "deep_counterexamples" / "execution_queue.json"),
                "profiles": [
                    {"profile": "default", "status": "success", "exit_code": 0, "log": str(audit_logs / "audit_deep_all_default.log"), "captured_report": str(audit_logs / "audit_deep_all_default_report.md")},
                    {"profile": "math", "status": "skipped_budget", "exit_code": 0, "log": None, "captured_report": None},
                ],
            },
        )
        self._write_json(audit_logs / "cross_lane_correlations.json", {"schema": "auditooor.cross_lane_correlations.v1"})
        self._write(audit_logs / "cross_lane_correlations.md", "# cross-lane\n")
        self._write_json(audit_logs / "typed_candidate_promotions.json", {"schema": "auditooor.typed_candidate_promotions.v1"})
        self._write(audit_logs / "typed_candidate_promotions.md", "# typed\n")
        self._write_json(self.ws / "deep_counterexamples" / "collection_manifest.json", {"schema": "auditooor.deep_counterexample_collection.v1"})
        self._write_json(self.ws / "deep_counterexamples" / "execution_queue.json", {"schema": "auditooor.deep_counterexample_queue.v1"})
        self._write(self.ws / "deep_counterexamples" / "execution_queue.md", "# queue\n")
        self._write_json(self.ws / ".auditooor" / "brain_prime_receipt.json", {"schema": "auditooor.brain_prime_receipt.v1"})
        self._write_json(self.ws / ".auditooor" / "high_impact_execution_bridge.json", {"schema": "auditooor.high_impact_execution_bridge.v1"})
        self._write(self.ws / ".auditooor" / "high_impact_execution_bridge.md", "# bridge\n")

        proc = subprocess.run(
            ["make", "audit-deep-manifest", f"WS={self.ws}"],
            cwd=REPO,
            env={**os.environ, "HOME": str(self.sandbox)},
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"make audit-deep-manifest failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        report_path = self.ws / ".audit_logs" / "audit_deep_manifest_report.md"
        self.assertTrue(report_path.is_file())
        text = report_path.read_text(encoding="utf-8")
        self.assertIn("audit-deep manifest summary", text)
        self.assertIn("audit-deep-all-manifest", text)
        self.assertIn("cross_lane_correlations.json", text)
        self.assertIn("typed_candidate_promotions.json", text)
        self.assertIn("deep_counterexamples/collection_manifest.json", text)
        self.assertIn("high-impact-execution-bridge", text)

    def test_check_fresh_accepts_current_run_solidity_manifest(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest()

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.audit_deep_manifest_freshness_check.v1")
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        self.assertEqual(payload["fresh_manifest_paths"], [".auditooor/solidity-deep-audit/manifest.json"])
        manifest_row = payload["source_manifests"][0]
        self.assertTrue(manifest_row["execution_ok"])
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["runner_artifact_check_count"], 1)
        self.assertEqual(detail["runner_artifact_error_count"], 0)
        self.assertEqual(detail["runner_artifact_errors"], [])

    def test_check_fresh_non_strict_reports_partial_invariant_denominator_without_failing(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest(
            extra_fields={"generated_per_function_harness_count": 2},
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        self.assertTrue(manifest_row["execution_ok"])
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["generated_per_function_harness_count"], 2)
        self.assertIsNone(detail["executed_generated_harness_count"])
        self.assertEqual(detail["invariant_denominator_check_count"], 2)
        self.assertEqual(detail["invariant_denominator_error_count"], 0)
        generated_check = next(
            row
            for row in detail["invariant_denominator_checks"]
            if row["denominator_field"] == "generated_per_function_harness_count"
        )
        self.assertEqual(generated_check["denominator_count"], 2)
        self.assertIsNone(generated_check["executed_count"])
        self.assertFalse(generated_check["strict_required"])

    def test_check_fresh_strict_rejects_generated_harness_denominator_above_executed(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest(
            extra_fields={
                "generated_per_function_harness_count": 2,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 0,
                "executed_engine_harness_count": 0,
            },
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][0]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity deep manifest invariant harness denominator exceeds executed counts",
        )
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["invariant_denominator_error_count"], 1)
        self.assertEqual(
            detail["invariant_denominator_errors"][0]["denominator_field"],
            "generated_per_function_harness_count",
        )
        self.assertEqual(detail["invariant_denominator_errors"][0]["denominator_count"], 2)
        self.assertEqual(detail["invariant_denominator_errors"][0]["executed_count"], 0)
        self.assertEqual(
            detail["invariant_denominator_errors"][0]["reason"],
            "denominator_exceeds_executed",
        )

    def test_check_fresh_strict_rejects_solidity_manifest_missing_denominator_fields(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest()

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][0]["execution_detail"]
        reasons = {row["reason"] for row in detail["invariant_denominator_errors"]}
        self.assertEqual(reasons, {"denominator_count_missing"})

    def test_check_fresh_strict_rejects_available_engine_harness_denominator_above_executed(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest(
            extra_fields={
                "generated_per_function_harness_count": 0,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 2,
                "executed_engine_harness_count": 1,
            },
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        detail = payload["source_manifests"][0]["execution_detail"]
        self.assertEqual(detail["invariant_denominator_error_count"], 1)
        self.assertEqual(
            detail["invariant_denominator_errors"][0]["denominator_field"],
            "available_engine_harness_count",
        )
        self.assertEqual(detail["invariant_denominator_errors"][0]["denominator_count"], 2)
        self.assertEqual(detail["invariant_denominator_errors"][0]["executed_count"], 1)

    def test_check_fresh_strict_accepts_full_invariant_denominator_match(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest(
            extra_fields={
                "generated_per_function_harness_count": 2,
                "executed_generated_harness_count": 2,
                "available_engine_harness_count": 2,
                "executed_engine_harness_count": 2,
            },
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        detail = payload["source_manifests"][0]["execution_detail"]
        self.assertEqual(detail["invariant_denominator_error_count"], 0)
        self.assertEqual(detail["generated_per_function_harness_count"], 2)
        self.assertEqual(detail["executed_generated_harness_count"], 2)
        self.assertEqual(detail["available_engine_harness_count"], 2)
        self.assertEqual(detail["executed_engine_harness_count"], 2)

    def test_check_fresh_strict_accepts_per_function_halmos_sidecar_denominator_match(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest(
            extra_fields={
                "generated_per_function_harness_count": 2,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 0,
                "executed_engine_harness_count": 0,
            },
        )
        self._write_per_function_halmos_manifest(count=2)

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][0]["execution_detail"]
        self.assertEqual(detail["generated_per_function_harness_count"], 2)
        self.assertEqual(detail["executed_generated_harness_count"], 2)
        self.assertEqual(detail["invariant_denominator_error_count"], 0)
        self.assertEqual(detail["per_function_halmos_manifest"]["errors"], [])
        self.assertTrue(detail["per_function_halmos_manifest"]["all_invocation_artifacts_valid"])
        self.assertTrue(detail["per_function_halmos_execution_ok"])
        self.assertTrue(detail["per_function_halmos_proof_ok"])
        self.assertEqual(
            detail["per_function_halmos_proof_gate"]["verdict"],
            "pass-engine-harness-proof",
        )

    def test_check_fresh_rejects_no_target_runner_without_per_function_proof(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_solidity_step_artifact()
        self._write_solidity_runner_artifact(
            reason="no-target: halmos found no check_ or invariant_ symbolic tests",
            stdout="ERROR No tests with --match-contract '' --match-test '^(check|invariant)_.*'",
        )
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [
                    {
                        "tool": "halmos-runner",
                        "status": "ok",
                        "artifact": str(
                            self.ws
                            / ".auditooor"
                            / "solidity-deep-audit"
                            / "halmos-runner.json"
                        ),
                    }
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][0]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity deep manifest has no load-bearing proof artifact; "
            "per-function Halmos requires engine-harness-proof-check pass",
        )
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["runner_artifact_no_target_count"], 1)
        self.assertEqual(detail["valid_load_bearing_proof_engine_count"], 0)

    def test_check_fresh_accepts_no_target_runner_when_per_function_halmos_artifacts_cover_run(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest(
            extra_fields={
                "generated_per_function_harness_count": 2,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 0,
                "executed_engine_harness_count": 0,
            },
        )
        self._write_solidity_runner_artifact(
            reason="no-target: halmos found no check_ or invariant_ symbolic tests",
            stdout="No tests with --match-test invariant",
        )
        self._write_per_function_halmos_manifest(count=2)

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][0]["execution_detail"]
        self.assertEqual(detail["runner_artifact_no_target_count"], 1)
        self.assertEqual(detail["valid_load_bearing_proof_engine_count"], 0)
        self.assertTrue(detail["per_function_halmos_execution_ok"])
        self.assertTrue(detail["per_function_halmos_proof_ok"])

    def test_check_fresh_rejects_per_function_halmos_without_harness_paths(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest(
            extra_fields={
                "generated_per_function_harness_count": 2,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 0,
                "executed_engine_harness_count": 0,
            },
        )
        self._write_solidity_runner_artifact(
            reason="no-target: halmos found no check_ or invariant_ symbolic tests",
            stdout="No tests with --match-test invariant",
        )
        self._write_per_function_halmos_manifest(count=2, include_harness_path=False)

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][0]["execution_detail"]
        self.assertTrue(detail["per_function_halmos_execution_ok"])
        self.assertFalse(detail["per_function_halmos_proof_ok"])
        self.assertEqual(
            detail["per_function_halmos_proof_gate"]["verdict"],
            "fail-no-proven-harness",
        )

    def test_check_fresh_rejects_advisory_per_function_halmos_harnesses(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest(
            extra_fields={
                "generated_per_function_harness_count": 2,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 0,
                "executed_engine_harness_count": 0,
            },
        )
        self._write_solidity_runner_artifact(
            reason="no-target: halmos found no check_ or invariant_ symbolic tests",
            stdout="No tests with --match-test invariant",
        )
        self._write_per_function_halmos_manifest(count=2, advisory_harness=True)

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][0]["execution_detail"]
        self.assertTrue(detail["per_function_halmos_execution_ok"])
        self.assertFalse(detail["per_function_halmos_proof_ok"])
        self.assertEqual(
            detail["per_function_halmos_proof_gate"]["verdict"],
            "fail-no-proven-harness",
        )
        self.assertTrue(detail["per_function_halmos_proof_gate"].get("advisory_only"))

    def test_check_fresh_rejects_per_function_halmos_sidecar_with_stale_invocation_artifact(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest(
            extra_fields={
                "generated_per_function_harness_count": 2,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 0,
                "executed_engine_harness_count": 0,
            },
        )
        self._write_per_function_halmos_manifest(
            count=2,
            artifact_created_at="2026-05-30T09:59:59Z",
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][0]["execution_detail"]
        sidecar = detail["per_function_halmos_manifest"]
        self.assertIn("invocation_artifact_errors", sidecar["errors"])
        self.assertEqual(sidecar["invocation_artifact_error_count"], 2)
        reasons = {
            reason
            for error in sidecar["invocation_artifact_errors"]
            for reason in error["reasons"]
        }
        self.assertIn("artifact_stale_or_missing_timestamp", reasons)

    def test_check_fresh_strict_invariant_denominator_rejects_each_denominator_exceeding_executed(self) -> None:
        cases = (
            (
                "generated_per_function_harness_count",
                "executed_generated_harness_count",
                "generated per-function harnesses",
            ),
            (
                "available_engine_harness_count",
                "executed_engine_harness_count",
                "available engine harness roots",
            ),
        )
        for denominator_field, executed_field, label in cases:
            with self.subTest(denominator_field=denominator_field):
                self._write_run_start("2026-05-30T10:00:00Z")
                self._write_valid_solidity_deep_manifest(
                    extra_fields={
                        "generated_per_function_harness_count": 0,
                        "executed_generated_harness_count": 0,
                        "available_engine_harness_count": 0,
                        "executed_engine_harness_count": 0,
                        denominator_field: 3,
                        executed_field: 2,
                    },
                )
                proc = self._run(
                    "--workspace",
                    str(self.ws),
                    "--check-fresh",
                    "--require-full-invariant-denominator",
                    "--json",
                )
                self.assertEqual(proc.returncode, 1)
                payload = json.loads(proc.stdout)
                self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
                manifest_row = payload["source_manifests"][0]
                self.assertFalse(manifest_row["execution_ok"])
                self.assertEqual(
                    manifest_row["execution_reason"],
                    "solidity deep manifest invariant harness denominator exceeds executed counts",
                )
                detail = manifest_row["execution_detail"]
                self.assertEqual(detail["invariant_denominator_error_count"], 1)
                error = detail["invariant_denominator_errors"][0]
                self.assertEqual(error["label"], label)
                self.assertEqual(error["denominator_field"], denominator_field)
                self.assertEqual(error["denominator_count"], 3)
                self.assertEqual(error["executed_field"], executed_field)
                self.assertEqual(error["executed_count"], 2)
                self.assertEqual(error["reason"], "denominator_exceeds_executed")
                shutil.rmtree(self.ws, ignore_errors=True)
                self.ws.mkdir(parents=True, exist_ok=True)

    def test_check_fresh_strict_invariant_denominator_accepts_when_executed_meets_denominator(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest(
            extra_fields={
                "generated_per_function_harness_count": 3,
                "executed_generated_harness_count": 3,
                "available_engine_harness_count": 4,
                "executed_engine_harness_count": 4,
            },
        )
        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        detail = payload["source_manifests"][0]["execution_detail"]
        self.assertEqual(detail["invariant_denominator_error_count"], 0)
        checks = {row["denominator_field"]: row for row in detail["invariant_denominator_checks"]}
        generated = checks["generated_per_function_harness_count"]
        self.assertEqual(generated["denominator_count"], 3)
        self.assertEqual(generated["executed_count"], 3)
        available = checks["available_engine_harness_count"]
        self.assertEqual(available["denominator_count"], 4)
        self.assertEqual(available["executed_count"], 4)

    def test_check_fresh_rejects_start_row_without_run_id(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id=None)
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok"}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-current-run-missing-run-id")
        self.assertEqual(payload["run_start_utc"], "2026-05-30T10:00:00Z")

    def test_check_fresh_run_id_selects_matching_start_not_latest(self) -> None:
        manifest = self.ws / ".auditooor" / "audit_run_full_manifest.jsonl"
        rows = [
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "start",
                "max_functions": "0",
                "workspace": str(self.ws),
                "run_id": "auditrun-a",
                "timestamp_utc": "2026-05-30T10:00:00Z",
            },
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "start",
                "max_functions": "0",
                "workspace": str(self.ws),
                "run_id": "auditrun-b",
                "timestamp_utc": "2026-05-30T10:05:00Z",
            },
        ]
        self._write(
            manifest,
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        )
        self._append_ready_stage_rows(manifest, run_id="auditrun-a")
        step = self._write_solidity_step_artifact(run_id="auditrun-a")
        self._write_solidity_runner_artifact(run_id="auditrun-a")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-a",
                "generated_at": "2026-05-30T10:01:00Z",
                "generated_per_function_harness_count": 0,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 0,
                "executed_engine_harness_count": 0,
                "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
            },
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-a",
            "--append-audit-run-success-events",
            "--json",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        self.assertEqual(payload["run_id"], "auditrun-a")
        self.assertEqual(payload["run_start_utc"], "2026-05-30T10:00:00Z")
        self.assertEqual(payload["run_start_line"], 1)
        written = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(written[-2]["event"], "stage-pass")
        self.assertEqual(written[-2]["run_id"], "auditrun-a")
        self.assertEqual(written[-1]["event"], "complete")
        self.assertEqual(written[-1]["run_id"], "auditrun-a")

    def test_check_fresh_accepts_non_solidity_all_manifest_as_completion_source(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-test")
        self._write_audit_deep_all_manifest(run_id="auditrun-test")

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        self.assertIn(".audit_logs/audit_deep_all_manifest.json", payload["fresh_manifest_paths"])
        row = payload["source_manifests"][1]
        self.assertTrue(row["completion_source_eligible"])
        self.assertTrue(row["execution_ok"])

    def test_check_fresh_accepts_current_run_rust_graph_manifests(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-rust")
        self._write_rust_source_graph_manifest(run_id="auditrun-rust")
        self._write_rust_cross_crate_graph_manifest(run_id="auditrun-rust")

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        self.assertEqual(
            set(payload["fresh_manifest_paths"]),
            {
                ".auditooor/rust_source_graph.json",
                ".auditooor/rust_cross_crate_graph.json",
            },
        )
        by_kind = {row["kind"]: row for row in payload["source_manifests"]}
        self.assertEqual(by_kind["rust-source-graph"]["schema"], "auditooor.rust_source_graph.v1")
        self.assertEqual(by_kind["rust-source-graph"]["timestamp_field"], "_meta.generated_at_utc")
        self.assertTrue(by_kind["rust-cross-crate-graph"]["execution_ok"])

    def test_check_fresh_accepts_current_run_go_dlt_enforcement_manifest(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-go")
        self._write_go_dlt_audit_enforcement_manifest(run_id="auditrun-go")

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        self.assertEqual(payload["fresh_manifest_paths"], [".audit_logs/go_dlt_audit_enforcement.json"])

    def test_check_fresh_ignores_advisory_rust_graph_without_run_id_when_go_manifest_is_fresh(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-mixed")
        self._write_audit_deep_all_manifest(run_id="auditrun-mixed")
        self._write_go_dlt_audit_enforcement_manifest(run_id="auditrun-mixed")
        self._write_rust_source_graph_manifest(run_id="auditrun-mixed")
        rust_graph = self.ws / ".auditooor" / "rust_source_graph.json"
        payload = json.loads(rust_graph.read_text(encoding="utf-8"))
        payload["_meta"].pop("run_id")
        rust_graph.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        self.assertEqual(
            payload["fresh_manifest_paths"],
            [
                ".audit_logs/audit_deep_all_manifest.json",
                ".audit_logs/go_dlt_audit_enforcement.json",
            ],
        )
        by_kind = {row["kind"]: row for row in payload["source_manifests"]}
        self.assertFalse(by_kind["rust-source-graph"]["completion_source_eligible"])
        self.assertEqual(payload["blocking_manifest_paths"], [])

    def test_audit_deep_all_defaults_to_unbounded_budget_for_run_bound_execution(self) -> None:
        proc = self._run_audit_deep_all(
            {"AUDITOOOR_AUDIT_RUN_FULL_ID": "auditrun-current"}
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(
            (self.ws / ".audit_logs" / "audit_deep_all_manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload["run_id"], "auditrun-current")
        self.assertEqual(payload["budget_seconds"], 0)
        self.assertTrue(
            all(row.get("status") != "skipped_budget" for row in payload.get("profiles", []))
        )

    def test_audit_deep_all_honors_explicit_budget_for_run_bound_execution(self) -> None:
        proc = self._run_audit_deep_all(
            {
                "AUDITOOOR_AUDIT_RUN_FULL_ID": "auditrun-current",
                "AUDIT_DEEP_ALL_MAX_SECONDS": "777",
            }
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(
            (self.ws / ".audit_logs" / "audit_deep_all_manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload["run_id"], "auditrun-current")
        self.assertEqual(payload["budget_seconds"], 777)

    def test_check_fresh_accepts_mixed_engine_manifests_from_same_run(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-test")
        self._write_valid_solidity_deep_manifest(run_id="auditrun-test")
        self._write_audit_deep_all_manifest(run_id="auditrun-test")

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        self.assertEqual(
            set(payload["fresh_manifest_paths"]),
            {
                ".auditooor/solidity-deep-audit/manifest.json",
                ".audit_logs/audit_deep_all_manifest.json",
            },
        )

    def test_check_fresh_accepts_solidity_all_harnesses_manifest(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_solidity_all_harnesses_manifest()

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        self.assertEqual(
            payload["fresh_manifest_paths"],
            [".audit_logs/solidity_deep_all_harnesses_manifest.json"],
        )
        manifest_row = payload["source_manifests"][2]
        self.assertEqual(manifest_row["kind"], "solidity-deep-all-harnesses")
        self.assertTrue(manifest_row["execution_ok"])
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["ok_harness_count"], 1)
        self.assertEqual(detail["ok_engine_count"], 3)
        self.assertEqual(detail["engine_artifact_error_count"], 0)

    def test_check_fresh_strict_rejects_all_harness_manifest_missing_denominator_fields(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_solidity_all_harnesses_manifest()

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][2]
        self.assertFalse(manifest_row["execution_ok"])
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["invariant_denominator_error_count"], 2)
        self.assertEqual(
            {row["reason"] for row in detail["invariant_denominator_errors"]},
            {"denominator_count_missing"},
        )

    def test_check_fresh_strict_accepts_all_harness_manifest_with_full_denominator(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_solidity_all_harnesses_manifest(
            extra_fields={
                "generated_per_function_harness_count": 0,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 1,
                "executed_engine_harness_count": 1,
            },
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][2]
        self.assertTrue(manifest_row["execution_ok"])
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["invariant_denominator_error_count"], 0)

    def test_check_fresh_rejects_all_harness_manifest_with_engine_failure(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        path = self._write_solidity_all_harnesses_manifest(
            extra_fields={
                "generated_per_function_harness_count": 0,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 1,
                "executed_engine_harness_count": 1,
            },
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["harnesses"][0]["engines"][2]["status"] = "engine-error"
        payload["harnesses"][0]["engines"][2]["engine_rc"] = 1
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        medusa_artifact = Path(payload["harnesses"][0]["engines"][2]["artifact"])
        medusa_payload = json.loads(medusa_artifact.read_text(encoding="utf-8"))
        medusa_payload["status"] = "engine-error"
        medusa_payload["engine_rc"] = 1
        medusa_artifact.write_text(
            json.dumps(medusa_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        manifest_row = json.loads(proc.stdout)["source_manifests"][2]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity all-harness manifest contains non-success engine rows",
        )
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["engine_status_error_count"], 1)
        self.assertEqual(detail["engine_artifact_error_count"], 1)
        self.assertEqual(detail["advisory_engine_status_error_count"], 0)
        self.assertEqual(detail["advisory_engine_artifact_error_count"], 0)

    def test_check_fresh_rejects_solidity_all_harnesses_manifest_with_missing_engine(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_solidity_all_harnesses_manifest(
            omit_engine="medusa",
            aggregate_status="ok",
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][2]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity all-harness manifest is missing required engine rows",
        )
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["missing_engine_errors"][0]["missing_engines"], ["medusa"])

    def test_check_fresh_rejects_solidity_all_harnesses_manifest_with_blocked_top_level_status(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_solidity_all_harnesses_manifest(
            aggregate_status="blocked",
            extra_fields={"blocked_harness_count": 0},
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][2]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity all-harness manifest status is not successful",
        )
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["status"], "blocked")

    def test_check_fresh_rejects_solidity_all_harnesses_manifest_with_blocked_harness_count(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_solidity_all_harnesses_manifest(
            aggregate_status="ok",
            extra_fields={"blocked_harness_count": 1, "status_counts": {"ok": 1, "blocked": 1}},
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][2]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity all-harness manifest contains blocked harnesses",
        )
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["blocked_harness_count"], 1)
        self.assertEqual(detail["status_counts"], {"ok": 1, "blocked": 1})

    def test_check_fresh_rejects_solidity_all_harnesses_manifest_with_tool_unavailable(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_solidity_all_harnesses_manifest(
            engine_status="tool-unavailable",
            aggregate_status="ok",
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][2]
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity all-harness manifest contains non-success engine rows",
        )
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["engine_status_error_count"], 3)

    def test_check_fresh_rejects_solidity_all_harnesses_manifest_with_engine_workspace_mismatch(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_solidity_all_harnesses_manifest(
            engine_workspace=str(self.sandbox / "other-workspace"),
            aggregate_status="ok",
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][2]
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity all-harness manifest has invalid engine artifacts",
        )
        detail = manifest_row["execution_detail"]
        reasons = {
            reason
            for error in detail["engine_artifact_errors"]
            for reason in error.get("reasons", [])
        }
        self.assertIn("workspace_mismatch", reasons)

    def test_check_fresh_rejects_solidity_all_harnesses_manifest_with_engine_run_id_mismatch(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_solidity_all_harnesses_manifest(
            engine_run_id="auditrun-other",
            aggregate_status="ok",
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][2]
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity all-harness manifest has invalid engine artifacts",
        )
        detail = manifest_row["execution_detail"]
        reasons = {
            reason
            for error in detail["engine_artifact_errors"]
            for reason in error.get("reasons", [])
        }
        self.assertIn("run_id_mismatch", reasons)

    def test_check_fresh_rejects_solidity_all_harnesses_manifest_with_empty_harness_artifacts(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_solidity_all_harnesses_manifest(
            aggregate_status="ok",
            harness_artifacts=[],
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][2]
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity all-harness manifest has invalid per-harness step artifacts",
        )
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["harness_step_errors"][0]["reason"], "no_artifact_executions")

    def test_check_fresh_reports_non_solidity_all_manifest_with_existing_captured_report(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_audit_deep_all_manifest(with_log=False, with_captured_report=True)

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        detail = payload["source_manifests"][1]["execution_detail"]
        self.assertEqual(detail["backed_profile_count"], 1)

    def test_check_fresh_rejects_non_solidity_all_manifest_with_invalid_top_level_report_path(self) -> None:
        cases = []

        cases.append(("missing", lambda: self._write_audit_deep_all_manifest(with_report=False), "missing_report_path"))

        def stale_case() -> Path:
            manifest = self._write_audit_deep_all_manifest()
            self._set_mtime(self.ws / ".audit_logs" / "audit_deep_all_report.md")
            return manifest

        cases.append(("stale", stale_case, "stale"))

        def outside_case() -> Path:
            manifest = self._write_audit_deep_all_manifest()
            outside_report = self._write(self.sandbox / "outside-all-report.md", "outside\n")
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["report"] = str(outside_report)
            self._write_json(manifest, payload)
            return manifest

        cases.append(("outside", outside_case, "outside_workspace"))

        def directory_case() -> Path:
            manifest = self._write_audit_deep_all_manifest()
            report_dir = self.ws / ".audit_logs" / "all-report-dir"
            report_dir.mkdir(parents=True, exist_ok=True)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["report"] = str(report_dir)
            self._write_json(manifest, payload)
            return manifest

        cases.append(("directory", directory_case, "not_regular_file"))

        for label, write_case, expected_error in cases:
            with self.subTest(label=label):
                shutil.rmtree(self.ws, ignore_errors=True)
                self.ws.mkdir(parents=True, exist_ok=True)
                self._write_run_start("2026-05-30T10:00:00Z")
                write_case()

                proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
                self.assertEqual(proc.returncode, 1)
                payload = json.loads(proc.stdout)
                self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
                manifest_row = payload["source_manifests"][1]
                self.assertFalse(manifest_row["execution_ok"])
                self.assertEqual(
                    manifest_row["execution_reason"],
                    "audit-deep-all manifest has invalid top-level report path",
                )
                detail = manifest_row["execution_detail"]
                self.assertFalse(detail["report_evidence_ok"])
                self.assertEqual(detail["report_evidence"]["error"], expected_error)

    def test_check_fresh_rejects_non_solidity_all_manifest_success_without_backed_profile_evidence(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_audit_deep_all_manifest(with_log=False, with_captured_report=False)

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][1]
        detail = manifest_row["execution_detail"]
        self.assertEqual(
            manifest_row["execution_reason"],
            "audit-deep-all manifest has successful profiles without backed evidence",
        )
        self.assertEqual(detail["profile_evidence_error_count"], 1)
        self.assertEqual(detail["profile_evidence_errors"][0]["profile"], "default")

    def test_check_fresh_rejects_non_solidity_all_manifest_with_missing_profile_log_path(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        missing_log = self.ws / ".audit_logs" / "missing.log"
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [
                    {
                        "profile": "default",
                        "status": "success",
                        "exit_code": 0,
                        "log": str(missing_log),
                    }
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][1]["execution_detail"]
        self.assertEqual(detail["profile_evidence_error_count"], 1)
        self.assertEqual(detail["profile_evidence_errors"][0]["checked_paths"][0]["error"], "missing")

    def test_check_fresh_rejects_non_solidity_all_manifest_with_stale_profile_evidence(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        log = self._write(self.ws / ".audit_logs" / "audit_deep_all_default.log", "old\n")
        self._set_mtime(log)
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [
                    {
                        "profile": "default",
                        "status": "success",
                        "exit_code": 0,
                        "log": str(log),
                    }
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][1]["execution_detail"]
        self.assertEqual(detail["profile_evidence_error_count"], 1)
        self.assertEqual(detail["profile_evidence_errors"][0]["checked_paths"][0]["error"], "stale")

    def test_check_fresh_rejects_non_solidity_all_manifest_with_outside_profile_evidence(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        outside_log = self._write(self.sandbox / "outside-audit-deep.log", "fresh but unrelated\n")
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [
                    {
                        "profile": "default",
                        "status": "success",
                        "exit_code": 0,
                        "log": str(outside_log),
                    }
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][1]["execution_detail"]
        self.assertEqual(detail["profile_evidence_error_count"], 1)
        self.assertEqual(detail["profile_evidence_errors"][0]["checked_paths"][0]["error"], "outside_workspace")

    def test_check_fresh_rejects_non_solidity_all_manifest_with_directory_profile_evidence(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        log_dir = self.ws / ".audit_logs" / "profile-log-dir"
        log_dir.mkdir(parents=True, exist_ok=True)
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [
                    {
                        "profile": "default",
                        "status": "success",
                        "exit_code": 0,
                        "log": str(log_dir),
                    }
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][1]["execution_detail"]
        self.assertEqual(detail["profile_evidence_error_count"], 1)
        self.assertEqual(detail["profile_evidence_errors"][0]["checked_paths"][0]["error"], "not_regular_file")

    def test_check_fresh_rejects_all_manifest_missing_expected_profiles(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_audit_deep_all_manifest(
            expected_profiles=["default", "math", "econ", "crypto"],
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][1]["execution_detail"]
        self.assertEqual(
            payload["source_manifests"][1]["execution_reason"],
            "audit-deep-all manifest is missing expected profiles",
        )
        self.assertEqual(detail["missing_expected_profiles"], ["math", "econ", "crypto"])

    def test_check_fresh_rejects_all_manifest_without_expected_profile_declaration(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        log = self._write(
            self.ws / ".audit_logs" / "audit_deep_all_default.log",
            "default profile completed\n",
        )
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [
                    {
                        "profile": "default",
                        "status": "success",
                        "exit_code": 0,
                        "log": str(log),
                    }
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(
            payload["source_manifests"][1]["execution_reason"],
            "audit-deep-all manifest does not declare expected profiles",
        )

    def test_check_fresh_rejects_all_manifest_with_nonzero_exit_code(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [{"profile": "default", "status": "success", "exit_code": 1}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][1]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertIn("nonzero profile exit codes", manifest_row["execution_reason"])

    def test_check_fresh_rejects_solidity_manifest_with_missing_schema(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok"}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][0]
        self.assertFalse(manifest_row["schema_matches"])
        self.assertEqual(manifest_row["expected_schema"], "auditooor.solidity_deep_audit.v1")
        self.assertEqual(manifest_row["execution_reason"], "source manifest schema mismatch")

    def test_check_fresh_rejects_non_solidity_all_manifest_with_wrong_schema(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.handwritten_fixture.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [{"profile": "default", "status": "success", "exit_code": 0}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][1]
        self.assertFalse(manifest_row["schema_matches"])
        self.assertEqual(manifest_row["expected_schema"], "auditooor.audit_deep_all.v1")
        self.assertEqual(manifest_row["execution_reason"], "source manifest schema mismatch")

    def test_check_fresh_rejects_non_solidity_all_manifest_without_profile_name(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [{"status": "success"}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][1]
        self.assertEqual(
            manifest_row["execution_reason"],
            "audit-deep-all manifest contains profile rows without names",
        )
        self.assertEqual(manifest_row["execution_detail"]["missing_profile_name_count"], 1)

    def test_check_fresh_rejects_stale_deep_manifest(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        manifest = self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "generated_at": "2026-05-30T09:59:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok"}],
            },
        )
        self._set_mtime(manifest)

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-stale-deep-manifest")
        self.assertFalse(payload["source_manifests"][0]["fresh"])

    def test_check_fresh_rejects_stale_timestamp_even_with_fresh_mtime(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        manifest = self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "generated_at": "2026-05-30T09:59:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok"}],
            },
        )
        os.utime(manifest, None)

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        self.assertEqual(payload["verdict"], "fail-stale-deep-manifest")
        self.assertFalse(manifest_row["fresh_by_mtime"])
        self.assertFalse(manifest_row["fresh"])

    def test_check_fresh_rejects_matching_run_id_when_timestamp_is_stale(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-demo")
        manifest = self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-demo",
                "generated_at": "2026-05-30T09:59:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok"}],
            },
        )
        self._set_mtime(manifest)

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        self.assertFalse(manifest_row["fresh_by_run_id"])
        self.assertFalse(manifest_row["run_id_mismatch"])
        self.assertFalse(manifest_row["fresh"])

    def test_check_fresh_rejects_matching_run_id_without_fresh_timestamp_or_mtime(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-demo")
        manifest = self._write_go_dlt_audit_enforcement_manifest(run_id="auditrun-demo")
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload.pop("timestamp_utc")
        manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._set_mtime(manifest)

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--run-id",
            "auditrun-demo",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][5]
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        self.assertTrue(manifest_row["run_id_matches_current"])
        self.assertTrue(manifest_row["fresh_by_run_id"])
        self.assertFalse(manifest_row["fresh_by_timestamp"])
        self.assertFalse(manifest_row["fresh_by_mtime"])
        self.assertFalse(manifest_row["fresh"])

    def test_check_fresh_rejects_mismatched_run_id_even_when_timestamp_is_fresh(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-other",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok"}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        self.assertTrue(manifest_row["fresh_by_timestamp"])
        self.assertTrue(manifest_row["run_id_mismatch"])
        self.assertFalse(manifest_row["fresh"])

    def test_check_fresh_rejects_missing_source_run_id_when_run_has_run_id(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok"}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        self.assertTrue(manifest_row["fresh_by_timestamp"])
        self.assertTrue(manifest_row["run_id_missing"])
        self.assertFalse(manifest_row["fresh"])

    def test_check_fresh_require_fresh_since_requires_run_id_identity(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        self._write_audit_deep_all_manifest(
            run_id="auditrun-other",
            timestamp_utc="2026-05-30T10:01:00Z",
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-fresh-since",
            "2026-05-30T10:00:00Z",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["verdict"], "fail-current-run-missing-run-id")
        self.assertIsNone(payload["run_id"])
        self.assertEqual(payload["source_manifests"], [])

    def test_check_fresh_rejects_dry_run_all_manifest(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": True,
                "profiles": [{"profile": "default", "status": "success", "exit_code": 0}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][1]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertIn("dry-run", manifest_row["execution_reason"])

    def test_check_fresh_rejects_failed_all_manifest_profile(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [{"profile": "default", "status": "failed", "exit_code": 1}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][1]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertIn("failed profiles", manifest_row["execution_reason"])

    def test_check_fresh_rejects_all_manifest_with_skipped_profiles(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [
                    {"profile": "default", "status": "success", "exit_code": 0},
                    {"profile": "math", "status": "skipped_budget", "exit_code": 0},
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][1]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertIn("skipped profiles", manifest_row["execution_reason"])

    def test_check_fresh_rejects_all_manifest_with_unknown_profile_status(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [
                    {"profile": "default", "status": "success", "exit_code": 0},
                    {"profile": "math", "status": "still_running", "exit_code": 0},
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][1]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertIn("unknown profile", manifest_row["execution_reason"])
        self.assertEqual(manifest_row["execution_detail"]["unknown_profile_statuses"], ["still_running"])

    def test_check_fresh_rejects_all_manifest_with_malformed_profile_rows(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {
                "schema": "auditooor.audit_deep_all.v1",
                "workspace": str(self.ws),
                "timestamp_utc": "2026-05-30T10:01:00Z",
                "dry_run": False,
                "profiles": [{"profile": "default", "status": "success", "exit_code": 0}, "bad-row"],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][1]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertIn("malformed profile", manifest_row["execution_reason"])
        self.assertEqual(manifest_row["execution_detail"]["malformed_profile_count"], 1)

    def test_check_fresh_rejects_solidity_manifest_without_engine_success(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "skipped"}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertIn("step artifacts did not all succeed", manifest_row["execution_reason"])

    def test_check_fresh_rejects_solidity_manifest_with_failed_engine_even_if_another_engine_succeeds(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [
                    {"tool": "halmos-runner", "status": "ok"},
                    {"tool": "medusa-fuzz", "status": "blocked"},
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertIn("step artifacts did not all succeed", manifest_row["execution_reason"])
        self.assertEqual(
            manifest_row["execution_detail"]["failed_deep_engines"],
            ["medusa-fuzz"],
        )

    def test_check_fresh_rejects_solidity_manifest_with_nonzero_engine_exit_code(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok", "exit_code": 1}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertIn("nonzero deep-engine exit codes", manifest_row["execution_reason"])

    def test_check_fresh_rejects_solidity_manifest_with_ok_engine_missing_step_artifact(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok"}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][0]
        detail = manifest_row["execution_detail"]
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity deep manifest has deep-engine rows without backed step artifacts",
        )
        self.assertEqual(detail["missing_step_artifact_count"], 1)
        self.assertEqual(detail["missing_step_artifacts"][0]["tool"], "halmos-runner")

    def test_check_fresh_rejects_solidity_manifest_with_outside_step_artifact(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        step = self.sandbox / "outside-halmos-step.json"
        self._write_json(
            step,
            {
                "schema": "auditooor.solidity_deep_audit.step.v1",
                "tool": "halmos-runner",
                "status": "ok",
                "returncode": 0,
                "run_id": "auditrun-current",
                "generated_at": "2026-05-30T10:01:30Z",
            },
        )
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][0]["execution_detail"]
        self.assertEqual(detail["step_schema_error_count"], 1)
        self.assertEqual(detail["step_schema_errors"][0]["error"], "outside_workspace")

    def test_check_fresh_rejects_solidity_manifest_with_bad_step_artifact_exit_code(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        step = self.ws / ".auditooor" / "solidity-deep-audit" / "halmos-runner.json"
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
            },
        )
        self._write_json(
            step,
            {
                "schema": "auditooor.solidity_deep_audit.step.v1",
                "tool": "halmos-runner",
                "status": "ok",
                "returncode": 1,
                "run_id": "auditrun-current",
                "generated_at": "2026-05-30T10:01:30Z",
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][0]
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["step_exit_code_error_count"], 1)
        self.assertEqual(detail["step_exit_code_errors"][0]["exit_code"], 1)

    def test_check_fresh_rejects_solidity_manifest_with_masked_runner_artifact_failures(self) -> None:
        cases = [
            ("medusa-fuzz", "medusa", "skipped", None, {"status_skipped"}),
            ("echidna-campaign", "echidna", "tool-unavailable", None, {"status_skipped"}),
            ("halmos-runner", "halmos", "ok", 1, {"nonzero_or_missing_exit_code"}),
        ]
        for tool, engine, runner_status, engine_rc, reasons in cases:
            with self.subTest(tool=tool, runner_status=runner_status, engine_rc=engine_rc):
                run_id = f"auditrun-{engine}-{runner_status}".replace("_", "-")
                self._write_run_start("2026-05-30T10:00:00Z", run_id=run_id)
                step = self._write_solidity_step_artifact(tool=tool, run_id=run_id)
                self._write_solidity_runner_artifact(
                    engine=engine,
                    status=runner_status,
                    engine_rc=engine_rc,
                )
                self._write_json(
                    self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
                    {
                        "schema": "auditooor.solidity_deep_audit.v1",
                        "workspace": str(self.ws),
                        "run_id": run_id,
                        "generated_at": "2026-05-30T10:01:00Z",
                        "artifacts": [{"tool": tool, "status": "ok", "artifact": str(step)}],
                    },
                )

                proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")

                self.assertEqual(proc.returncode, 1)
                payload = json.loads(proc.stdout)
                self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
                manifest_row = payload["source_manifests"][0]
                self.assertFalse(manifest_row["execution_ok"])
                self.assertEqual(
                    manifest_row["execution_reason"],
                    "solidity deep manifest runner artifacts did not all succeed",
                )
                detail = manifest_row["execution_detail"]
                self.assertEqual(detail["runner_artifact_error_count"], 1)
                error = detail["runner_artifact_errors"][0]
                self.assertEqual(error["tool"], tool)
                self.assertEqual(error["artifact"], f".auditooor/{engine}/artifact.json")
                self.assertTrue(reasons.issubset(set(error["reasons"])))

    def test_check_fresh_rejects_runner_artifact_with_no_execution_status(self) -> None:
        """Regression: an artifact with status='no-execution' is not evidence of a
        successful deep-engine run. The engine binary ran (rc=0) but the execution
        floor was not met - no symbolic checks fired (halmos) or no fuzz tests ran
        (echidna/medusa). The certification layer must treat this as a failure and
        emit 'status_no_execution' as the reason, never certify it as ok."""
        cases = [
            ("halmos-runner", "halmos", "no-execution"),
            ("echidna-campaign", "echidna", "no-execution"),
            ("medusa-fuzz", "medusa", "no-execution"),
            # Underscore variant must also be rejected.
            ("halmos-runner", "halmos", "no_execution"),
        ]
        for tool, engine, no_exec_status in cases:
            with self.subTest(tool=tool, status=no_exec_status):
                shutil.rmtree(self.ws / ".auditooor", ignore_errors=True)
                run_id = f"auditrun-{engine}-no-exec"
                self._write_run_start("2026-05-30T10:00:00Z", run_id=run_id)
                step = self._write_solidity_step_artifact(tool=tool, run_id=run_id)
                # Engine binary ran and exited 0, but no checks/tests actually ran.
                self._write_solidity_runner_artifact(
                    engine=engine,
                    status=no_exec_status,
                    engine_rc=0,
                    reason="engine ran but execution floor not met",
                    run_id=run_id,
                )
                self._write_json(
                    self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
                    {
                        "schema": "auditooor.solidity_deep_audit.v1",
                        "workspace": str(self.ws),
                        "run_id": run_id,
                        "generated_at": "2026-05-30T10:01:00Z",
                        "artifacts": [{"tool": tool, "status": "ok", "artifact": str(step)}],
                    },
                )

                proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")

                self.assertEqual(proc.returncode, 1, f"expected rejection for {tool} status={no_exec_status}")
                payload = json.loads(proc.stdout)
                self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
                manifest_row = payload["source_manifests"][0]
                self.assertFalse(
                    manifest_row["execution_ok"],
                    f"no-execution artifact for {tool} must not certify as ok",
                )
                self.assertEqual(
                    manifest_row["execution_reason"],
                    "solidity deep manifest runner artifacts did not all succeed",
                )
                detail = manifest_row["execution_detail"]
                self.assertEqual(detail["runner_artifact_error_count"], 1)
                error = detail["runner_artifact_errors"][0]
                self.assertEqual(error["tool"], tool)
                self.assertEqual(error["artifact"], f".auditooor/{engine}/artifact.json")
                self.assertIn(
                    "status_no_execution",
                    error["reasons"],
                    f"expected status_no_execution in reasons for {tool} status={no_exec_status}, got {error['reasons']}",
                )

    def test_check_fresh_rejects_typed_runner_engine_error_as_current_run_evidence(self) -> None:
        run_id = "auditrun-halmos-engine-error"
        self._write_run_start("2026-05-30T10:00:00Z", run_id=run_id)
        step = self._write_solidity_step_artifact(tool="halmos-runner", run_id=run_id)
        self._write_solidity_runner_artifact(
            engine="halmos",
            status="engine-error",
            engine_rc=2,
        )
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": run_id,
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")

        self.assertEqual(proc.returncode, 1, proc.stdout)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity deep manifest runner artifacts did not all succeed",
        )
        self.assertEqual(manifest_row["execution_detail"]["runner_artifact_error_count"], 1)
        self.assertIn(
            "status_failed",
            manifest_row["execution_detail"]["runner_artifact_errors"][0]["reasons"],
        )

    def test_check_fresh_rejects_solidity_manifest_with_missing_runner_artifact(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        step = self._write_solidity_step_artifact(run_id="auditrun-current")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][0]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertEqual(
            manifest_row["execution_reason"],
            "solidity deep manifest runner artifacts did not all succeed",
        )
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["runner_artifact_check_count"], 0)
        self.assertEqual(detail["runner_artifact_error_count"], 1)
        error = detail["runner_artifact_errors"][0]
        self.assertEqual(error["tool"], "halmos-runner")
        self.assertEqual(error["artifact"], ".auditooor/halmos/artifact.json")
        self.assertEqual(error["reason"], "missing")

    def test_check_fresh_rejects_solidity_manifest_with_stale_runner_artifact(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        step = self._write_solidity_step_artifact(run_id="auditrun-current")
        self._write_solidity_runner_artifact(created_at="2026-05-30T09:59:59Z")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        detail = payload["source_manifests"][0]["execution_detail"]
        self.assertEqual(detail["runner_artifact_error_count"], 1)
        self.assertIn("stale_or_missing_timestamp", detail["runner_artifact_errors"][0]["reasons"])

    def test_check_fresh_rejects_solidity_manifest_with_stale_step_artifact(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        step = self.ws / ".auditooor" / "solidity-deep-audit" / "halmos-runner.json"
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
            },
        )
        self._write_json(
            step,
            {
                "schema": "auditooor.solidity_deep_audit.step.v1",
                "tool": "halmos-runner",
                "status": "ok",
                "returncode": 0,
                "run_id": "auditrun-current",
                "generated_at": "2026-05-30T09:59:30Z",
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][0]
        detail = manifest_row["execution_detail"]
        self.assertEqual(detail["step_freshness_error_count"], 1)

    def test_check_fresh_rejects_solidity_manifest_with_failure_status(self) -> None:
        """Status 'failure' is a FAILED_STATE: execution_ok=False with medusa in failed_deep_engines."""
        shutil.rmtree(self.ws / ".auditooor", ignore_errors=True)
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [
                    {"tool": "halmos-runner", "status": "ok"},
                    {"tool": "medusa-fuzz", "status": "failure"},
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertIn("step artifacts did not all succeed", manifest_row["execution_reason"])
        self.assertEqual(
            manifest_row["execution_detail"]["failed_deep_engines"],
            ["medusa-fuzz"],
        )

    def test_check_fresh_rejects_solidity_manifest_with_timeout_status(self) -> None:
        """Status 'timeout' is a NO_EXECUTION_STATE (non-certifying): execution_ok=False,
        but medusa does NOT appear in failed_deep_engines (it's a timeout, not a failure).
        The runner exits 0 so the all-harnesses loop continues to the next harness."""
        shutil.rmtree(self.ws / ".auditooor", ignore_errors=True)
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [
                    {"tool": "halmos-runner", "status": "ok"},
                    {"tool": "medusa-fuzz", "status": "timeout"},
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        # Non-certifying: execution_ok must be False.
        self.assertFalse(manifest_row["execution_ok"])
        # "timeout" is a no-execution state, NOT a failed state, so the engine
        # must not appear in failed_deep_engines.
        detail = manifest_row["execution_detail"]
        self.assertNotIn("medusa-fuzz", detail.get("failed_deep_engines", []))

    def test_check_fresh_rejects_solidity_manifest_with_only_universal_fp_success(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "universal-fp-runner", "status": "ok"}],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        manifest_row = payload["source_manifests"][0]
        self.assertFalse(manifest_row["execution_ok"])
        self.assertEqual(
            manifest_row["execution_detail"]["ok_deep_engines"],
            ["universal-fp-runner"],
        )
        self.assertEqual(manifest_row["execution_detail"]["ok_proof_engines"], [])

    def test_check_fresh_rejects_fresh_manifest_masking_existing_current_failed_source_manifest(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_audit_deep_all_manifest()
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [
                    {"tool": "halmos-runner", "status": "ok"},
                    {"tool": "medusa-fuzz", "status": "timeout"},
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        self.assertEqual(
            payload["blocking_manifest_paths"],
            [".auditooor/solidity-deep-audit/manifest.json"],
        )

    def test_check_fresh_rejects_skip_masking_current_failed_source_manifest(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_json(
            self.ws / ".auditooor" / "stage_skips.json",
            {"NO_AUDIT_DEEP_REASON": "no supported deep engine for this workspace"},
        )
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [
                    {"tool": "halmos-runner", "status": "ok"},
                    {"tool": "medusa-fuzz", "status": "timeout"},
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        self.assertEqual(
            payload["blocking_manifest_paths"],
            [".auditooor/solidity-deep-audit/manifest.json"],
        )
        self.assertEqual(payload["skip"]["key"], "NO_AUDIT_DEEP_REASON")

    def test_check_fresh_rejects_valid_skip_masking_matching_run_id_stale_failed_source_manifest(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-test")
        self._write_structured_skip(run_id="auditrun-test")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "generated_at": "2026-05-30T09:59:00Z",
                "artifacts": [
                    {"tool": "halmos-runner", "status": "ok"},
                    {"tool": "medusa-fuzz", "status": "timeout"},
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][0]
        self.assertFalse(manifest_row["fresh_by_timestamp"])
        self.assertTrue(manifest_row["run_id_matches_current"])
        self.assertFalse(manifest_row["execution_ok"])

    def test_check_fresh_rejects_valid_skip_masking_matching_run_id_invalid_timestamp_failed_source_manifest(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-test")
        self._write_structured_skip(run_id="auditrun-test")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-test",
                "generated_at": "not-a-timestamp",
                "artifacts": [
                    {"tool": "halmos-runner", "status": "ok"},
                    {"tool": "medusa-fuzz", "status": "timeout"},
                ],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        manifest_row = payload["source_manifests"][0]
        self.assertIsNone(manifest_row["timestamp_utc"])
        self.assertTrue(manifest_row["run_id_matches_current"])
        self.assertFalse(manifest_row["execution_ok"])

    def test_check_fresh_accepts_fresh_manifest_despite_historical_stale_source_manifest(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_valid_solidity_deep_manifest()
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_manifest.json",
            {
                "schema": "auditooor.audit_deep_manifest_summary.v1",
                "workspace": str(self.ws),
                "generated_at_utc": "2026-05-30T09:59:00Z",
                "rows": [],
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        self.assertEqual(payload["blocking_manifest_paths"], [])

    def test_check_fresh_accepts_typed_skip_reason(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_structured_skip()

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-explicit-deep-skip")
        self.assertEqual(payload["skip"]["key"], "NO_AUDIT_DEEP_REASON")

    def test_append_success_events_records_typed_skip_reason(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-skip")
        self._append_ready_stage_rows(manifest, run_id="auditrun-skip")
        self._write_structured_skip(run_id="auditrun-skip")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-skip",
            "--append-audit-run-success-events",
            "--json",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-explicit-deep-skip")
        self.assertEqual(len(payload["appended_events"]), 2)
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[-2]["event"], "stage-pass")
        self.assertEqual(rows[-2]["stage"], "deep-freshness")
        self.assertEqual(rows[-2]["run_id"], "auditrun-skip")
        self.assertEqual(rows[-2]["deep_engine_completion_mode"], "typed-skip")
        self.assertEqual(rows[-2]["deep_engine_freshness_verdict"], "pass-explicit-deep-skip")
        self.assertEqual(rows[-2]["deep_engine_skip_reason"], "no supported deep engine for this workspace")
        self.assertEqual(rows[-1]["event"], "complete")
        self.assertEqual(rows[-1]["run_id"], "auditrun-skip")
        self.assertEqual(rows[-1]["deep_engine_completion_mode"], "typed-skip")
        self.assertEqual(rows[-1]["deep_engine_freshness_verdict"], "pass-explicit-deep-skip")
        self.assertEqual(rows[-1]["deep_engine_skip_key"], "NO_AUDIT_DEEP_REASON")

    def test_append_success_events_records_fresh_manifest_paths(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-fresh")
        self._append_ready_stage_rows(manifest, run_id="auditrun-fresh")
        step = self._write_solidity_step_artifact(run_id="auditrun-fresh")
        self._write_solidity_runner_artifact(run_id="auditrun-fresh")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-fresh",
                "generated_at": "2026-05-30T10:01:00Z",
                "generated_per_function_harness_count": 0,
                "executed_generated_harness_count": 0,
                "available_engine_harness_count": 0,
                "executed_engine_harness_count": 0,
                "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
            },
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-fresh",
            "--append-audit-run-success-events",
            "--json",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[-2]["event"], "stage-pass")
        self.assertEqual(rows[-2]["deep_engine_completion_mode"], "fresh-manifest")
        self.assertEqual(rows[-2]["deep_engine_freshness_verdict"], "pass-fresh-deep-manifest")
        self.assertEqual(rows[-2]["fresh_manifest_paths"], [".auditooor/solidity-deep-audit/manifest.json"])
        self.assertEqual(rows[-1]["event"], "complete")
        self.assertEqual(rows[-1]["deep_engine_completion_mode"], "fresh-manifest")
        self.assertEqual(rows[-1]["deep_engine_freshness_verdict"], "pass-fresh-deep-manifest")
        self.assertEqual(rows[-1]["fresh_manifest_paths"], [".auditooor/solidity-deep-audit/manifest.json"])

    def test_append_full_success_events_refuses_bounded_start_row(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-bounded-cli")
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        rows[0]["max_functions"] = "17"
        manifest.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        self._append_ready_stage_rows(manifest, run_id="auditrun-bounded-cli")
        self._write_strict_solidity_deep_manifest(run_id="auditrun-bounded-cli")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-bounded-cli",
            "--append-audit-run-success-events",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "")
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["verdict"], "fail-audit-run-success-append")
        self.assertIn("bounded start row", payload["append_error"])
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([row["event"] for row in rows], ["start", "stage-start", "stage-pass", "stage-start"])
        self.assertNotIn("complete", {row.get("event") for row in rows})
        self.assertNotIn("bounded-complete", {row.get("event") for row in rows})

    def test_append_bounded_success_events_records_bounded_terminal(self) -> None:
        manifest = self._write_run_start(
            "2026-05-30T10:00:00Z",
            run_id="auditrun-bounded",
            max_functions="17",
        )
        self._append_ready_stage_rows(manifest, run_id="auditrun-bounded")
        self._write_strict_solidity_deep_manifest(run_id="auditrun-bounded")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-bounded",
            "--append-audit-run-bounded-success-events",
            "--bounded-max-functions",
            "17",
            "--json",
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-fresh-deep-manifest")
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[-2]["event"], "stage-pass")
        self.assertEqual(rows[-2]["stage"], "deep-freshness")
        self.assertEqual(rows[-2]["deep_engine_completion_mode"], "fresh-manifest")
        self.assertEqual(rows[-1]["event"], "bounded-complete")
        self.assertEqual(rows[-1]["full_hunt_denominator"], "bounded")
        self.assertEqual(rows[-1]["max_functions"], "17")
        self.assertEqual(rows[-1]["deep_engine_completion_mode"], "fresh-manifest")
        self.assertEqual(rows[-1]["fresh_manifest_paths"], [".auditooor/solidity-deep-audit/manifest.json"])
        self.assertNotIn("complete", {row.get("event") for row in rows})

    def test_append_bounded_success_events_records_typed_skip_reason(self) -> None:
        manifest = self._write_run_start(
            "2026-05-30T10:00:00Z",
            run_id="auditrun-bounded-skip",
            max_functions="9",
        )
        self._append_ready_stage_rows(manifest, run_id="auditrun-bounded-skip")
        self._write_structured_skip(run_id="auditrun-bounded-skip")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-bounded-skip",
            "--append-audit-run-bounded-success-events",
            "--bounded-max-functions",
            "9",
            "--json",
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-explicit-deep-skip")
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[-2]["event"], "stage-pass")
        self.assertEqual(rows[-2]["stage"], "deep-freshness")
        self.assertEqual(rows[-2]["deep_engine_completion_mode"], "typed-skip")
        self.assertEqual(rows[-1]["event"], "bounded-complete")
        self.assertEqual(rows[-1]["full_hunt_denominator"], "bounded")
        self.assertEqual(rows[-1]["max_functions"], "9")
        self.assertEqual(rows[-1]["deep_engine_completion_mode"], "typed-skip")
        self.assertEqual(rows[-1]["deep_engine_skip_key"], "NO_AUDIT_DEEP_REASON")

    def test_append_bounded_success_events_requires_positive_max_functions(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-bounded-zero")
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        rows[0]["max_functions"] = "0"
        manifest.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        self._append_ready_stage_rows(manifest, run_id="auditrun-bounded-zero")
        self._write_strict_solidity_deep_manifest(run_id="auditrun-bounded-zero")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-bounded-zero",
            "--append-audit-run-bounded-success-events",
            "--bounded-max-functions",
            "0",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        self.assertIn("positive max_functions bound", proc.stderr)
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertNotIn("bounded-complete", {row.get("event") for row in rows})

    def test_append_bounded_success_events_requires_numeric_max_functions(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-bounded-nonnumeric")
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        rows[0]["max_functions"] = "all"
        manifest.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        self._append_ready_stage_rows(manifest, run_id="auditrun-bounded-nonnumeric")
        self._write_strict_solidity_deep_manifest(run_id="auditrun-bounded-nonnumeric")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-bounded-nonnumeric",
            "--append-audit-run-bounded-success-events",
            "--bounded-max-functions",
            "all",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        self.assertIn("non-integer max_functions", proc.stderr)
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertNotIn("bounded-complete", {row.get("event") for row in rows})

    def test_append_bounded_success_events_requires_max_functions_flag(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-bounded-missing")
        self._append_ready_stage_rows(manifest, run_id="auditrun-bounded-missing")
        self._write_strict_solidity_deep_manifest(run_id="auditrun-bounded-missing")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-bounded-missing",
            "--append-audit-run-bounded-success-events",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        self.assertIn("without max_functions", proc.stderr)
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertNotIn("bounded-complete", {row.get("event") for row in rows})

    def test_append_bounded_success_events_requires_start_row_bound_match(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-bounded-mismatch")
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        rows[0]["max_functions"] = "5"
        manifest.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        self._append_ready_stage_rows(manifest, run_id="auditrun-bounded-mismatch")
        self._write_strict_solidity_deep_manifest(run_id="auditrun-bounded-mismatch")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-bounded-mismatch",
            "--append-audit-run-bounded-success-events",
            "--bounded-max-functions",
            "9",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "")
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["verdict"], "fail-audit-run-success-append")
        self.assertIn("mismatched max_functions", payload["append_error"])
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertNotIn("bounded-complete", {row.get("event") for row in rows})

    def test_append_success_events_strict_refuses_partial_solidity_denominator(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-partial")
        self._append_ready_stage_rows(manifest, run_id="auditrun-partial")
        step = self._write_solidity_step_artifact(run_id="auditrun-partial")
        self._write_solidity_runner_artifact(run_id="auditrun-partial")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-partial",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
            },
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--require-full-invariant-denominator",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-partial",
            "--append-audit-run-success-events",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertNotIn("complete", {row.get("event") for row in rows})
        self.assertEqual(rows[-1]["stage"], "deep-freshness")

    def test_append_success_events_not_written_when_solidity_step_artifact_missing(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        self._append_ready_stage_rows(manifest, run_id="auditrun-current")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok"}],
            },
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-current",
            "--append-audit-run-success-events",
            "--json",
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["ok"])
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([row["event"] for row in rows], ["start", "stage-start", "stage-pass", "stage-start"])

    def test_append_success_events_not_written_when_freshness_fails(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-other",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok"}],
            },
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-current",
            "--append-audit-run-success-events",
            "--json",
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["ok"])
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_append_success_events_helper_strict_revalidates_solidity_denominator(self) -> None:
        module = self._load_tool_module("for_strict_append_revalidation_test")

        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        self._append_ready_stage_rows(manifest, run_id="auditrun-current")
        step = self._write_solidity_step_artifact(run_id="auditrun-current")
        self._write_solidity_runner_artifact()
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "generated_at": "2026-05-30T10:01:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok", "artifact": str(step)}],
            },
        )
        non_strict_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [".auditooor/solidity-deep-audit/manifest.json"],
        }

        with self.assertRaisesRegex(ValueError, "conflicting source manifest"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=non_strict_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([row["event"] for row in rows], ["start", "stage-start", "stage-pass", "stage-start"])

    def test_append_success_events_not_written_when_manifest_is_stale(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        self._write_json(
            self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "generated_at": "2026-05-30T09:59:00Z",
                "artifacts": [{"tool": "halmos-runner", "status": "ok"}],
            },
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-current",
            "--append-audit-run-success-events",
            "--json",
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")
        self.assertNotIn("complete", {row.get("event") for row in rows})

    def test_append_bounded_success_events_not_written_when_manifest_is_stale(self) -> None:
        manifest = self._write_run_start(
            "2026-05-30T10:00:00Z",
            run_id="auditrun-current",
            max_functions="5",
        )
        self._write_audit_deep_all_manifest(
            run_id="auditrun-current",
            timestamp_utc="2026-05-30T09:59:00Z",
        )

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-current",
            "--append-audit-run-bounded-success-events",
            "--bounded-max-functions",
            "5",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-conflicting-deep-manifest")
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")
        self.assertNotIn("bounded-complete", {row.get("event") for row in rows})

    def test_append_success_events_helper_refuses_failed_direct_call(self) -> None:
        import importlib.util

        module_name = "audit_deep_manifest_for_direct_call_test"
        spec = importlib.util.spec_from_file_location(module_name, TOOL)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        failed_result = {
            "ok": False,
            "verdict": "fail-conflicting-deep-manifest",
            "fresh_manifest_paths": [".audit_logs/audit_deep_all_manifest.json"],
        }
        with self.assertRaisesRegex(ValueError, "failed freshness result"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=failed_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_append_success_events_helper_refuses_incomplete_pass_direct_call(self) -> None:
        import importlib.util

        module_name = "audit_deep_manifest_for_incomplete_pass_test"
        spec = importlib.util.spec_from_file_location(module_name, TOOL)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        incomplete_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [],
        }
        with self.assertRaisesRegex(ValueError, "without fresh manifest paths"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=incomplete_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_append_success_events_helper_refuses_stale_skip_direct_call(self) -> None:
        import importlib.util

        module_name = "audit_deep_manifest_for_stale_skip_test"
        spec = importlib.util.spec_from_file_location(module_name, TOOL)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        stale_skip_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-explicit-deep-skip",
            "skip": {
                "key": "NO_AUDIT_DEEP_REASON",
                "reason": "no supported deep engine for this workspace",
                "fresh_for_run": False,
            },
        }
        with self.assertRaisesRegex(ValueError, "backed typed skip reason"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=stale_skip_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_append_success_events_helper_refuses_truthy_text_skip_direct_call(self) -> None:
        import importlib.util

        module_name = "audit_deep_manifest_for_text_skip_test"
        spec = importlib.util.spec_from_file_location(module_name, TOOL)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        text_skip_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-explicit-deep-skip",
            "skip": {
                "key": "NO_AUDIT_DEEP_REASON",
                "reason": "no supported deep engine for this workspace",
                "fresh_for_run": "false",
            },
        }
        with self.assertRaisesRegex(ValueError, "backed typed skip reason"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=text_skip_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_append_success_events_helper_refuses_legacy_only_fresh_paths_direct_call(self) -> None:
        import importlib.util

        module_name = "audit_deep_manifest_for_legacy_path_test"
        spec = importlib.util.spec_from_file_location(module_name, TOOL)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        legacy_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [".audit_logs/audit_deep_manifest.json"],
            "source_manifests": [
                {
                    "kind": "legacy-audit-deep-manifest",
                    "path": ".audit_logs/audit_deep_manifest.json",
                    "fresh": True,
                    "completion_source_eligible": False,
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "matching backed source manifest paths"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=legacy_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_append_success_events_helper_refuses_fresh_path_without_source_row(self) -> None:
        module = self._load_tool_module("for_missing_row_test")

        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        missing_row_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [".audit_logs/audit_deep_all_manifest.json"],
            "source_manifests": [],
        }
        with self.assertRaisesRegex(ValueError, "matching backed source manifest paths"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=missing_row_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_append_success_events_helper_refuses_missing_start_direct_call(self) -> None:
        module = self._load_tool_module("for_missing_start_test")

        manifest = self.ws / ".auditooor" / "audit_run_full_manifest.jsonl"
        forged_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [".audit_logs/audit_deep_all_manifest.json"],
            "source_manifests": [self._eligible_audit_deep_all_source_row()],
        }
        with self.assertRaisesRegex(ValueError, "matching start row"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=forged_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        self.assertFalse(manifest.exists())

    def test_append_success_events_helper_refuses_mismatched_start_direct_call(self) -> None:
        module = self._load_tool_module("for_mismatched_start_test")

        manifest = self._write_run_start(
            "2026-05-30T10:00:00Z",
            workspace=str(self.sandbox / "other-workspace"),
            run_id="auditrun-current",
        )
        forged_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [".audit_logs/audit_deep_all_manifest.json"],
            "source_manifests": [self._eligible_audit_deep_all_source_row()],
        }
        with self.assertRaisesRegex(ValueError, "matching start row"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=forged_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_append_success_events_helper_refuses_prior_stage_failure_direct_call(self) -> None:
        module = self._load_tool_module("for_prior_stage_failure_test")

        rows = [
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "start",
                "max_functions": "0",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "timestamp_utc": "2026-05-30T10:00:00Z",
            },
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "stage-fail",
                "run_id": "auditrun-current",
                "stage": "hunt-coverage",
                "rc": 1,
                "timestamp_utc": "2026-05-30T10:02:00Z",
            },
        ]
        manifest = self._write(
            self.ws / ".auditooor" / "audit_run_full_manifest.jsonl",
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        )
        forged_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [".audit_logs/audit_deep_all_manifest.json"],
            "source_manifests": [self._eligible_audit_deep_all_source_row()],
        }
        with self.assertRaisesRegex(ValueError, "prior stage failure"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=forged_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        written = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(written, rows)

    def test_append_success_events_allows_superseded_stage_failure(self) -> None:
        module = self._load_tool_module("for_superseded_stage_failure_test")

        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        rows = [
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "stage-start",
                "run_id": "auditrun-current",
                "stage": "hunt-coverage",
                "timestamp_utc": "2026-05-30T10:01:00Z",
            },
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "stage-fail",
                "run_id": "auditrun-current",
                "stage": "hunt-coverage",
                "rc": 2,
                "timestamp_utc": "2026-05-30T10:01:30Z",
            },
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "stage-start",
                "run_id": "auditrun-current",
                "stage": "hunt-coverage",
                "timestamp_utc": "2026-05-30T10:02:00Z",
            },
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "stage-pass",
                "run_id": "auditrun-current",
                "stage": "hunt-coverage",
                "timestamp_utc": "2026-05-30T10:02:30Z",
            },
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "stage-start",
                "run_id": "auditrun-current",
                "stage": "deep-freshness",
                "timestamp_utc": "2026-05-30T10:03:00Z",
            },
        ]
        with manifest.open("a", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        self._write_strict_solidity_deep_manifest(run_id="auditrun-current")
        result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [".auditooor/solidity-deep-audit/manifest.json"],
            "source_manifests": [self._eligible_solidity_source_row()],
        }

        appended = module.append_audit_run_success_events(
            audit_run_manifest=manifest,
            result=result,
            workspace=self.ws,
            run_id="auditrun-current",
        )

        events = {row["event"] for row in appended}
        self.assertIn("stage-pass", events)
        self.assertIn("complete", events)

    def test_append_success_events_cli_reports_prior_stage_failure_as_json(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        self._append_ready_stage_rows(manifest, run_id="auditrun-current")
        with manifest.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "schema": "auditooor.audit_run_full_manifest.v1",
                        "event": "stage-fail",
                        "run_id": "auditrun-current",
                        "stage": "exploit-conversion-loop",
                        "rc": 2,
                        "timestamp_utc": "2026-05-30T10:03:00Z",
                    },
                    sort_keys=True,
                )
                + "\n"
            )
        self._write_strict_solidity_deep_manifest(run_id="auditrun-current")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-current",
            "--append-audit-run-success-events",
            "--json",
        )

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "")
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["verdict"], "fail-audit-run-success-append")
        self.assertIn("prior stage failure", payload["append_error"])
        written = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertNotIn("complete", {row.get("event") for row in written})

    def test_append_success_events_helper_refuses_prior_top_level_failure_direct_call(self) -> None:
        module = self._load_tool_module("for_prior_top_level_failure_test")

        rows = [
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "start",
                "max_functions": "0",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "timestamp_utc": "2026-05-30T10:00:00Z",
            },
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "fail",
                "run_id": "auditrun-current",
                "stage": "preflight",
                "reason": "insufficient free disk space",
                "timestamp_utc": "2026-05-30T10:02:00Z",
            },
        ]
        manifest = self._write(
            self.ws / ".auditooor" / "audit_run_full_manifest.jsonl",
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        )
        forged_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [".audit_logs/audit_deep_all_manifest.json"],
            "source_manifests": [self._eligible_audit_deep_all_source_row()],
        }
        with self.assertRaisesRegex(ValueError, "prior stage failure"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=forged_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        written = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(written, rows)

    def test_append_success_events_helper_refuses_forged_source_row_without_disk_manifest(self) -> None:
        module = self._load_tool_module("for_forged_source_row_test")

        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        forged_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [".audit_logs/audit_deep_all_manifest.json"],
            "source_manifests": [self._eligible_audit_deep_all_source_row()],
        }
        with self.assertRaisesRegex(ValueError, "matching backed source manifest paths"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=forged_result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_append_success_events_helper_refuses_no_prior_stage_quorum(self) -> None:
        module = self._load_tool_module("for_no_stage_quorum_test")

        rows = [
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "start",
                "max_functions": "0",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "timestamp_utc": "2026-05-30T10:00:00Z",
            },
            {
                "schema": "auditooor.audit_run_full_manifest.v1",
                "event": "stage-start",
                "run_id": "auditrun-current",
                "stage": "deep-freshness",
                "timestamp_utc": "2026-05-30T10:02:00Z",
            },
        ]
        manifest = self._write(
            self.ws / ".auditooor" / "audit_run_full_manifest.jsonl",
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        )
        self._write_strict_solidity_deep_manifest(run_id="auditrun-current")
        forged_result = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [".auditooor/solidity-deep-audit/manifest.json"],
        }
        with self.assertRaisesRegex(ValueError, "without prior audit-run stages"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=forged_result,
                workspace=self.ws.resolve(strict=False),
                run_id="auditrun-current",
            )
        written = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(written, rows)

    def test_append_success_events_helper_refuses_wrong_result_schema_direct_call(self) -> None:
        module = self._load_tool_module("for_wrong_result_schema_test")

        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        result = {
            **self._fresh_result_metadata(),
            "schema": "wrong.schema",
            "ok": True,
            "verdict": "pass-fresh-deep-manifest",
            "fresh_manifest_paths": [],
        }
        with self.assertRaisesRegex(ValueError, "valid freshness result schema"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=result,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_append_success_events_helper_refuses_forged_skip_without_backing_file(self) -> None:
        module = self._load_tool_module("for_forged_skip_test")

        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        forged_skip = {
            **self._fresh_result_metadata(),
            "ok": True,
            "verdict": "pass-explicit-deep-skip",
            "skip": {
                "key": "NO_AUDIT_DEEP_REASON",
                "reason": "no supported deep engine for this workspace",
                "fresh_for_run": True,
            },
        }
        with self.assertRaisesRegex(ValueError, "backed typed skip reason"):
            module.append_audit_run_success_events(
                audit_run_manifest=manifest,
                result=forged_skip,
                workspace=self.ws,
                run_id="auditrun-current",
            )
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_check_fresh_rejects_legacy_manifest_as_sole_completion_source(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        self._write_json(
            self.ws / ".audit_logs" / "audit_deep_manifest.json",
            {
                "schema": "auditooor.audit_deep_manifest_summary.v1",
                "workspace": str(self.ws),
                "run_id": "auditrun-current",
                "generated_at_utc": "2026-05-30T10:01:00Z",
                "status": "success",
            },
        )

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-stale-deep-manifest")
        legacy = next(
            row for row in payload["source_manifests"] if row["kind"] == "legacy-audit-deep-manifest"
        )
        self.assertFalse(legacy["completion_source_eligible"])
        self.assertFalse(legacy["fresh"])

    def test_append_success_events_refuses_require_fresh_since_mode(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        self._write_valid_solidity_deep_manifest(run_id="auditrun-current")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-current",
            "--require-fresh-since",
            "2026-05-30T10:00:00Z",
            "--append-audit-run-success-events",
            "--json",
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("cannot be used with --require-fresh-since", proc.stderr)
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "start")

    def test_emit_provenance_stage_pass_records_typed_skip_reason(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-skip")
        self._write_structured_skip(run_id="auditrun-skip")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-skip",
            "--emit-provenance-stage-pass",
            "hunt-full",
            "--json",
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        row = payload["provenance_stage_pass"]
        self.assertEqual(row["event"], "stage-pass")
        self.assertEqual(row["stage"], "hunt-full")
        self.assertEqual(row["run_id"], "auditrun-skip")
        self.assertEqual(row["deep_engine_completion_mode"], "typed-skip")
        self.assertEqual(row["deep_engine_freshness_verdict"], "pass-explicit-deep-skip")
        self.assertEqual(row["deep_engine_skip_reason"], "no supported deep engine for this workspace")
        self.assertEqual(row["deep_engine_skip_key"], "NO_AUDIT_DEEP_REASON")
        self.assertEqual(row["deep_engine_skip_source"], "stage_skips.json")
        self.assertNotIn("fresh_manifest_paths", row)

    def test_emit_provenance_stage_pass_records_fresh_manifest_paths(self) -> None:
        manifest = self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-fresh")
        self._write_valid_solidity_deep_manifest(run_id="auditrun-fresh")

        proc = self._run(
            "--workspace",
            str(self.ws),
            "--check-fresh",
            "--audit-run-manifest",
            str(manifest),
            "--run-id",
            "auditrun-fresh",
            "--emit-provenance-stage-pass",
            "hunt-full",
            "--json",
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        row = payload["provenance_stage_pass"]
        self.assertEqual(row["event"], "stage-pass")
        self.assertEqual(row["stage"], "hunt-full")
        self.assertEqual(row["run_id"], "auditrun-fresh")
        self.assertEqual(row["deep_engine_completion_mode"], "fresh-manifest")
        self.assertEqual(row["deep_engine_freshness_verdict"], "pass-fresh-deep-manifest")
        self.assertEqual(
            row["fresh_manifest_paths"],
            [".auditooor/solidity-deep-audit/manifest.json"],
        )
        self.assertNotIn("deep_engine_skip_reason", row)

    def test_check_fresh_rejects_stale_typed_skip_reason(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        self._write_structured_skip(timestamp="2026-05-30T09:59:00Z")

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-no-deep-manifest")
        self.assertFalse(payload["skip"]["fresh_for_run"])

    def test_check_fresh_rejects_structured_skip_without_run_id(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        self._write_structured_skip(run_id=None)

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-no-deep-manifest")
        self.assertTrue(payload["skip"]["run_id_missing"])
        self.assertFalse(payload["skip"]["fresh_for_run"])
        self.assertIn("lacks run_id", payload["skip"]["freshness_error"])

    def test_check_fresh_rejects_string_skip_even_with_fresh_file_mtime(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")
        skip = self._write_json(
            self.ws / ".auditooor" / "stage_skips.json",
            {"NO_AUDIT_DEEP_REASON": "no supported deep engine for this workspace"},
        )
        self._set_mtime(skip, timestamp=1_906_000_000)

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-no-deep-manifest")
        self.assertFalse(payload["skip"]["fresh_for_run"])
        self.assertIn("per-skip timestamp", payload["skip"]["freshness_error"])

    def test_check_fresh_rejects_markdown_skip_without_run_id_even_with_fresh_file_mtime(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z", run_id="auditrun-current")
        skip = self._write(
            self.ws / ".auditooor" / "NO_AUDIT_DEEP_REASON.md",
            "no supported deep engine for this workspace\n",
        )
        self._set_mtime(skip, timestamp=1_906_000_000)

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["verdict"], "fail-no-deep-manifest")
        self.assertEqual(payload["skip"]["source"], "NO_AUDIT_DEEP_REASON.md")
        self.assertTrue(payload["skip"]["fresh_by_mtime"])
        self.assertFalse(payload["skip"]["fresh_for_run"])
        self.assertIn("lacks run_id", payload["skip"]["freshness_error"])

    def test_check_fresh_rejects_missing_manifest_without_skip(self) -> None:
        self._write_run_start("2026-05-30T10:00:00Z")

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-no-deep-manifest")

    def test_check_fresh_uses_latest_run_start(self) -> None:
        self._write(
            self.ws / ".auditooor" / "audit_run_full_manifest.jsonl",
            "\n".join(
                [
                    json.dumps(
                        {
                            "schema": "auditooor.audit_run_full_manifest.v1",
                            "event": "start",
                            "workspace": str(self.ws),
                            "run_id": "auditrun-old",
                            "timestamp_utc": "2026-05-30T09:00:00Z",
                        },
                        sort_keys=True,
                    ),
                    json.dumps(
                        {
                            "schema": "auditooor.audit_run_full_manifest.v1",
                            "event": "start",
                            "workspace": str(self.ws),
                            "run_id": "auditrun-new",
                            "timestamp_utc": "2026-05-30T10:00:00Z",
                        },
                        sort_keys=True,
                    ),
                ]
            )
            + "\n",
        )
        manifest = self._write_audit_deep_all_manifest(
            run_id=None,
            timestamp_utc="2026-05-30T09:30:00Z",
        )
        self._set_mtime(manifest)

        proc = self._run("--workspace", str(self.ws), "--check-fresh", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["run_start_utc"], "2026-05-30T10:00:00Z")
        self.assertEqual(payload["verdict"], "fail-stale-deep-manifest")

    def test_makefile_blocks_complete_on_deep_freshness(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        gate = text.rindex("stage-start\",\"stage\":\"deep-freshness")
        check = text.index("--append-audit-run-success-events", gate)
        complete = text.index("[make audit-run-full] complete")
        self.assertLess(gate, check)
        self.assertLess(check, complete)
        self.assertIn("AUDITOOOR_AUDIT_RUN_FULL_ID", text)
        self.assertIn('"event":"start","run_id":"%s"', text)
        self.assertIn('"event":"stage-start","stage":"deep-freshness","run_id":"%s"', text)
        self.assertIn('"event":"stage-fail","stage":"deep-freshness","run_id":"%s"', text)
        self.assertIn("--append-audit-run-success-events", text)
        self.assertIn("--run-id", text)

    def test_makefile_bounded_max_functions_uses_distinct_terminal_event(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        target_start = text.index("audit-run-full:")
        target_end = text.index("cvl-spec-risk-scan:", target_start)
        body = text[target_start:target_end]
        deep_stage = body.rindex('"event":"stage-start","stage":"deep-freshness"')
        full_branch = body.index('if [ "$(_AUDIT_RUN_FULL_MAX_FUNCTIONS)" = "0" ]; then', deep_stage)
        append_complete = body.index("--append-audit-run-success-events", full_branch)
        bounded_branch = body.index("else \\", append_complete)
        append_bounded = body.index("--append-audit-run-bounded-success-events", bounded_branch)
        bounded_max = body.index("--bounded-max-functions", append_bounded)
        bounded_echo = body.index("bounded complete (MAX_FUNCTIONS=$(_AUDIT_RUN_FULL_MAX_FUNCTIONS))", bounded_max)

        self.assertLess(deep_stage, full_branch)
        self.assertLess(full_branch, append_complete)
        self.assertLess(append_complete, bounded_branch)
        self.assertLess(bounded_branch, append_bounded)
        self.assertLess(append_bounded, bounded_max)
        self.assertLess(bounded_max, bounded_echo)
        self.assertNotIn("python3 -c 'import datetime,json,sys", body[bounded_branch:bounded_echo])
        self.assertNotIn("deep-freshness-bounded", body[bounded_branch:bounded_echo])
        self.assertIn("bounded complete (MAX_FUNCTIONS=$(_AUDIT_RUN_FULL_MAX_FUNCTIONS))", body)

    def test_makefile_audit_run_full_enforces_strict_hunt_coverage_before_proof(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        target_start = text.index("audit-run-full:")
        target_end = text.index("cvl-spec-risk-scan:", target_start)
        body = text[target_start:target_end]
        corpus_pass = body.index('stage-pass","run_id":"%s","stage":"corpus-driven-hunt')
        coverage_start = body.index('stage-start","run_id":"%s","stage":"hunt-coverage')
        coverage_gate = body.index('hunt-coverage-gate WS="$(_WS_RESOLVED)" MIN_COVERAGE=1.0 STRICT=1')
        conversion_start = body.index('stage-start","run_id":"%s","stage":"exploit-conversion-loop')
        proof_start = body.index('stage-start","run_id":"%s","stage":"prove-top-leads')
        self.assertLess(corpus_pass, coverage_start)
        self.assertLess(coverage_start, coverage_gate)
        self.assertLess(coverage_gate, conversion_start)
        self.assertLess(coverage_gate, proof_start)

    def test_makefile_audit_run_full_checks_deep_freshness_before_hunt_full_pass(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        target_start = text.index("audit-run-full:")
        target_end = text.index("cvl-spec-risk-scan:", target_start)
        body = text[target_start:target_end]
        hunt_cmd = body.index('hunt-full WS="$(_WS_RESOLVED)"')
        hunt_fresh_check = body.index(
            'tools/audit-deep-manifest.py --workspace "$(_WS_RESOLVED)" --check-fresh',
            hunt_cmd,
        )
        hunt_pass = body.index('payload["provenance_stage_pass"]', hunt_cmd)
        self.assertLess(hunt_cmd, hunt_fresh_check)
        self.assertLess(hunt_fresh_check, hunt_pass)
        self.assertIn('"stage":"hunt-full","step":"deep-freshness-after-hunt-full"', body)
        self.assertIn("--emit-provenance-stage-pass hunt-full", body)

    def test_makefile_audit_run_full_proof_conversion_advisory_by_default(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        target_start = text.index("audit-run-full:")
        target_end = text.index("cvl-spec-risk-scan:", target_start)
        body = text[target_start:target_end]
        self.assertIn(
            '[ "$${ENFORCE_AUTONOMOUS_PROOF_CONVERSION:-}" = "1" ] && '
            '[ -z "$(filter 1 true yes,$(EXECUTE_READY))" ]',
            body,
        )
        conversion_start = body.index('stage":"exploit-conversion-loop"')
        proof_start = body.index('stage":"prove-top-leads"')
        conversion_block = body[conversion_start:proof_start]
        proof_block = body[proof_start:]
        for stage, block in (
            ("exploit-conversion-loop", conversion_block),
            ("prove-top-leads", proof_block),
        ):
            with self.subTest(stage=stage):
                self.assertIn("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", block)
                self.assertIn('if [ "$$proof_enforce" = "1" ]; then', block)
                self.assertIn(f'"event":"stage-fail","run_id":"%s","stage":"{stage}"', block)
                self.assertIn(f'"event":"stage-warn","run_id":"%s","stage":"{stage}"', block)
                self.assertIn('"enforce_autonomous_proof_conversion":"0"', block)
                self.assertIn('"enforce_autonomous_proof_conversion":"1"', block)
                self.assertLess(
                    block.index(f'"event":"stage-pass","run_id":"%s","stage":"{stage}"'),
                    block.index("else"),
                )

    def test_makefile_audit_run_full_enforces_disk_free_preflight_before_mcp(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        target_start = text.index("audit-run-full:")
        target_end = text.index("cvl-spec-risk-scan:", target_start)
        body = text[target_start:target_end]
        self.assertIn("AUDIT_RUN_FULL_MIN_FREE_MB ?= 25600", text)
        self.assertIn("[AUDIT_RUN_FULL_MIN_FREE_MB=25600]", body)
        self.assertIn("_AUDIT_RUN_FULL_MAX_FUNCTIONS = $(if $(MAX_FUNCTIONS),$(MAX_FUNCTIONS),0)", text)
        self.assertIn("[MAX_FUNCTIONS=0]", body)
        self.assertIn('"max_functions":"%s"', body)
        self.assertIn('"$(_AUDIT_RUN_FULL_MAX_FUNCTIONS)"', body)
        start_row = body.index('"event":"start","run_id":"%s"')
        numeric_guard = body.index("AUDIT_RUN_FULL_MIN_FREE_MB must be a nonnegative integer")
        oversized_guard = body.index("AUDIT_RUN_FULL_MIN_FREE_MB is too large for shell-safe comparison")
        disk_check = body.index('df -Pm "$(_WS_RESOLVED)"')
        disk_fail = body.index('"reason":"insufficient free disk space"')
        bypass_hint = body.index("AUDIT_RUN_FULL_MIN_FREE_MB=0")
        mcp_start = body.index('stage":"mcp-preflight"')
        self.assertLess(start_row, disk_check)
        self.assertLess(start_row, numeric_guard)
        self.assertLess(numeric_guard, disk_check)
        self.assertLess(oversized_guard, disk_check)
        self.assertLess(disk_check, disk_fail)
        self.assertLess(disk_fail, mcp_start)
        self.assertLess(bypass_hint, mcp_start)
        self.assertIn('"reason":"invalid minimum free disk space"', body)

    def test_makefile_audit_run_full_defaults_to_full_function_coverage(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        target_start = text.index("audit-run-full:")
        target_end = text.index("cvl-spec-risk-scan:", target_start)
        body = text[target_start:target_end]
        self.assertIn("_AUDIT_RUN_FULL_MAX_FUNCTIONS = $(if $(MAX_FUNCTIONS),$(MAX_FUNCTIONS),0)", text)
        self.assertIn('hunt-full WS="$(_WS_RESOLVED)"', body)
        self.assertIn('MAX_FUNCTIONS="$(_AUDIT_RUN_FULL_MAX_FUNCTIONS)"', body)
        self.assertIn('novel-chain-hunt WS="$(_WS_RESOLVED)"', body)
        self.assertIn('corpus-driven-hunt WS="$(_WS_RESOLVED)"', body)
        self.assertNotIn('MAX_FUNCTIONS="$(if $(MAX_FUNCTIONS),$(MAX_FUNCTIONS),12)"', body)

    def test_makefile_audit_run_full_has_no_double_tab_silent_prefix(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        target_start = text.index("audit-run-full:")
        target_end = text.index("cvl-spec-risk-scan:", target_start)
        body = text[target_start:target_end]
        bad = [
            line
            for line in body.splitlines()
            if line.startswith("\t\t@")
        ]
        self.assertEqual(bad, [])

    def test_makefile_audit_run_full_manifest_rows_carry_run_id(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        target_start = text.index("audit-run-full:")
        target_end = text.index("cvl-spec-risk-scan:", target_start)
        body = text[target_start:target_end]
        self.assertNotIn('"event":"complete"', body)
        manifest_printfs = [
            line
            for line in body.splitlines()
            if "printf" in line and "auditooor.audit_run_full_manifest.v1" in line
        ]
        self.assertGreater(len(manifest_printfs), 10)
        for line in manifest_printfs:
            with self.subTest(line=line):
                self.assertRegex(line, re.escape('"run_id":"%s"'))

    def test_canonical_flow_verifies_deep_freshness_not_legacy_tail(self) -> None:
        inventory = (REPO / "tools" / "capability-inventory-build.py").read_text(encoding="utf-8")
        flow_doc = (REPO / "docs" / "CANONICAL_FLOWS.md").read_text(encoding="utf-8")
        for text in (inventory, flow_doc):
            with self.subTest(path="flow"):
                self.assertIn("tools/audit-deep-manifest.py --workspace <workspace> --check-fresh", text)
                self.assertIn("--audit-run-manifest <workspace>/.auditooor/audit_run_full_manifest.jsonl", text)
                self.assertIn("--run-id <auditrun-id>", text)
                self.assertIn("pass-fresh-deep-manifest|pass-explicit-deep-skip", text)
                self.assertIn("Do not trust legacy complete rows", text)
        self.assertNotIn('"expected_output": "stage-pass|stage-fail|complete"', inventory)
        self.assertNotIn("tail -20 <workspace>/.auditooor/audit_run_full_manifest.jsonl", flow_doc)
        self.assertNotIn("step['command'][:120]", inventory)
        self.assertIn("```bash", flow_doc)
        self.assertIn(
            "python3 /Users/wolf/auditooor-mcp/tools/vault-mcp-server.py --call vault_capability_inventory --args '{\"query\":\"audit-run-full\",\"limit\":10}'",
            flow_doc,
        )
        self.assertNotIn('{"query":"audit-ru`', flow_doc)
        self.assertNotIn('{"query":"cvl-spec`', flow_doc)


if __name__ == "__main__":
    unittest.main()
