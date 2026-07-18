#!/usr/bin/env python3
"""Tests for tools/evidence-class-validator.py (KNOWN_LIMITATIONS item #14).

Hermetic via ``tempfile.TemporaryDirectory``. Each test scaffolds a
synthetic workspace tree containing one or more closeout artifacts at
specific evidence-class buckets and asserts that:

- per-class counts add up correctly,
- legacy rows surface in ``legacy_count`` and ``legacy_artifact_paths``,
- ``--strict`` exits non-zero when at least one artifact is legacy,
- ``--out-json`` writes a deterministic JSON payload.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "evidence-class-validator.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("ec_validator", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ec_validator"] = mod
    spec.loader.exec_module(mod)
    return mod


def _scaffold_artifacts(ws: Path, *, briefs: list[dict], survivors: list[dict],
                        deep_records: list[dict], queue_items: list[dict] | None,
                        manifests: list[dict]) -> None:
    if briefs is not None:
        (ws / "swarm").mkdir(exist_ok=True)
        (ws / "swarm" / "brief_candidates.json").write_text(
            json.dumps({"candidates": briefs}, indent=2) + "\n",
            encoding="utf-8",
        )
    if survivors is not None:
        (ws / "source_mining" / "campaign_a").mkdir(parents=True, exist_ok=True)
        (ws / "source_mining" / "campaign_a" / "survivors.json").write_text(
            json.dumps(survivors, indent=2) + "\n",
            encoding="utf-8",
        )
    if deep_records:
        (ws / "deep_counterexamples").mkdir(parents=True, exist_ok=True)
        for rec in deep_records:
            name = rec.get("_name") or rec.get("target_function", "demo")
            payload = {k: v for k, v in rec.items() if k != "_name"}
            (
                ws
                / "deep_counterexamples"
                / f"{name}.deep_counterexample.v1.json"
            ).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if queue_items is not None:
        (ws / "deep_counterexamples").mkdir(parents=True, exist_ok=True)
        (ws / "deep_counterexamples" / "execution_queue.json").write_text(
            json.dumps(
                {"schema_version": "test", "items": queue_items}, indent=2
            )
            + "\n",
            encoding="utf-8",
        )
    if manifests:
        for idx, manifest in enumerate(manifests):
            mdir = ws / "poc_execution" / f"case_{idx:03d}"
            mdir.mkdir(parents=True, exist_ok=True)
            (mdir / "execution_manifest.json").write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )


class CollectTest(unittest.TestCase):
    """Per-class counts add up across every artifact type."""

    def test_partitions_each_class_correctly(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory(prefix="ecv-") as tmp:
            ws = Path(tmp)
            _scaffold_artifacts(
                ws,
                briefs=[
                    {"contract": "Vault", "evidence_class": "generated_hypothesis"},
                    {"contract": "Vault", "evidence_class": "generated_hypothesis"},
                ],
                survivors=[
                    {"candidate_id": "S1", "evidence_class": "generated_hypothesis"},
                ],
                deep_records=[
                    {
                        "_name": "case01",
                        "schema_version": "auditooor.deep_counterexample.v1",
                        "target_function": "Vault.withdraw",
                        "evidence_class": "scaffolded_unverified",
                    },
                    {
                        "_name": "case02",
                        "schema_version": "auditooor.deep_counterexample.v1",
                        "target_function": "Vault.deposit",
                        "evidence_class": "executed_with_manifest",
                    },
                ],
                queue_items=[
                    {
                        "record_id": "case01",
                        "status": "needs_replay_wiring",
                        "evidence_class": "scaffolded_unverified",
                    },
                    {
                        "record_id": "case02",
                        "status": "executed",
                        "evidence_class": "executed_with_manifest",
                    },
                ],
                manifests=[
                    {
                        "candidate_id": "case02",
                        "final_result": "proved",
                        "impact_assertion": "exploit_impact",
                        "evidence_class": "executed_with_manifest",
                    },
                    {
                        "candidate_id": "case03",
                        "final_result": "proved",
                        "impact_assertion": "exploit_impact",
                        "evidence_class": "human_verified",
                    },
                ],
            )
            payload = mod.collect(ws)

        agg = payload["aggregate_counts"]
        self.assertEqual(agg["generated_hypothesis"], 3)  # 2 briefs + 1 survivor
        self.assertEqual(agg["scaffolded_unverified"], 2)  # 1 record + 1 queue row
        self.assertEqual(agg["executed_with_manifest"], 3)  # record + queue + manifest
        self.assertEqual(agg["human_verified"], 1)
        self.assertEqual(agg["missing"], 0)
        self.assertEqual(payload["verified_count"], 4)
        self.assertEqual(payload["hypothesis_count"], 5)
        self.assertEqual(payload["legacy_count"], 0)

        # Per-artifact rollups are present and shaped correctly.
        self.assertEqual(
            payload["per_artifact"]["brief_candidates"]["row_count"], 2
        )
        self.assertEqual(
            payload["per_artifact"]["poc_execution_manifests"]["verified_count"], 2
        )

    def test_pr560_generated_artifacts_are_counted_as_non_proof(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory(prefix="ecv-pr560-") as tmp:
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
                + "\n",
                encoding="utf-8",
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
                + "\n",
                encoding="utf-8",
            )
            (audit / "source_proof_impact_bridge.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.pr560.source_proof_impact_bridge.v1",
                        "rows": [
                            {"bridge_id": "SPIC-001", "evidence_class": "generated_hypothesis"}
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
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
                + "\n",
                encoding="utf-8",
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
                                "selected_impact": "topology proof pair",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
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
                + "\n",
                encoding="utf-8",
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
                + "\n",
                encoding="utf-8",
            )
            (logs / "local_provider_verification_queue.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.provider_local_verification_queue.v1",
                        "rows": [
                            {
                                "task_id": "PLV-001",
                                "evidence_class": "generated_hypothesis",
                                "submit_ready": False,
                                "selected_impact": "source review only",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            payload = mod.collect(ws)

        self.assertEqual(payload["verified_count"], 0)
        self.assertEqual(payload["legacy_count"], 0)
        self.assertEqual(payload["policy_violation_count"], 0)
        self.assertEqual(payload["aggregate_counts"]["generated_hypothesis"], 6)
        self.assertEqual(payload["aggregate_counts"]["scaffolded_unverified"], 3)
        self.assertEqual(
            payload["per_artifact"]["impact_miss_benchmark"]["row_count"], 2
        )
        self.assertEqual(
            payload["per_artifact"]["scanner_autonomy_plan"]["hypothesis_count"], 1
        )
        self.assertEqual(
            payload["per_artifact"]["semantic_detector_argument_resolver"]["row_count"], 1
        )
        self.assertEqual(
            payload["per_artifact"]["live_topology_proof_requirements"]["row_count"], 1
        )
        self.assertEqual(
            payload["per_artifact"]["live_provider_result_triage"]["row_count"], 1
        )
        self.assertEqual(
            payload["per_artifact"]["provider_local_verification_queue"]["row_count"], 1
        )

    def test_live_provider_result_triage_requires_evidence_class(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory(prefix="ecv-live-triage-") as tmp:
            ws = Path(tmp)
            logs = ws / ".audit_logs" / "pr560_worker_zz"
            logs.mkdir(parents=True)
            (logs / "live_provider_result_triage.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.live_provider_result_triage.v1",
                        "rows": [
                            {
                                "task_id": "LPRT-LEGACY",
                                "submit_ready": False,
                                "submission_posture": "NOT_SUBMIT_READY",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            payload = mod.collect(ws)

        self.assertEqual(payload["legacy_count"], 1)
        self.assertEqual(
            payload["per_artifact"]["live_provider_result_triage"]["legacy_count"], 1
        )
        self.assertTrue(
            any("live_provider_result_triage.json" in p for p in payload["legacy_artifact_paths"])
        )

    def test_policy_violations_prevent_unverified_submit_ready_rows(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory(prefix="ecv-policy-") as tmp:
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
                + "\n",
                encoding="utf-8",
            )
            payload = mod.collect(ws)

        self.assertEqual(payload["legacy_count"], 0)
        self.assertEqual(payload["policy_violation_count"], 2)
        reasons = {row["reason"] for row in payload["policy_violations_sample"]}
        self.assertIn("unverified_row_submit_ready_true", reasons)
        self.assertIn("unverified_row_promotion_allowed_true", reasons)

    def test_missing_field_raises_legacy_count(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory(prefix="ecv-") as tmp:
            ws = Path(tmp)
            _scaffold_artifacts(
                ws,
                briefs=[
                    {"contract": "Vault"},  # legacy: no evidence_class
                    {"contract": "Vault", "evidence_class": "generated_hypothesis"},
                ],
                survivors=[],
                deep_records=[],
                queue_items=None,
                manifests=[],
            )
            payload = mod.collect(ws)
        self.assertEqual(payload["legacy_count"], 1)
        self.assertEqual(
            payload["aggregate_counts"]["generated_hypothesis"], 1
        )
        self.assertGreater(payload["legacy_artifact_path_total"], 0)
        sample = payload["legacy_artifact_paths"]
        self.assertTrue(any("brief_candidates.json" in p for p in sample))


class CliTest(unittest.TestCase):
    """End-to-end exit-code and JSON shape via subprocess."""

    def test_strict_exits_nonzero_on_legacy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ecv-") as tmp:
            ws = Path(tmp)
            _scaffold_artifacts(
                ws,
                briefs=[{"contract": "Vault"}],  # legacy
                survivors=[],
                deep_records=[],
                queue_items=None,
                manifests=[],
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--strict"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("legacy total:", proc.stdout)

    def test_json_mode_emits_per_class_payload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ecv-") as tmp:
            ws = Path(tmp)
            out = ws / "validator.json"
            _scaffold_artifacts(
                ws,
                briefs=[{"contract": "Vault", "evidence_class": "generated_hypothesis"}],
                survivors=[],
                deep_records=[],
                queue_items=None,
                manifests=[
                    {
                        "candidate_id": "case01",
                        "final_result": "proved",
                        "impact_assertion": "exploit_impact",
                        "evidence_class": "executed_with_manifest",
                    }
                ],
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--json",
                    "--out-json",
                    str(out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            stdout_payload = json.loads(proc.stdout)
            disk_payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(stdout_payload, disk_payload)
            self.assertEqual(stdout_payload["verified_count"], 1)
            self.assertEqual(stdout_payload["hypothesis_count"], 1)
            self.assertEqual(stdout_payload["legacy_count"], 0)


if __name__ == "__main__":
    unittest.main()
