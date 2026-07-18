#!/usr/bin/env python3
"""Focused tests for tools/solidity-deep-all-harnesses-manifest.py."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent.parent
TOOL = REPO / "tools" / "solidity-deep-all-harnesses-manifest.py"


def _load_tool_module():
    spec = importlib.util.spec_from_file_location("solidity_deep_all_harnesses_manifest", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module from {TOOL}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestSolidityDeepAllHarnessesManifest(unittest.TestCase):
    def setUp(self) -> None:
        self.sandbox = Path(tempfile.mkdtemp(prefix="solidity_all_harness_manifest_"))
        self.workspace = self.sandbox / "ws"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.module = _load_tool_module()

    def tearDown(self) -> None:
        shutil.rmtree(self.sandbox, ignore_errors=True)

    def _write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _write_json(self, path: Path, payload: dict) -> None:
        self._write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def _write_per_function_manifests(
        self,
        *,
        run_id: str,
        generated_count: int,
        ok_count: int,
    ) -> None:
        self._write_json(
            self.workspace / "poc-tests" / "per_function_invariants" / "manifest.json",
            {
                "schema": "auditooor.per_function_invariant_gen.v1",
                "workspace": str(self.workspace),
                "function_count": generated_count,
                "functions": [{"selector": f"Vault.fn{i}"} for i in range(generated_count)],
            },
        )
        self._write_json(
            self.workspace / ".audit_logs" / "solidity_per_function_halmos_manifest.json",
            {
                "schema": "auditooor.solidity_per_function_halmos.v1",
                "workspace": str(self.workspace),
                "run_id": run_id,
                "expected_invocation_count": generated_count,
                "executed_invocation_count": generated_count,
                "ok_invocation_count": ok_count,
                "invocations": [
                    {
                        "selector": f"Vault.fn{i}",
                        "status": "ok" if i < ok_count else "blocked",
                    }
                    for i in range(generated_count)
                ],
            },
        )

    def _prepare_harness(self, slug: str, run_id: str) -> Path:
        root = self.workspace / "poc-tests" / slug
        manifest = self.workspace / ".auditooor" / "solidity-deep-audit" / "by-harness" / slug / "manifest.json"
        runner_root = self.workspace / ".auditooor" / "deep-engine-runs" / "by-harness" / slug
        self._write_json(
            manifest,
            {
                "schema": "auditooor.solidity_deep_audit.v1",
                "workspace": str(self.workspace),
                "run_id": run_id,
                "status_counts": {"ok": 3},
            },
        )
        for engine in ("halmos", "echidna", "medusa"):
            self._write_json(
                runner_root / engine / "artifact.json",
                {
                    "status": "ok",
                    "run_id": run_id,
                    "engine_rc": 0,
                },
            )
        return root

    def test_build_manifest_emits_full_denominator_fields(self) -> None:
        run_id = "auditrun-1"
        root_a = self._prepare_harness("alpha-engine-harness", run_id)
        root_b = self._prepare_harness("beta-engine-harness", run_id)
        self._write_per_function_manifests(run_id=run_id, generated_count=3, ok_count=3)
        roots_file = self.workspace / ".auditooor" / "solidity-deep-audit" / "all-harness-roots.txt"
        self._write(roots_file, f"{root_a}\n{root_b}\n")

        payload = self.module.build_manifest(
            self.workspace,
            roots_file,
            self.workspace / ".audit_logs" / "solidity_deep_all_harnesses_manifest.json",
            run_id,
        )

        self.assertEqual(payload["schema"], "auditooor.solidity_deep_all_harnesses.v1")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["expected_harness_count"], 2)
        self.assertEqual(payload["enumerated_harness_count"], 2)
        self.assertEqual(payload["executed_harness_count"], 2)
        self.assertEqual(payload["available_engine_harness_roots"], [str(root_a), str(root_b)])
        self.assertEqual(payload["available_engine_harness_count"], 2)
        self.assertEqual(payload["generated_per_function_harness_count"], 3)
        self.assertEqual(payload["executed_generated_harness_count"], 3)
        self.assertEqual(payload["executed_engine_harness_count"], 2)
        self.assertEqual(payload["invariant_denominator_status"], "complete-full-invariant-denominator")
        self.assertTrue(payload["full_in_scope_invariant_denominator"])
        self.assertEqual(payload["ok_harness_count"], 2)
        self.assertEqual(payload["blocked_harness_count"], 0)
        self.assertEqual(payload["skipped_harness_count"], 0)
        self.assertEqual(payload["missing_harness_count"], 0)
        self.assertEqual(payload["ok_harness_slugs"], ["alpha-engine-harness", "beta-engine-harness"])

    def test_build_manifest_reports_partial_denominator_when_harness_is_missing(self) -> None:
        run_id = "auditrun-1"
        root = self.workspace / "poc-tests" / "alpha-engine-harness"
        self._write_per_function_manifests(run_id=run_id, generated_count=1, ok_count=0)
        roots_file = self.workspace / ".auditooor" / "solidity-deep-audit" / "all-harness-roots.txt"
        self._write(roots_file, f"{root}\n")

        payload = self.module.build_manifest(
            self.workspace,
            roots_file,
            self.workspace / ".audit_logs" / "solidity_deep_all_harnesses_manifest.json",
            run_id,
        )

        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(payload["expected_harness_count"], 1)
        self.assertEqual(payload["enumerated_harness_count"], 1)
        self.assertEqual(payload["executed_harness_count"], 1)
        self.assertEqual(payload["generated_per_function_harness_count"], 1)
        self.assertEqual(payload["available_engine_harness_count"], 1)
        self.assertEqual(payload["executed_generated_harness_count"], 1)
        self.assertEqual(payload["executed_engine_harness_count"], 0)
        self.assertEqual(payload["invariant_denominator_status"], "partial-invariant-denominator")
        self.assertFalse(payload["full_in_scope_invariant_denominator"])
        self.assertEqual(payload["blocked_harness_count"], 0)
        self.assertEqual(payload["missing_harness_count"], 1)
        self.assertEqual(payload["missing_harness_slugs"], ["alpha-engine-harness"])

    def test_build_manifest_counts_attempted_per_function_denominator(self) -> None:
        run_id = "auditrun-1"
        root = self._prepare_harness("alpha-engine-harness", run_id)
        self._write_per_function_manifests(run_id=run_id, generated_count=5, ok_count=4)
        roots_file = self.workspace / ".auditooor" / "solidity-deep-audit" / "all-harness-roots.txt"
        self._write(roots_file, f"{root}\n")

        payload = self.module.build_manifest(
            self.workspace,
            roots_file,
            self.workspace / ".audit_logs" / "solidity_deep_all_harnesses_manifest.json",
            run_id,
        )

        self.assertEqual(payload["available_engine_harness_count"], 1)
        self.assertEqual(payload["executed_engine_harness_count"], 1)
        self.assertEqual(payload["generated_per_function_harness_count"], 5)
        self.assertEqual(payload["executed_generated_harness_count"], 5)
        self.assertEqual(payload["invariant_denominator_status"], "complete-full-invariant-denominator")
        self.assertTrue(payload["full_in_scope_invariant_denominator"])

    def test_build_manifest_records_harness_when_one_engine_skips_but_another_succeeds(self) -> None:
        run_id = "auditrun-1"
        root = self._prepare_harness("alpha-engine-harness", run_id)
        self._write_per_function_manifests(run_id=run_id, generated_count=1, ok_count=1)
        self._write_json(
            self.workspace
            / ".auditooor"
            / "deep-engine-runs"
            / "by-harness"
            / "alpha-engine-harness"
            / "echidna"
            / "artifact.json",
            {
                "status": "skipped",
                "run_id": run_id,
                "engine_rc": 0,
            },
        )
        roots_file = self.workspace / ".auditooor" / "solidity-deep-audit" / "all-harness-roots.txt"
        self._write(roots_file, f"{root}\n")

        payload = self.module.build_manifest(
            self.workspace,
            roots_file,
            self.workspace / ".audit_logs" / "solidity_deep_all_harnesses_manifest.json",
            run_id,
        )

        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["skipped_harness_count"], 0)
        self.assertEqual(payload["skipped_harness_slugs"], [])
        self.assertEqual(payload["ok_harness_count"], 1)
        self.assertEqual(payload["executed_engine_harness_count"], 1)
        self.assertTrue(payload["full_in_scope_invariant_denominator"])

    def test_build_manifest_records_harness_when_one_engine_fails_but_another_succeeds(self) -> None:
        run_id = "auditrun-1"
        root = self._prepare_harness("alpha-engine-harness", run_id)
        self._write_per_function_manifests(run_id=run_id, generated_count=1, ok_count=1)
        self._write_json(
            self.workspace
            / ".auditooor"
            / "deep-engine-runs"
            / "by-harness"
            / "alpha-engine-harness"
            / "halmos"
            / "artifact.json",
            {
                "status": "engine-error",
                "run_id": run_id,
                "engine_rc": 1,
            },
        )
        roots_file = self.workspace / ".auditooor" / "solidity-deep-audit" / "all-harness-roots.txt"
        self._write(roots_file, f"{root}\n")

        payload = self.module.build_manifest(
            self.workspace,
            roots_file,
            self.workspace / ".audit_logs" / "solidity_deep_all_harnesses_manifest.json",
            run_id,
        )

        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["blocked_harness_count"], 0)
        self.assertEqual(payload["ok_harness_count"], 1)
        self.assertEqual(payload["executed_engine_harness_count"], 1)
        self.assertTrue(payload["full_in_scope_invariant_denominator"])


if __name__ == "__main__":
    unittest.main()
