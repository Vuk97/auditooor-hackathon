#!/usr/bin/env python3
"""Regression tests for Pipeline V2 full-driver authority and run order."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MAKEFILE = REPO / "Makefile"
MANIFEST = REPO / "tools" / "readme_runbook_steps.json"
EXECUTOR = REPO / "tools" / "pipeline-executor.py"


def _read_makefile() -> str:
    return MAKEFILE.read_text(encoding="utf-8")


def _read_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _extract_target_body(text: str, target: str) -> str:
    """Return the recipe body for a Makefile target."""
    start_marker = f"\n{target}:"
    start = text.find(start_marker)
    if start == -1:
        raise ValueError(f"target '{target}' not found in Makefile")
    body_start = text.index("\n", start + 1) + 1
    pos = body_start
    while pos < len(text):
        nl = text.find("\n", pos)
        if nl == -1:
            break
        line = text[nl + 1 :]
        if (
            line
            and not line[0].isspace()
            and ":" in line.split("=")[0]
            and not line.startswith(".PHONY")
            and not line.startswith("#")
        ):
            return text[body_start : nl + 1]
        pos = nl + 1
    return text[body_start:]


class TestPipelineFullExecutorAuthority(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not MAKEFILE.is_file():
            raise unittest.SkipTest(f"{MAKEFILE} not found")
        cls.text = _read_makefile()
        cls.public = _extract_target_body(cls.text, "audit-pipeline-full")
        cls.legacy = _extract_target_body(cls.text, "_audit-pipeline-full")
        cls.executor = EXECUTOR.read_text(encoding="utf-8")

    def test_public_target_validates_manifest_and_invokes_executor(self) -> None:
        self.assertIn("pipeline-manifest-validate.py", self.public)
        self.assertIn("tools/readme_runbook_steps.json", self.public)
        self.assertIn("pipeline-executor.py", self.public)
        self.assertIn("run-all", self.public)

    def test_public_target_never_invokes_legacy_shell_driver(self) -> None:
        self.assertNotIn("_audit-pipeline-full", self.public)
        self.assertNotIn("strict-pipeline-run.py", self.public)

    def test_public_target_forwards_runtime_modes_as_environment(self) -> None:
        for name in (
            "SOURCE_ONLY",
            "GITHUB_ONLY",
            "AUDITOOOR_LLM_HUNT",
            "AUDITOOOR_LLM_NETWORK_CONSENT",
            "PIPELINE_FORCE",
            "PIPELINE_STRICT",
        ):
            self.assertIn(name, self.public)

    def test_legacy_recipe_is_explicitly_noncanonical(self) -> None:
        self.assertIn("Retired legacy shell driver", self.text)
        self.assertIn("_audit-pipeline-full is retired", self.legacy)
        self.assertTrue(self.legacy.strip())

    def test_executor_runs_steps_from_manifest_state_machine(self) -> None:
        self.assertIn('_load_module("_pipeline_executor_manifest"', self.executor)
        self.assertIn('_load_module("_pipeline_executor_state"', self.executor)
        self.assertIn('_load_module("_pipeline_executor_receipt"', self.executor)
        self.assertIn('_load_module("_pipeline_executor_applicability"', self.executor)
        self.assertIn("def run_all(", self.executor)
        self.assertIn("_execution_manifest(_load_manifest(manifest_path), root)", self.executor)
        self.assertIn("next_step = _next_step(manifest, state)", self.executor)
        self.assertIn("run_step(manifest_path=manifest_path, workspace=root", self.executor)


class TestPipelineFullManifestOrder(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        manifest = _read_manifest()
        cls.manifest = manifest
        cls.steps = manifest["steps"]
        cls.by_id = {step["step_id"]: step for step in cls.steps}
        cls.contracts = {row["id"]: row for row in manifest["artifact_contracts"]}

    def test_all_sixty_nine_steps_are_required(self) -> None:
        self.assertEqual(self.manifest["schema"], "auditooor.pipeline_manifest.v2")
        self.assertEqual(self.manifest["expected_step_count"], 69)
        self.assertEqual(len(self.steps), 69)
        self.assertTrue(all(step["required"] is True for step in self.steps))
        self.assertEqual(sorted(step["order_index"] for step in self.steps), list(range(69)))
        self.assertEqual(sorted(step["run_sequence"] for step in self.steps), list(range(69)))

    def test_step_0g_precedes_step_1_and_uses_intake_target(self) -> None:
        self.assertLess(self.by_id["step-0g"]["run_sequence"], self.by_id["step-1"]["run_sequence"])
        self.assertEqual(
            self.by_id["step-0g"]["execution_target"],
            ["make", "pipeline-intake-coverage-plane", "WS={workspace}"],
        )
        self.assertEqual(
            self.by_id["step-1"]["execution_target"],
            [
                "make",
                "audit",
                "WS={workspace}",
                "AUDITOOOR_DEFER_DATAFLOW_SLICE=1",
                "AUDITOOOR_DEFER_HUNT_COVERAGE=1",
                "AUDITOOOR_DEFER_DRIVE=1",
                "FORCE=1",
                "STRICT=1",
                "AUDITOOOR_CANONICAL_STRICT=1",
            ],
        )
        self.assertEqual(
            self.by_id["step-1"]["depends_on"],
            ["step-0g"],
        )
        self.assertEqual(
            self.by_id["step-1"]["consumes"],
            ["artifact.step-0g", "artifact.step-0g-language-capability"],
        )

    def test_phase_two_reasoners_precede_hunt_depth_probe_fuzz_and_conversion(self) -> None:
        gates = (
            self.by_id["step-3"]["run_sequence"],
            self.by_id["step-4"]["run_sequence"],
            self.by_id["step-2c-input"]["run_sequence"],
            self.by_id["step-2c"]["run_sequence"],
            self.by_id["step-4e-exploit-conversion"]["run_sequence"],
        )
        for step in self.steps:
            if step["phase"] != "reasoning":
                continue
            self.assertLess(
                step["run_sequence"],
                min(gates),
                f"{step['step_id']} must stay ahead of hunt/depth/fuzz/exploit conversion",
            )

    def test_hunt_precedes_depth_manual_invariants_fuzz_input_and_fuzz(self) -> None:
        hunt = self.by_id["step-3"]["run_sequence"]
        self.assertLess(hunt, self.by_id["step-4"]["run_sequence"])
        self.assertLess(hunt, self.by_id["step-4b"]["run_sequence"])
        self.assertLess(hunt, self.by_id["step-2c-input"]["run_sequence"])
        self.assertLess(hunt, self.by_id["step-2c"]["run_sequence"])
        self.assertEqual(self.by_id["step-4"]["execution_target"][:2], ["make", "audit-deep-depth-probe"])
        self.assertEqual(
            self.by_id["step-4b"]["execution_target"],
            [
                "python3",
                "tools/readme-attestation-check.py",
                "--verify",
                "--ws",
                "{workspace}",
                "--step",
                "step-4b",
                "--json",
            ],
        )

    def test_depth_to_manual_to_fuzz_routes_follow_manifest_dependencies(self) -> None:
        self.assertEqual(self.by_id["step-4b"]["depends_on"], ["step-4"])
        self.assertEqual(self.by_id["step-2c-input"]["depends_on"], ["step-4b"])
        self.assertEqual(self.by_id["step-2c"]["depends_on"], ["step-2c-input"])
        self.assertEqual(self.contracts["artifact.step-4"]["consumer_step_ids"], ["step-4b"])
        self.assertEqual(self.contracts["artifact.step-4b"]["consumer_step_ids"], ["step-2c-input"])
        self.assertEqual(self.contracts["artifact.step-2c-input"]["consumer_step_ids"], ["step-2c"])

    def test_final_step_3e_through_3k_screens_precede_step_5(self) -> None:
        screen_ids = [
            "step-3e-coupled-state",
            "step-3f-enforcement-point",
            "step-3g-compiler-feature",
            "step-3h-trust-seam",
            "step-3i-authority-blast-radius",
            "step-3i-go-consensus-determinism",
            "step-3j-enforcement-layer-census",
            "step-3k-rust-untrusted-panic",
        ]
        verdict = self.by_id["step-5"]["run_sequence"]
        for step_id in screen_ids:
            self.assertLess(self.by_id[step_id]["run_sequence"], verdict, step_id)
        for earlier, later in zip(screen_ids, screen_ids[1:]):
            self.assertEqual(self.by_id[later]["depends_on"], [earlier])
        self.assertEqual(self.by_id["step-5"]["depends_on"], ["step-3k-rust-untrusted-panic"])

    def test_hunt_consumes_reasoner_regen_and_grounded_corpus_routes(self) -> None:
        hunt = self.by_id["step-3"]
        self.assertIn("artifact.step-2h-reasoner-regen", hunt["consumes"])
        self.assertIn("artifact.step-4c", hunt["consumes"])
        self.assertEqual(
            self.by_id["step-4c"]["produces"],
            ["artifact.step-4c-hunt-report", "artifact.step-4c"],
        )
        self.assertIn(
            "artifact.step-4c-hunt-report",
            self.by_id["step-2h-reasoner-regen"]["consumes"],
        )
        self.assertEqual(
            self.contracts["artifact.step-4c-hunt-report"]["consumer_step_ids"],
            ["step-2h-reasoner-regen"],
        )
        self.assertEqual(self.contracts["artifact.step-4c"]["validators"], ["file_exists"])
        self.assertEqual(
            self.contracts["artifact.step-4c"]["consumer_step_ids"],
            ["step-2h-reasoner-regen", "step-3", "step-4e-exploit-conversion", "step-5"],
        )
        self.assertEqual(
            self.contracts["artifact.step-2h-reasoner-regen"]["consumer_step_ids"],
            ["step-3", "step-4e-exploit-conversion", "step-5"],
        )


class TestTargetCommitMiningContract(unittest.TestCase):
    def test_target_commit_mining_is_bounded(self) -> None:
        body = _extract_target_body(_read_makefile(), "audit-target-commit-mining")
        self.assertIn("AUDITOOOR_TARGET_COMMIT_MINING_TIMEOUT", body)
        self.assertIn("gtimeout --kill-after=30", body)
        self.assertIn("timeout --kill-after=30", body)


if __name__ == "__main__":
    unittest.main()
