#!/usr/bin/env python3
"""Tests for tools/audit-workflow-coverage-map.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "audit-workflow-coverage-map.py"


def load_module():
    spec = importlib.util.spec_from_file_location("audit_workflow_coverage_map", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AuditWorkflowCoverageMapTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="audit_workflow_coverage_")
        self.root = Path(self.tmp.name)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.makefile = self.root / "Makefile"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_fixture(self, makefile: str) -> None:
        self.makefile.write_text(textwrap.dedent(makefile).lstrip(), encoding="utf-8")

    def touch_tool(self, rel: str, body: str = "") -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body or "# fixture\n", encoding="utf-8")

    @staticmethod
    def status(report: dict, workflow_id: str, concept_id: str) -> str:
        for workflow in report["workflows"]:
            if workflow["workflow_id"] != workflow_id:
                continue
            for concept in workflow["concepts"]:
                if concept["concept_id"] == concept_id:
                    return concept["status"]
        raise AssertionError(f"missing {workflow_id}/{concept_id}")

    def test_temp_makefile_fixture_maps_present_unknown_missing(self) -> None:
        module = load_module()
        self.write_fixture(
            """
            audit:
            \tpython3 tools/memory-context-load.py --workspace "$(WS)"
            \t$(MAKE) --no-print-directory brain-prime WS="$(WS)"
            \t$(MAKE) --no-print-directory provider-fanout-discipline-check WS="$(WS)"
            \t$(MAKE) --no-print-directory prior-disclosure-index WS="$(WS)"
            \t$(MAKE) --no-print-directory exploit-queue WS="$(WS)" JSON=1

            audit-deep:
            \tbash tools/audit-deep.sh "$(WS)"
            \tpython3 tools/harness-execution-queue.py --workspace "$(WS)"
            \t$(MAKE) --no-print-directory exploit-conversion-loop WS="$(WS)"

            audit-closeout:
            \tpython3 tools/audit-closeout-check.py --workspace "$(WS)"
            \t$(MAKE) --no-print-directory provider-fanout-discipline-check WS="$(WS)"

            v3-provider-fanout-closeout:
            \tpython3 tools/v3-provider-fanout-closeout.py --workspace "$(WS)"

            agent-artifact-mine:
            \tpython3 tools/agent-artifact-miner.py --workspace "$(WS)"
            """
        )
        self.touch_tool("tools/memory-context-load.py")
        self.touch_tool("tools/brain-prime.py")
        self.touch_tool("tools/provider-fanout-discipline-check.py")
        self.touch_tool("tools/exploit-queue.py")
        self.touch_tool("tools/harness-execution-queue.py")
        self.touch_tool("tools/agent-artifact-miner.py")
        self.touch_tool(
            "tools/pre-submit-check.sh",
            "# Originality posture\n# OOS scope\n# dupe-risk\n# candidate judgment packet\n# SEVERITY-CALIBRATION\n",
        )

        report = module.build_report(self.makefile, self.tools)

        self.assertEqual(self.status(report, "audit", "mcp_recall"), "present")
        self.assertEqual(self.status(report, "audit", "brain_prime_hacker_brief"), "present")
        self.assertEqual(self.status(report, "audit", "provider_fanout"), "present")
        self.assertEqual(self.status(report, "audit_deep", "proof_execution"), "present")
        self.assertEqual(self.status(report, "closeout", "queue_closeout"), "present")
        self.assertEqual(self.status(report, "pre_submit", "originality"), "present")
        self.assertEqual(self.status(report, "pre_submit", "oos_scope"), "present")
        self.assertEqual(self.status(report, "pre_submit", "dupe_risk"), "present")
        self.assertEqual(self.status(report, "pre_submit", "candidate_judgment"), "present")
        self.assertEqual(self.status(report, "pre_submit", "severity_calibration"), "present")
        self.assertEqual(self.status(report, "audit", "agent_artifact_mining"), "unknown")
        self.assertEqual(self.status(report, "pre_submit", "hacker_questions"), "missing")
        self.assertIn("dupe_risk", report["concept_summary"])
        self.assertIn("candidate_judgment", report["concept_summary"])
        self.assertIn("severity_calibration", report["concept_summary"])

    def test_pre_submit_makefile_reference_is_evidence_source(self) -> None:
        module = load_module()
        self.write_fixture(
            """
            audit:
            \tpython3 tools/audit-progress.py --workspace "$(WS)"

            paste-ready:
            \tbash tools/pre-submit-check.sh "$(DRAFT)"
            """
        )
        self.touch_tool("tools/pre-submit-check.sh", "# HACKER-QUESTION-ANSWERS\n")

        report = module.build_report(self.makefile, self.tools)
        self.assertEqual(self.status(report, "pre_submit", "hacker_questions"), "present")
        pre_submit = next(w for w in report["workflows"] if w["workflow_id"] == "pre_submit")
        self.assertTrue(any("Makefile references" in ref for ref in pre_submit["source_refs"]))

    def test_cli_json_uses_temp_makefile(self) -> None:
        self.write_fixture(
            """
            audit:
            \tpython3 tools/memory-context-load.py --workspace "$(WS)"
            """
        )
        self.touch_tool("tools/memory-context-load.py")

        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--makefile",
                str(self.makefile),
                "--tools-dir",
                str(self.tools),
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.audit_workflow_coverage_map.v1")
        self.assertEqual(self.status(payload, "audit", "mcp_recall"), "present")


if __name__ == "__main__":
    unittest.main()
