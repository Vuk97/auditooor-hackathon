from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUGMENTER = ROOT / "tools" / "agent-prompt-hacker-augmenter.py"
CHAINED = ROOT / "tools" / "chained-attack-planner.py"
PROOF_QUEUE = ROOT / "tools" / "proof-obligation-queue.py"


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_cli(tool: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(tool), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=45,
    )


def _extract_make_target(makefile_text: str, target: str) -> str:
    lines = makefile_text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(target)}\s*:", line):
            start = i
            break
    if start is None:
        return ""

    end = len(lines)
    for j in range(start + 1, len(lines)):
        if re.match(r"^\S.*:", lines[j]):
            end = j
            break

    return "\n".join(lines[start + 1 : end])


class HackerLogicWorkflowSmokeTest(unittest.TestCase):
    def test_detector_hacker_artifacts_become_proof_tasks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hacker-logic-workflow-") as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / "swarm").mkdir()

            (ws / "engage_report.md").write_text(
                "\n".join(
                    [
                        "# Engagement Report",
                        "",
                        "### reentrancy-no-guard",
                        "- src/Vault.sol:42: withdraw callback path lacks reentrancy lock",
                        "",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            _write_json(
                ws / "engage_report.json",
                {
                    "clusters": [
                        {
                            "detector_slug": "reentrancy-no-guard",
                            "hits": [
                                {
                                    "severity": "HIGH",
                                    "file_path": "src/Vault.sol:42",
                                    "snippet": "withdraw callback path lacks reentrancy lock",
                                }
                            ],
                        }
                    ]
                },
            )
            _write_json(
                ws / ".auditooor" / "exploit_memory_brief.json",
                {
                    "schema": "auditooor.exploit_memory_brief.v1",
                    "workspace_path": str(ws),
                    "angles": [
                        {
                            "angle_id": "angle-001",
                            "title": "withdraw accounting drift",
                            "target_files": ["src/Vault.sol"],
                            "source_refs": ["workspace:src/Vault.sol:42"],
                            "proof_prerequisites": [
                                {
                                    "artifact": ".auditooor/live_topology_proof_requirements.json",
                                    "status": "required",
                                    "summary": "collect local proof pair",
                                    "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                                }
                            ],
                            "not_submit_ready_until": ["pre-submit gate has not passed"],
                        }
                    ],
                },
            )

            brief_out = ws / ".auditooor" / "hacker_brief.md"
            augmenter = _run_cli(
                AUGMENTER,
                [
                    "--workspace",
                    str(ws),
                    "--lane-id",
                    "H1-vault",
                    "--files",
                    "src/Vault.sol",
                    "--out",
                    str(brief_out),
                    "--json-out",
                ],
            )
            self.assertEqual(
                augmenter.returncode,
                0,
                f"augmenter failed\nstdout:\n{augmenter.stdout}\nstderr:\n{augmenter.stderr}",
            )

            brief_sidecar = ws / ".auditooor" / "hacker_brief.md.json"
            self.assertTrue(brief_sidecar.is_file(), "hacker brief sidecar missing")
            brief_payload = json.loads(brief_sidecar.read_text(encoding="utf-8"))
            questions = (
                brief_payload.get("sections", {})
                .get("sec13_question_list", {})
                .get("items", [])
            )
            qdet_ids = {
                str(row.get("id"))
                for row in questions
                if isinstance(row, dict) and str(row.get("id", "")).startswith("Q-DET-")
            }
            self.assertTrue(qdet_ids, "hacker brief did not emit any Q-DET questions")

            chained = _run_cli(CHAINED, ["--workspace", str(ws)])
            self.assertEqual(
                chained.returncode,
                0,
                f"chained planner failed\nstdout:\n{chained.stdout}\nstderr:\n{chained.stderr}",
            )

            chained_path = ws / "swarm" / "chained_attack_plans.json"
            self.assertTrue(chained_path.is_file(), "chained attack plans output missing")
            chained_payload = json.loads(chained_path.read_text(encoding="utf-8"))
            self.assertGreaterEqual(chained_payload["summary"]["hacker_brief_qdet_count"], 1)
            self.assertGreaterEqual(chained_payload["summary"]["plan_count"], 1)

            queue_out = ws / ".auditooor" / "proof_obligation_queue.json"
            queue = _run_cli(
                PROOF_QUEUE,
                [
                    "--workspace",
                    str(ws),
                    "--out",
                    str(queue_out),
                    "--generated-at",
                    "2026-05-13T00:00:00Z",
                ],
            )
            self.assertEqual(
                queue.returncode,
                0,
                f"proof queue failed\nstdout:\n{queue.stdout}\nstderr:\n{queue.stderr}",
            )
            self.assertTrue(queue_out.is_file(), "proof obligation queue output missing")
            queue_payload = json.loads(queue_out.read_text(encoding="utf-8"))

            self.assertEqual(queue_payload["schema"], "auditooor.proof_obligation_queue.v1")
            self.assertEqual(queue_payload["generated_at_utc"], "2026-05-13T00:00:00Z")
            self.assertGreaterEqual(queue_payload["summary"]["question_tasks"], 1)
            self.assertGreaterEqual(queue_payload["summary"]["chain_blocker_tasks"], 1)

            task_questions = {
                str(row.get("source_question"))
                for row in queue_payload.get("tasks", [])
                if row.get("source_question")
            }
            self.assertTrue(task_questions & qdet_ids, "no Q-DET question was promoted into the proof queue")
            self.assertTrue(
                any(str(row.get("chain_id") or "").startswith("CHAIN-") for row in queue_payload.get("tasks", [])),
                "no chained-plan blocker task found in proof queue",
            )


class HackerLogicOperatorContractTextTest(unittest.TestCase):
    def test_makefile_audit_invokes_bridge_and_freshness_marker(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        audit_body = _extract_make_target(makefile, "audit")
        self.assertTrue(audit_body, "audit target not found in Makefile")
        self.assertIn(
            "$(MAKE) --no-print-directory audit-hacker-logic-bridge WS=\"$(_WS_RESOLVED)\" STRICT=\"$(STRICT)\" || bridge_rc=$$? ; \\",
            audit_body,
            "make audit must invoke audit-hacker-logic-bridge",
        )
        self.assertIn(
            "python3 tools/proof-queue-freshness-marker.py",
            audit_body,
            "make audit must call proof queue freshness marker",
        )
        self.assertIn("--mode mark-stale", audit_body, "make audit should mark proof queue as stale on bridge failure")
        self.assertIn("--mode mark-fresh", audit_body, "make audit should mark proof queue fresh on bridge success")
        self.assertIn(
            "STRICT=1: failing on audit-hacker-logic-bridge",
            audit_body,
            "make audit STRICT=1 must fail closed on bridge failure",
        )

    def test_makefile_bridge_target_passes_strict_flag_to_cli(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        bridge_body = _extract_make_target(makefile, "audit-hacker-logic-bridge")
        self.assertTrue(bridge_body, "audit-hacker-logic-bridge target not found in Makefile")
        self.assertIn(
            "$(if $(filter 1 true TRUE yes YES,$(STRICT)),--strict)",
            bridge_body,
            "make audit-hacker-logic-bridge STRICT=1 must pass --strict to the CLI",
        )

    def test_workflow_docs_reference_make_audit_detector_to_hacker_proof_queue_path(self) -> None:
        candidate_docs = [
            ROOT / "README.md",
            ROOT / "docs" / "DETECTOR_TO_HACKER_BRIDGE.md",
            ROOT / "docs" / "WORKFLOW.md",
            ROOT / "docs" / "TOOL_STATUS.md",
        ]
        matching_docs = []
        for path in candidate_docs:
            text = path.read_text(encoding="utf-8").lower()
            if (
                "make audit" in text
                and ("detector-to-hacker" in text or "detector to hacker" in text)
                and "proof queue" in text
            ):
                matching_docs.append(path)

        self.assertTrue(
            matching_docs,
            "user-facing workflow docs no longer document make audit feeding detector-to-hacker/proof queue path",
        )

    def test_detector_bridge_doc_keeps_mcp_first_and_deep_non_exhaustive_boundaries(self) -> None:
        bridge_doc = (ROOT / "docs" / "DETECTOR_TO_HACKER_BRIDGE.md").read_text(encoding="utf-8")
        lowered = bridge_doc.lower()
        normalized = re.sub(r"\s+", " ", lowered)

        self.assertLess(
            lowered.index("start with bounded mcp recall"),
            lowered.index("make audit ws=~/audits/<project>"),
            "bridge doc must put initial MCP recall before make audit mechanics",
        )
        for required in (
            "pre-audit orientation step",
            "post-audit detector-cluster feed",
            "advisory",
            "not exhaustive coverage",
            "do not ingest `audit_deep_all_manifest.json`",
            "before regenerating the queue",
        ):
            self.assertIn(required, normalized)


if __name__ == "__main__":
    unittest.main()
