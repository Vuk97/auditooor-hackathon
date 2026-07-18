from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "source-proof-record.py"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _workspace(*, with_contract: bool = True) -> Path:
    ws = Path(tempfile.mkdtemp(prefix="source_proof_ws_"))
    (ws / "src").mkdir()
    (ws / "src" / "Bridge.sol").write_text(
        textwrap.dedent(
            """\
            pragma solidity ^0.8.20;

            contract Bridge {
                function finalize(bytes calldata proof) external {
                    require(proof.length > 0, "proof");
                }
            }
            """
        ),
        encoding="utf-8",
    )
    if with_contract:
        out = ws / ".auditooor"
        out.mkdir()
        (out / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.impact_contracts.v1",
                    "workspace": str(ws),
                    "contracts": [
                        {
                            "candidate_id": "C-BRIDGE",
                            "selected_impact": "",
                            "original_selected_impact": "Bridge finalization can be bypassed",
                            "severity": "Critical",
                            "exact_impact_row": True,
                            "listed_impact_proven": True,
                            "evidence_class": "source_proof",
                            "oos_traps": "No admin-only or imported-contract prerequisite.",
                            "stop_condition": "Stop if cited source no longer bypasses bridge finalization.",
                            "posture": "NOT_SUBMIT_READY",
                            "terminal_route": "source_proof",
                        }
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )
    return ws


class SourceProofRecordTest(unittest.TestCase):
    def test_candidate_snapshot_prefers_newest_queue_generation(self) -> None:
        ws = _workspace(with_contract=False)
        out = ws / ".auditooor"
        out.mkdir(exist_ok=True)
        source_mined = out / "exploit_queue.source_mined.json"
        canonical = out / "exploit_queue.json"
        source_mined.write_text(
            json.dumps({"queue": [{"lead_id": "EQ-006", "title": "stale recycled title"}]}),
            encoding="utf-8",
        )
        canonical.write_text(
            json.dumps({"queue": [{"lead_id": "EQ-006", "title": "current governance title"}]}),
            encoding="utf-8",
        )
        os.utime(source_mined, ns=(1_000_000_000, 1_000_000_000))
        os.utime(canonical, ns=(2_000_000_000, 2_000_000_000))
        result = _run([
            "--workspace", str(ws), "--candidate", "EQ-006",
            "--citation", "src/Bridge.sol:4", "--verdict", "killed", "--print-json",
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["candidate_title"], "current governance title")
        self.assertEqual(Path(payload["candidate_queue_path"]).resolve(), canonical.resolve())
    def test_records_proved_source_only_with_exact_impact_contract(self) -> None:
        ws = _workspace()
        result = _run(
            [
                "--workspace",
                str(ws),
                "--candidate",
                "C-BRIDGE",
                "--citation",
                "src/Bridge.sol:4-5",
                "--oos-status",
                "in_scope",
                "--verdict",
                "proved_source_only",
                "--print-json",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema_version"], "auditooor.source_proof.v1")
        self.assertEqual(payload["final_verdict"], "proved_source_only")
        self.assertTrue(payload["impact_contract_linked"])
        self.assertEqual(payload["selected_impact"], "Bridge finalization can be bypassed")
        self.assertEqual(payload["valid_source_citation_count"], 1)
        self.assertEqual(payload["oos_status"], "in_scope")
        self.assertEqual(payload["evidence_class"], "human_verified")
        self.assertEqual(
            payload["impact_contract_preflight"]["route"],
            "source-proof",
        )
        self.assertEqual(
            payload["impact_contract_preflight"]["decision"]["code"],
            "impact-contract-explicit",
        )
        self.assertTrue((ws / "source_proofs" / "C-BRIDGE" / "source_proof.json").is_file())

    def test_missing_impact_contract_blocks_even_if_proof_requested(self) -> None:
        ws = _workspace(with_contract=False)
        result = _run(
            [
                "--workspace",
                str(ws),
                "--candidate",
                "C-BRIDGE",
                "--citation",
                "src/Bridge.sol:4",
                "--oos-status",
                "in_scope",
                "--verdict",
                "proved_source_only",
                "--print-json",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["final_verdict"], "blocked_missing_impact_contract")
        self.assertFalse(payload["impact_contract_linked"])
        self.assertTrue(payload["impact_contract_preflight"]["decision"]["blocked"])
        self.assertIn("missing exact impact_contract", " ".join(payload["blockers"]))

    def test_killed_record_does_not_require_impact_contract(self) -> None:
        ws = _workspace(with_contract=False)
        (ws / ".auditooor").mkdir(exist_ok=True)
        (ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [{
                "lead_id": "C-BRIDGE",
                "title": "bridge finalization bypass",
                "source_refs": ["src/Bridge.sol:4"],
            }]}), encoding="utf-8"
        )
        result = _run(
            [
                "--workspace",
                str(ws),
                "--candidate",
                "C-BRIDGE",
                "--citation",
                "src/Bridge.sol:4",
                "--oos-status",
                "not_checked",
                "--verdict",
                "killed",
                "--print-json",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["final_verdict"], "killed")
        self.assertEqual(payload["requested_verdict"], "killed")
        self.assertFalse(payload["impact_contract_linked"])
        self.assertEqual(payload["valid_source_citation_count"], 1)
        self.assertEqual(payload["blockers"], [])
        self.assertEqual(payload["candidate_title"], "bridge finalization bypass")
        self.assertEqual(payload["candidate_source_refs"], ["src/Bridge.sol:4"])
        self.assertTrue(payload["candidate_identity_sha256"])

    def test_proved_source_only_requires_valid_citation_and_in_scope_oos(self) -> None:
        ws = _workspace()
        result = _run(
            [
                "--workspace",
                str(ws),
                "--candidate",
                "C-BRIDGE",
                "--citation",
                "src/Bridge.sol:4",
                "--oos-status",
                "oos",
                "--verdict",
                "proved_source_only",
                "--print-json",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["final_verdict"], "killed")
        self.assertEqual(payload["valid_source_citation_count"], 1)
        self.assertIn("in_scope", " ".join(payload["blockers"]))

    def test_missing_citation_is_not_valid_even_for_killed_record(self) -> None:
        ws = _workspace(with_contract=False)
        result = _run(
            [
                "--workspace", str(ws),
                "--candidate", "C-BRIDGE",
                "--citation", "src/does-not-exist.sol:4",
                "--verdict", "killed",
                "--print-json",
            ]
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid source citation", result.stderr)
        self.assertFalse((ws / "source_proofs" / "C-BRIDGE" / "source_proof.json").exists())


if __name__ == "__main__":
    unittest.main()
