#!/usr/bin/env python3
"""Offline regressions for local-only live-topology preflight output."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools" / "live-check-runner.py"


class LiveCheckRunnerLocalPreflightTest(unittest.TestCase):
    def test_preserves_pair_metadata_and_disabled_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            spec = ws / "local_live_checks.json"
            out_json = ws / "live_topology_checks.local.json"
            out_md = ws / "LIVE_TOPOLOGY.local.md"
            spec.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.live_checks.spec.v1",
                        "checks": [
                            {
                                "id": "edge-row",
                                "title": "Local edge row",
                                "contract": "Edge",
                                "network": "sepolia",
                                "address": "0x1111111111111111111111111111111111111111",
                                "call": "owner()",
                                "expect": "0x2222222222222222222222222222222222222222",
                                "evidence_class": "topology-relation",
                                "related_angle_ids": ["A-AUTH"],
                                "pair_id": "local-same-block-pair",
                                "local_only_runner": "fixture-local-runner.py",
                            },
                            {
                                "id": "authority-row",
                                "title": "Local authority row",
                                "contract": "Authority",
                                "network": "sepolia",
                                "address": "0x2222222222222222222222222222222222222222",
                                "call": "guardian()",
                                "expect": "0x3333333333333333333333333333333333333333",
                                "evidence_class": "topology-relation",
                                "related_angle_ids": ["A-AUTH"],
                                "pair_id": "local-same-block-pair",
                                "local_only_runner": "fixture-local-runner.py",
                            },
                            {
                                "id": "placeholder-row",
                                "title": "Placeholder expected value row",
                                "contract": "Verifier",
                                "network": "sepolia",
                                "address": "0x3333333333333333333333333333333333333333",
                                "call": "SP1_VERIFIER()",
                                "expect": "FILL_FROM_SAME_BLOCK_PROBE",
                                "enabled": False,
                                "blocked_reason": "expected value must be probed at the same local block",
                                "evidence_class": "topology-relation",
                                "related_angle_ids": ["A-AUTH"],
                                "pair_id": "local-placeholder-pair",
                                "local_only_runner": "fixture-local-runner.py",
                            },
                        ],
                    },
                    indent=2,
                )
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(ws),
                    "--spec",
                    str(spec),
                    "--dry-run",
                    "--pin-block",
                    "12345",
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stdout={proc.stdout}\nstderr={proc.stderr}")
            payload = json.loads(out_json.read_text())

            self.assertEqual(payload["summary"]["dry_run"], 2)
            self.assertEqual(payload["summary"]["disabled"], 1)
            rows = {row["id"]: row for row in payload["results"]}
            self.assertEqual(rows["edge-row"]["pair_id"], "local-same-block-pair")
            self.assertEqual(rows["authority-row"]["local_only_runner"], "fixture-local-runner.py")
            self.assertEqual(rows["placeholder-row"]["status"], "disabled")
            self.assertEqual(rows["placeholder-row"]["execution_mode"], "skipped")
            self.assertIn("same local block", rows["placeholder-row"]["blocked_reason"])

            pairs = {pair["id"]: pair for pair in payload["proof_pairs"]}
            self.assertIn("local-same-block-pair", pairs)
            self.assertEqual(pairs["local-same-block-pair"]["status"], "partial")
            self.assertEqual(pairs["local-same-block-pair"]["shared_block"], "12345")

            md = out_md.read_text()
            self.assertIn("- Disabled: 1", md)
            self.assertIn("## placeholder-row", md)


if __name__ == "__main__":
    unittest.main()
