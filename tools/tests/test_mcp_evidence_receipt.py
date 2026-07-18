from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from lib.mcp_evidence_receipt import (  # noqa: E402
    SCHEMA,
    build_receipt,
    stable_hash,
    validate_receipt,
    validate_receipt_file,
)


class McpEvidenceReceiptTest(unittest.TestCase):
    def test_build_receipt_adds_proof_and_validates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            receipt = build_receipt(
                callable_name="vault_hacker_brief_for_lane",
                workspace=workspace,
                context_pack_id="auditooor.vault_hacker_brief_for_lane.v1:test",
                context_pack_hash="a" * 64,
                consumer_packet_hash="b" * 64,
                output_artifact_hash="c" * 64,
                source_file_hashes=[{"path": "src/lib.rs", "sha256": "d" * 64}],
                required_call_set=["vault_hacker_brief_for_lane", "vault_kill_rubric_context"],
                args={"lane_id": "bridge"},
                repo_sha="e" * 40,
                corpus_index_hash="f" * 64,
                timestamp="2026-05-21T00:00:00+00:00",
            )

        self.assertEqual(receipt["schema"], SCHEMA)
        body = dict(receipt)
        proof = body.pop("receipt_proof")
        self.assertEqual(proof, stable_hash(body))
        ok, errors = validate_receipt(receipt, workspace=workspace)
        self.assertTrue(ok, errors)

    def test_validate_rejects_malformed_hash_and_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            receipt = build_receipt(
                callable_name="vault_route",
                workspace=workspace,
                context_pack_id="auditooor.vault_route.v1:test",
                context_pack_hash="a" * 64,
                consumer_packet_hash="b" * 64,
                output_artifact_hash="c" * 64,
                required_call_set=["vault_route"],
            )
            receipt["context_pack_hash"] = "not-a-hash"

        ok, errors = validate_receipt(receipt, workspace=workspace)
        self.assertFalse(ok)
        self.assertIn("invalid_context_pack_hash", errors)
        self.assertIn("receipt_proof_mismatch", errors)

    def test_validate_receipt_file_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            receipt = build_receipt(
                callable_name="vault_dispatch_context",
                workspace=workspace,
                context_pack_id="auditooor.vault_dispatch_context.v1:test",
                context_pack_hash="a" * 64,
                consumer_packet_hash="b" * 64,
                output_artifact_hash="c" * 64,
                required_call_set=["vault_dispatch_context"],
            )
            path = workspace / ".auditooor" / "receipt.json"
            path.parent.mkdir()
            path.write_text(json.dumps(receipt), encoding="utf-8")

            ok, errors, loaded = validate_receipt_file(path, workspace=workspace)

        self.assertTrue(ok, errors)
        self.assertEqual(loaded["context_pack_id"], "auditooor.vault_dispatch_context.v1:test")


if __name__ == "__main__":
    unittest.main()

