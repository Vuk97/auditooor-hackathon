from __future__ import annotations

import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "prior-history-awareness-gate.py"
SPEC = importlib.util.spec_from_file_location("prior_history_awareness_gate", TOOL)
GATE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(GATE)


def complete_manifest() -> dict:
    kinds = sorted(GATE._load_awareness_module().SOURCE_KINDS)
    rows = []
    for kind in kinds:
        content = "reviewed evidence"
        rows.append({
            "source_id": f"source-{kind}",
            "source_kind": kind,
            "pin_binding": "pin-1",
            "content": content,
            "source_ref": f"https://github.example/{kind}",
            "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "awareness_state": "team_aware",
        })
    return {
        "audit_pin": "pin-1",
        "required_source_kinds": kinds,
        "expected_sources": [
            {
                "source_id": row["source_id"],
                "source_kind": row["source_kind"],
                "source_ref": row["source_ref"],
                "pin_binding": row["pin_binding"],
            }
            for row in rows
        ],
        "evidence_rows": rows,
        "candidates": [
            {
                "candidate_id": "candidate-1",
                "pin_binding": "pin-1",
                "source_ids": [row["source_id"] for row in rows],
                "root_cause": "missing state update",
                "affected_path": "src/Vault.sol:42",
                "required_fix": "update state before interaction",
                "reviewer_rationale": "All known sources establish awareness.",
                "semantic_review": {
                    "reviewer_id": "reviewer-1",
                    "reviewed_at": "2026-07-18T00:00:00Z",
                    "method": "semantic comparison",
                    "rationale": "Compared root cause, path, and fix.",
                    "source_ids": [row["source_id"] for row in rows],
                },
            }
        ],
    }


def write_discovery(root: Path, value: dict) -> Path:
    path = root / ".auditooor" / "awareness_source_discovery.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema": "auditooor.awareness_source_discovery.v1",
        "audit_pin": value["audit_pin"],
        "coverage": {
            kind: {"status": "complete"}
            for kind in GATE._load_awareness_module().SOURCE_KINDS
        },
        "sources": value["expected_sources"],
    }), encoding="utf-8")
    return path


class PriorHistoryAwarenessGateTests(unittest.TestCase):
    def test_builds_receiptable_ledger_only_from_complete_semantic_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            output = root / ".auditooor" / "awareness_ledger.json"
            value = complete_manifest()
            manifest.write_text(json.dumps(value), encoding="utf-8")
            write_discovery(root, value)
            result = GATE.build_awareness_ledger(root, manifest, output)
            self.assertFalse(result["fail_closed"])
            self.assertEqual(result["candidates"][0]["state"], "team_aware")
            self.assertTrue(output.is_file())

    def test_partial_history_cannot_produce_a_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            output = root / ".auditooor" / "awareness_ledger.json"
            value = complete_manifest()
            value["evidence_rows"].pop()
            manifest.write_text(json.dumps(value), encoding="utf-8")
            write_discovery(root, value)
            with self.assertRaisesRegex(ValueError, "awareness_ledger_incomplete"):
                GATE.build_awareness_ledger(root, manifest, output)
            self.assertFalse(output.exists())

    def test_attested_pin_must_match_the_reviewed_history_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            output = root / ".auditooor" / "awareness_ledger.json"
            value = complete_manifest()
            manifest.write_text(json.dumps(value), encoding="utf-8")
            write_discovery(root, value)
            with self.assertRaisesRegex(ValueError, "awareness_ledger_attestation_pin_mismatch"):
                GATE.build_awareness_ledger(root, manifest, output, expected_pin="different-pin")
            self.assertFalse(output.exists())

    def test_unreviewed_discovered_source_blocks_receiptable_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            output = root / ".auditooor" / "awareness_ledger.json"
            value = complete_manifest()
            value["expected_sources"].append({
                "source_id": "commit-unreviewed",
                "source_kind": "commit",
                "source_ref": "https://github.example/commit/unreviewed",
                "pin_binding": "pin-1",
            })
            manifest.write_text(json.dumps(value), encoding="utf-8")
            write_discovery(root, value)
            with self.assertRaisesRegex(ValueError, "awareness_ledger_incomplete"):
                GATE.build_awareness_ledger(root, manifest, output)

    def test_manifest_cannot_substitute_a_hand_authored_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            output = root / ".auditooor" / "awareness_ledger.json"
            value = complete_manifest()
            write_discovery(root, value)
            value["expected_sources"] = value["expected_sources"][:-1]
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "awareness_manifest_inventory_mismatch"):
                GATE.build_awareness_ledger(root, manifest, output)


if __name__ == "__main__":
    unittest.main()
