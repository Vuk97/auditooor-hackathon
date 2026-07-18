from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "semantic_engine_substrate", ROOT / "tools" / "semantic-engine-substrate.py"
)
TOOL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(TOOL)


class SemanticEngineSubstrateTest(unittest.TestCase):
    def build_workspace(self, language: str = "go"):
        root = tempfile.TemporaryDirectory()
        ws = Path(root.name)
        rel = {"go": "src/app.go", "rust": "src/lib.rs", "solidity": "src/Vault.sol"}[language]
        source = ws / rel
        source.parent.mkdir(parents=True)
        source.write_text("source\n", encoding="utf-8")
        audit = ws / ".auditooor"
        audit.mkdir()
        (audit / "inscope_units.jsonl").write_text(json.dumps({"file": rel, "lang": language}) + "\n", encoding="utf-8")
        files, source_hash = TOOL._inventory(ws, language)
        backend = {"go": "go-ssa", "rust": "rustc-mir", "solidity": "slither"}[language]
        receipt = {
            "receipt_schema": "auditooor.language_backend_receipt.v1", "language": language,
            "status": "pass", "confidence": "semantic-ssa", "backend": backend,
            "source_set_sha256": source_hash, "inventory_unit_count": len(files),
            "examined_empty": False,
            "execution": {
                "argv": ["backend"], "executable": "backend", "returncode": 0,
                "command_sha256": "a" * 64, "stdout_sha256": "b" * 64,
                "stderr_sha256": "c" * 64, "artifact_kind": f"{backend.replace('rustc-', '')}-semantic-rows",
                "artifact_sha256": "",
            },
        }
        receipts = audit / "language_backend_receipts"
        receipts.mkdir()
        (receipts / "dataflow.jsonl").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
        aliases = TOOL.EXPECTATIONS[language][1]
        record = TOOL.DATAFLOW.new_path(
            "semantic-1", next(iter(aliases)), "backward", backend,
            {"kind": "param", "fn": "f", "var": "x", "file": rel, "line": 1},
            {"kind": "transfer", "callee": "send", "arg_pos": 0, "fn": "f", "file": rel, "line": 1}, [],
        )
        (audit / "dataflow_paths.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
        receipt["execution"]["artifact_sha256"] = TOOL._record_digest([record])
        (receipts / "dataflow.jsonl").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
        return root, ws

    def test_build_requires_current_semantic_receipt_and_writes_contract(self):
        root, ws = self.build_workspace()
        with root:
            result = TOOL.build(ws, "go", ws / ".auditooor/out.json", ws / ".auditooor/out.jsonl")
            self.assertEqual(result["schema"], TOOL.SCHEMA)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["record_count"], 1)
            self.assertFalse(result["degraded"])

    def test_stale_source_receipt_is_rejected(self):
        root, ws = self.build_workspace("rust")
        with root:
            receipt = ws / ".auditooor/language_backend_receipts/dataflow.jsonl"
            row = json.loads(receipt.read_text())
            row["source_set_sha256"] = "0" * 64
            receipt.write_text(json.dumps(row) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(TOOL.SubstrateError, "source_snapshot_stale"):
                TOOL.build(ws, "rust", ws / ".auditooor/out.json", ws / ".auditooor/out.jsonl")

    def test_current_strict_producer_receipt_shape_is_accepted(self):
        root, ws = self.build_workspace("solidity")
        with root:
            receipt = ws / ".auditooor/language_backend_receipts/dataflow.jsonl"
            row = json.loads(receipt.read_text())
            self.assertIn("receipt_schema", row)
            self.assertNotIn("schema", row)
            result = TOOL.build(ws, "solidity", ws / ".auditooor/out.json", ws / ".auditooor/out.jsonl")
            self.assertEqual("passed", result["status"])

    def test_shape_rows_cannot_be_packaged_as_semantic_engine_evidence(self):
        root, ws = self.build_workspace("solidity")
        with root:
            paths = ws / ".auditooor/dataflow_paths.jsonl"
            row = json.loads(paths.read_text())
            row["confidence"] = "syntactic"
            paths.write_text(json.dumps(row) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(TOOL.SubstrateError, "nonsemantic_dataflow_row"):
                TOOL.build(ws, "solidity", ws / ".auditooor/out.json", ws / ".auditooor/out.jsonl")

    def test_semantic_receipt_requires_execution_provenance(self):
        root, ws = self.build_workspace("go")
        with root:
            receipt = ws / ".auditooor/language_backend_receipts/dataflow.jsonl"
            row = json.loads(receipt.read_text())
            row.pop("execution")
            receipt.write_text(json.dumps(row) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(TOOL.SubstrateError, "execution_missing"):
                TOOL.build(ws, "go", ws / ".auditooor/out.json", ws / ".auditooor/out.jsonl")

    def test_semantic_receipt_cannot_reuse_another_runs_artifact_digest(self):
        root, ws = self.build_workspace("rust")
        with root:
            receipt = ws / ".auditooor/language_backend_receipts/dataflow.jsonl"
            row = json.loads(receipt.read_text())
            row["execution"]["artifact_sha256"] = "e" * 64
            receipt.write_text(json.dumps(row) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(TOOL.SubstrateError, "artifact_mismatch"):
                TOOL.build(ws, "rust", ws / ".auditooor/out.json", ws / ".auditooor/out.jsonl")


if __name__ == "__main__":
    unittest.main()
