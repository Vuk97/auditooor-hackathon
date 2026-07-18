#!/usr/bin/env python3
"""Focused regression tests for memory-context-load receipt proofs."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_tool(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


LOAD = _load_tool("memory_context_load_receipt_tests", REPO_ROOT / "tools" / "memory-context-load.py")


class MemoryContextLoadReceiptProofTest(unittest.TestCase):
    def _requirements_doc(self, ws: Path) -> dict:
        return {
            "schema": LOAD.REQ_SCHEMA,
            "workspace": "demo",
            "workspace_path": str(ws),
            "generated_at": "2026-05-06T00:00:00Z",
            "generator": "tools/memory-auto-link.py",
            "workspace_facts": {"languages": ["unknown"], "artifact_predicates": [], "newest_input_mtime": 0},
            "requirements": [
                {
                    "requirement_id": "base.resume",
                    "context_kind": "resume",
                    "tool": "vault_resume_context",
                    "args": {"workspace_path": str(ws), "limit": 8},
                    "required_by": ["flow-gate", "closeout"],
                    "reason": "resume",
                    "matched_predicates": ["workspace_exists"],
                    "fresh_after_refs": [],
                    "strictness": "warn_default",
                }
            ],
        }

    def _valid_resume_pack(self) -> dict:
        body = {
            "schema": "auditooor.vault_context_pack.v1",
            "kind": "resume",
            "source_refs": ["docs/VAULT_MCP_SERVER.md"],
            "knowledge_gap_refs": [],
        }
        digest = LOAD.sha256_text(LOAD.canonical_json(body))
        return {
            "context_pack_id": f"auditooor.vault_context_pack.v1:resume:{digest[:16]}",
            "context_pack_hash": digest,
            **body,
        }

    def _receipt_doc(self, ws: Path, req_path: Path, pack_path: Path, pack: dict) -> dict:
        req_doc = self._requirements_doc(ws)
        return {
            "schema": LOAD.RECEIPT_SCHEMA,
            "workspace": "demo",
            "workspace_path": str(ws),
            "generated_at": "2026-05-06T00:01:00Z",
            "loader": {
                "tool": LOAD.LOADER,
                "command": "python3 tools/memory-context-load.py --workspace demo --from-requirements --write-receipt",
                "argv_hash": "0" * 64,
            },
            "requirements_path": str(req_path),
            "requirements_hash": LOAD.sha256_file(req_path),
            "loaded_contexts": [
                {
                    "requirement_id": "base.resume",
                    "context_kind": "resume",
                    "tool": "vault_resume_context",
                    "args_hash": LOAD.sha256_text(LOAD.canonical_json(req_doc["requirements"][0]["args"])),
                    "context_pack_id": pack["context_pack_id"],
                    "context_pack_hash": pack["context_pack_hash"],
                    "pack_path": str(pack_path),
                    "pack_schema": pack["schema"],
                    "loaded_at": "2026-05-06T00:02:00Z",
                    "status": "loaded",
                    "source_refs": ["docs/VAULT_MCP_SERVER.md"],
                    "knowledge_gap_refs": [],
                }
            ],
            "missing_contexts": [],
            "summary": {
                "required_count": 1,
                "loaded_count": 1,
                "missing_count": 0,
                "stale_count": 0,
                "strict_ready": True,
            },
        }

    def test_load_from_requirements_writes_receipt_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-load-proof-") as tmp:
            ws = Path(tmp)
            req_doc = self._requirements_doc(ws)
            req_path = LOAD.requirements_path(ws)
            req_path.parent.mkdir(parents=True)
            req_path.write_text(json.dumps(req_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            with mock.patch.object(LOAD, "run_mcp_tool", return_value=(self._valid_resume_pack(), None)):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = LOAD.main(
                        ["--workspace", str(ws), "--from-requirements", "--write-receipt", "--json"]
                    )

            self.assertEqual(rc, 0, buf.getvalue())
            receipt = json.loads(LOAD.receipt_path(ws).read_text(encoding="utf-8"))
            self.assertEqual(receipt["receipt_proof"], LOAD.expected_receipt_proof(receipt))

    def test_check_receipt_can_require_receipt_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-load-proof-") as tmp:
            ws = Path(tmp)
            req_doc = self._requirements_doc(ws)
            req_path = LOAD.requirements_path(ws)
            req_path.parent.mkdir(parents=True)
            req_path.write_text(json.dumps(req_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            pack = self._valid_resume_pack()
            pack_path = LOAD.write_pack(ws, pack)
            receipt = self._receipt_doc(ws, req_path, pack_path, pack)
            LOAD.receipt_path(ws).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            rc, summary = LOAD.check_receipt(ws, require_proof=True)

            self.assertEqual(rc, 1)
            self.assertEqual(summary["status"], "invalid")
            self.assertEqual(summary["receipt_proof_status"], "missing")
            self.assertEqual(summary["invalid_contexts"][0]["reason"], "receipt_proof missing")

    def test_check_receipt_reports_valid_receipt_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-load-proof-") as tmp:
            ws = Path(tmp)
            req_doc = self._requirements_doc(ws)
            req_path = LOAD.requirements_path(ws)
            req_path.parent.mkdir(parents=True)
            req_path.write_text(json.dumps(req_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            pack = self._valid_resume_pack()
            pack_path = LOAD.write_pack(ws, pack)
            receipt = self._receipt_doc(ws, req_path, pack_path, pack)
            receipt["receipt_proof"] = LOAD.expected_receipt_proof(receipt)
            LOAD.receipt_path(ws).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = LOAD.main(["--workspace", str(ws), "--check", "--require-proof", "--json"])

            self.assertEqual(rc, 0, buf.getvalue())
            summary = json.loads(buf.getvalue())
            self.assertEqual(summary["status"], "ok")
            self.assertEqual(summary["receipt_proof_status"], "valid")
            self.assertEqual(summary["receipt_proof"], receipt["receipt_proof"])

    def test_check_receipt_requires_hm_artifact_source_ref_coverage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-load-proof-") as tmp:
            ws = Path(tmp)
            req_doc = self._requirements_doc(ws)
            req_path = LOAD.requirements_path(ws)
            req_path.parent.mkdir(parents=True)
            req_path.write_text(json.dumps(req_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            final_dir = ws / "submissions" / "final_cantina_paste"
            final_dir.mkdir(parents=True)
            (final_dir / "finding.md").write_text("# Finding\n\nSeverity: Medium\n", encoding="utf-8")
            pack = self._valid_resume_pack()
            pack_path = LOAD.write_pack(ws, pack)
            receipt = self._receipt_doc(ws, req_path, pack_path, pack)
            receipt["receipt_proof"] = LOAD.expected_receipt_proof(receipt)
            LOAD.receipt_path(ws).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            rc, summary = LOAD.check_receipt(ws, strict=True, require_proof=True)

            self.assertEqual(rc, 1)
            self.assertEqual(summary["status"], "incomplete")
            self.assertEqual(
                summary["missing_contexts"][0]["artifact_ref"],
                "workspace:submissions/final_cantina_paste/finding.md",
            )
            self.assertIn("source_refs coverage", summary["missing_contexts"][0]["reason"])

    def test_check_receipt_accepts_hm_artifact_when_source_ref_is_traced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-load-proof-") as tmp:
            ws = Path(tmp)
            req_doc = self._requirements_doc(ws)
            req_path = LOAD.requirements_path(ws)
            req_path.parent.mkdir(parents=True)
            req_path.write_text(json.dumps(req_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            final_dir = ws / "submissions" / "final_cantina_paste"
            final_dir.mkdir(parents=True)
            (final_dir / "finding.md").write_text("# Finding\n\nSeverity: Medium\n", encoding="utf-8")
            pack = self._valid_resume_pack()
            pack["source_refs"] = [
                "workspace:submissions/final_cantina_paste/finding.md",
                "docs/VAULT_MCP_SERVER.md",
            ]
            pack["context_pack_hash"] = LOAD.expected_pack_hash(pack)
            pack["context_pack_id"] = f"auditooor.vault_context_pack.v1:resume:{pack['context_pack_hash'][:16]}"
            pack_path = LOAD.write_pack(ws, pack)
            receipt = self._receipt_doc(ws, req_path, pack_path, pack)
            receipt["loaded_contexts"][0]["context_pack_id"] = pack["context_pack_id"]
            receipt["loaded_contexts"][0]["context_pack_hash"] = pack["context_pack_hash"]
            receipt["loaded_contexts"][0]["source_refs"] = pack["source_refs"]
            receipt["receipt_proof"] = LOAD.expected_receipt_proof(receipt)
            LOAD.receipt_path(ws).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            rc, summary = LOAD.check_receipt(ws, strict=True, require_proof=True)

            self.assertEqual(rc, 0)
            self.assertEqual(summary["status"], "ok")
            self.assertEqual(summary["missing_contexts"], [])

    def test_check_receipt_requires_root_final_cantina_paste_source_ref(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-load-proof-") as tmp:
            ws = Path(tmp)
            req_doc = self._requirements_doc(ws)
            req_path = LOAD.requirements_path(ws)
            req_path.parent.mkdir(parents=True)
            req_path.write_text(json.dumps(req_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            final_dir = ws / "final_cantina_paste"
            final_dir.mkdir(parents=True)
            (final_dir / "finding.md").write_text("# Finding\n\nSeverity: Medium\n", encoding="utf-8")
            pack = self._valid_resume_pack()
            pack_path = LOAD.write_pack(ws, pack)
            receipt = self._receipt_doc(ws, req_path, pack_path, pack)
            receipt["receipt_proof"] = LOAD.expected_receipt_proof(receipt)
            LOAD.receipt_path(ws).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            rc, summary = LOAD.check_receipt(ws, strict=True, require_proof=True)

            self.assertEqual(rc, 1)
            self.assertEqual(
                summary["missing_contexts"][0]["artifact_ref"],
                "workspace:final_cantina_paste/finding.md",
            )


if __name__ == "__main__":
    unittest.main()
