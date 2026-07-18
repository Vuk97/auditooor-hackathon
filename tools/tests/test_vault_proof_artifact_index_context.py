from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_proof_artifact_index_test",
        MODULE_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


class ProofArtifactIndexContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-proof-artifact-index-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.sidecar = self.root / "audit" / "corpus_tags" / "derived" / "proof_artifact_index.jsonl"
        self.sidecar.parent.mkdir(parents=True)
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_rows(self, rows: list[dict[str, Any]], *, invalid_line: bool = False) -> None:
        lines = [json.dumps(row, sort_keys=True) for row in rows]
        if invalid_line:
            lines.append("{not-json")
        self.sidecar.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_filters_by_engagement_confidence_status_and_ranks_top_rows(self) -> None:
        self._write_rows(
            [
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "engagement": "spark",
                    "submission_path": "audits/spark/submissions/staging/a.md",
                    "submission_status": "staging",
                    "submission_title": "Staging finding",
                    "candidate_proof_path": "audits/spark/poc-tests/a_test.go",
                    "candidate_artifact_exists": True,
                    "candidate_artifact_kind": "poc-tests",
                    "confidence": "high",
                    "confidence_score": 0.8,
                    "match_method": "submission-explicit-path",
                    "source_reasons": ["submission_explicit_reference"],
                    "token_overlap": ["a"],
                },
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "engagement": "spark",
                    "submission_path": "audits/spark/submissions/paste_ready/b.md",
                    "submission_status": "paste_ready",
                    "submission_title": "Paste ready finding",
                    "candidate_proof_path": "audits/spark/poc-tests/b_test.go",
                    "candidate_artifact_exists": True,
                    "candidate_artifact_kind": "poc-tests",
                    "confidence": "high",
                    "confidence_score": 1.0,
                    "match_method": "submission-explicit-path",
                    "source_reasons": ["submission_explicit_reference", "referenced_artifact_exists"],
                    "token_overlap": ["b"],
                },
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "engagement": "base-azul",
                    "submission_path": "audits/base-azul/submissions/root.md",
                    "submission_status": "root",
                    "submission_title": "Other engagement",
                    "candidate_proof_path": "audits/base-azul/poc-tests/c.t.sol",
                    "candidate_artifact_exists": True,
                    "candidate_artifact_kind": "test-file",
                    "confidence": "high",
                    "confidence_score": 1.0,
                    "match_method": "submission-explicit-path",
                    "source_reasons": ["submission_explicit_reference"],
                    "token_overlap": [],
                },
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "engagement": "spark",
                    "submission_path": "audits/spark/submissions/paste_ready/low.md",
                    "submission_status": "paste_ready",
                    "submission_title": "Low confidence",
                    "candidate_proof_path": "audits/spark/poc-tests/low_test.go",
                    "candidate_artifact_exists": True,
                    "candidate_artifact_kind": "poc-tests",
                    "confidence": "low",
                    "confidence_score": 0.2,
                    "match_method": "submission-artifact-token-overlap",
                    "source_reasons": ["weak_filename_token_overlap"],
                    "token_overlap": ["low"],
                },
            ],
            invalid_line=True,
        )

        result = self.vault.vault_proof_artifact_index_context(
            engagement="spark",
            confidence="high",
            status="paste_ready",
            sidecar_path=str(self.sidecar),
            limit=5,
        )

        self.assertEqual(result["schema"], vault_mcp_server.PROOF_ARTIFACT_INDEX_CONTEXT_SCHEMA)
        self.assertFalse(result["degraded"])
        self.assertEqual(result["rows_total"], 4)
        self.assertEqual(result["rows_matched"], 1)
        self.assertEqual(result["rows_returned"], 1)
        self.assertEqual(result["sidecar_metadata"]["rows"], 4)
        self.assertEqual(result["sidecar_metadata"]["invalid_rows"], 1)
        self.assertEqual(result["sidecar_metadata"]["freshness_class"], "fresh")
        self.assertEqual(result["sidecar_metadata"]["freshness_basis"], "mtime")
        self.assertTrue(result["sidecar_metadata"]["mtime_utc"])
        self.assertEqual(result["summary"]["invalid_rows_skipped"], 1)
        self.assertEqual(result["summary"]["by_engagement"], {"spark": 1})
        self.assertEqual(result["summary"]["by_confidence"], {"high": 1})
        self.assertEqual(result["summary"]["by_status"], {"paste_ready": 1})
        self.assertEqual(
            result["rows"][0]["candidate_proof_path"],
            "audits/spark/poc-tests/b_test.go",
        )
        self.assertTrue(result["privacy_guards"]["sidecar_only"])
        self.assertFalse(result["privacy_guards"]["raw_file_scan"])
        self.assertEqual(len(result["context_pack_hash"]), 64)

    def test_workspace_path_basename_filters_engagement_and_exists_only(self) -> None:
        self._write_rows(
            [
                {
                    "engagement": "dydx",
                    "submission_path": "audits/dydx/submissions/root.md",
                    "submission_status": "root",
                    "submission_title": "Missing artifact",
                    "candidate_proof_path": "audits/dydx/results/missing.log",
                    "candidate_artifact_exists": False,
                    "candidate_artifact_kind": "execution-output",
                    "confidence": "medium",
                    "confidence_score": 0.72,
                    "match_method": "submission-explicit-path",
                    "source_reasons": ["referenced_artifact_missing_locally"],
                    "token_overlap": [],
                },
                {
                    "engagement": "dydx",
                    "submission_path": "audits/dydx/submissions/paste_ready/proved.md",
                    "submission_status": "paste_ready",
                    "submission_title": "Existing artifact",
                    "candidate_proof_path": "audits/dydx/poc-tests/proved_test.go",
                    "candidate_artifact_exists": True,
                    "candidate_artifact_kind": "poc-tests",
                    "confidence": "medium",
                    "confidence_score": 0.6,
                    "match_method": "submission-artifact-token-overlap",
                    "source_reasons": ["strong_filename_token_overlap"],
                    "token_overlap": ["proved"],
                },
            ]
        )

        result = self.vault.vault_proof_artifact_index_context(
            workspace_path=str(self.root / "dydx"),
            exists_only=True,
            sidecar_path=str(self.sidecar),
        )

        self.assertFalse(result["degraded"])
        self.assertEqual(result["filter"]["engagement"], "dydx")
        self.assertEqual(result["rows_matched"], 1)
        self.assertEqual(result["rows"][0]["candidate_proof_path"], "audits/dydx/poc-tests/proved_test.go")

    def test_missing_sidecar_degrades_without_rows(self) -> None:
        result = self.vault.vault_proof_artifact_index_context(
            sidecar_path=str(self.root / "missing.jsonl"),
        )

        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "proof_artifact_index_sidecar_missing")
        self.assertEqual(result["sidecar_metadata"]["freshness_class"], "missing")
        self.assertEqual(result["sidecar_metadata"]["rows"], 0)
        self.assertEqual(result["rows"], [])
        self.assertTrue(result["privacy_guards"]["sidecar_only"])

    def test_sidecar_metadata_prefers_generated_at_for_freshness(self) -> None:
        self._write_rows(
            [
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "generated_at": "2000-01-01T00:00:00Z",
                    "engagement": "spark",
                    "submission_path": "audits/spark/submissions/root.md",
                    "submission_status": "root",
                    "submission_title": "Root finding",
                    "candidate_proof_path": "audits/spark/poc-tests/root_test.go",
                    "candidate_artifact_exists": True,
                    "candidate_artifact_kind": "poc-tests",
                    "confidence": "high",
                    "confidence_score": 1.0,
                    "match_method": "submission-explicit-path",
                    "source_reasons": ["submission_explicit_reference"],
                    "token_overlap": [],
                }
            ]
        )

        result = self.vault.vault_proof_artifact_index_context(sidecar_path=str(self.sidecar))

        self.assertFalse(result["degraded"])
        self.assertEqual(result["rows_total"], 1)
        self.assertEqual(result["sidecar_metadata"]["rows"], 1)
        self.assertEqual(result["sidecar_metadata"]["generated_at"], "2000-01-01T00:00:00Z")
        self.assertEqual(result["sidecar_metadata"]["freshness_basis"], "generated_at")
        self.assertEqual(result["sidecar_metadata"]["freshness_class"], "stale")

    def test_dispatch_and_tool_schema_registration(self) -> None:
        self._write_rows(
            [
                {
                    "engagement": "spark",
                    "submission_path": "audits/spark/submissions/root.md",
                    "submission_status": "root",
                    "submission_title": "Root finding",
                    "candidate_proof_path": "audits/spark/poc-tests/root_test.go",
                    "candidate_artifact_exists": True,
                    "candidate_artifact_kind": "poc-tests",
                    "confidence": "high",
                    "confidence_score": 1.0,
                    "match_method": "submission-explicit-path",
                    "source_reasons": ["submission_explicit_reference"],
                    "token_overlap": [],
                }
            ]
        )

        dispatched = self.vault._dispatch(
            "vault_proof_artifact_index_context",
            {"sidecar_path": str(self.sidecar), "engagement": "spark"},
        )
        self.assertEqual(dispatched["rows_returned"], 1)
        names = {tool["name"] for tool in vault_mcp_server.TOOL_SCHEMAS}
        self.assertIn("vault_proof_artifact_index_context", names)


if __name__ == "__main__":
    unittest.main()
