from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_originality_before_proof_gate",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _gate_payload(status: str, *, warnings=None, evidence=None, errors=None) -> dict:
    return {
        "schema": "auditooor.originality_before_proof_gate.v1",
        "status": status,
        "workspace": "/tmp/ws",
        "workspace_name": "ws",
        "keywords": ["affiliate", "blocked"],
        "evidence": list(evidence or []),
        "counts": {
            "keyword_count": 2,
            "vault_hits": 1 if evidence else 0,
            "local_hits": 0,
            "local_files_scanned": 1,
            "local_files_with_hits": 0,
            "strong_hits": 1 if status == "fail" else 0,
            "weak_hits": 1 if status == "warn" else 0,
        },
        "warnings": list(warnings or []),
        "errors": list(errors or []),
        "status_reason": [row["code"] for row in list(warnings or []) + list(errors or [])],
        "source_refs": ["vault://external-audits-extracts/ws/demo.md"],
        "source_scan": [
            "tools/dedup-grep.py",
            "tools/vault-mcp-server.py:vault_originality_context",
        ],
    }


class VaultOriginalityBeforeProofGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-orig-gate-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        self.ws = self.root / "audit-ws"
        self.ws.mkdir()
        self.mod = _load_vault_mcp()
        self.vault = self.mod.VaultQuery(self.vault_dir, repo_root=self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_pass_status_is_preserved(self) -> None:
        gate = SimpleNamespace(_run=lambda *_a, **_k: _gate_payload("pass"))
        with mock.patch.object(self.mod, "_load_tool_module", return_value=gate):
            result = self.vault.vault_originality_before_proof_gate(
                workspace_path=str(self.ws),
                keywords=["affiliate", "blocked"],
            )

        self.assertEqual(result["schema"], self.mod.ORIGINALITY_BEFORE_PROOF_GATE_SCHEMA)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["warnings"], [])
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["context_pack_id"].startswith(self.mod.ORIGINALITY_BEFORE_PROOF_GATE_SCHEMA))

    def test_warn_missing_corpus_is_preserved(self) -> None:
        gate = SimpleNamespace(
            _run=lambda *_a, **_k: _gate_payload(
                "warn",
                warnings=[{"code": "corpus_missing", "message": "no local prior_audits and no prior-audits-extracts corpus"}],
            )
        )
        with mock.patch.object(self.mod, "_load_tool_module", return_value=gate):
            result = self.vault.vault_originality_before_proof_gate(
                workspace_path=str(self.ws),
                keywords=["affiliate"],
            )

        self.assertEqual(result["status"], "warn")
        self.assertTrue(any(row["code"] == "corpus_missing" for row in result["warnings"]))

    def test_fail_strong_duplicate_is_preserved_with_evidence(self) -> None:
        evidence = [
            {
                "source": "prior_audit_extract",
                "strength": "strong",
                "source_ref": "vault://external-audits-extracts/ws/demo.md",
                "finding_id": "M-01",
                "status": "ACK",
                "score": 10,
                "matched_terms": ["affiliate", "blocked"],
                "snippet": "affiliate blocked from recipient",
            }
        ]
        gate = SimpleNamespace(_run=lambda *_a, **_k: _gate_payload("fail", evidence=evidence))
        with mock.patch.object(self.mod, "_load_tool_module", return_value=gate):
            result = self.vault.call(
                "vault_originality_before_proof_gate",
                {
                    "workspace_path": str(self.ws),
                    "keywords": ["affiliate", "blocked"],
                },
            )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["evidence"][0]["strength"], "strong")
        self.assertEqual(result["evidence"][0]["source_ref"], "vault://external-audits-extracts/ws/demo.md")

    def test_validation_error_when_missing_keywords_and_draft(self) -> None:
        result = self.vault.vault_originality_before_proof_gate(workspace_path=str(self.ws))

        self.assertEqual(result["status"], "error")
        self.assertTrue(any(row["code"] == "missing_keywords_or_draft" for row in result["errors"]))

    def test_callable_is_registered(self) -> None:
        names = [tool["name"] for tool in self.mod.TOOL_SCHEMAS]
        self.assertIn("vault_originality_before_proof_gate", names)


if __name__ == "__main__":
    unittest.main()
