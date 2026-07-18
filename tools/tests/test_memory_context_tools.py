#!/usr/bin/env python3
"""Regression tests for memory-auto-link and memory-context-load."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_tool(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


AUTO = _load_tool("memory_auto_link", REPO_ROOT / "tools" / "memory-auto-link.py")
LOAD = _load_tool("memory_context_load", REPO_ROOT / "tools" / "memory-context-load.py")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class MemoryAutoLinkTest(unittest.TestCase):
    def test_workspace_memory_schema_allows_emitted_languages(self) -> None:
        schema = json.loads(
            (REPO_ROOT / "docs" / "schemas" / "workspace_memory_requirements.v1.json").read_text(
                encoding="utf-8"
            )
        )
        allowed = set(schema["properties"]["workspace_facts"]["properties"]["languages"]["items"]["enum"])

        self.assertTrue(set(AUTO.LANG_EXT.values()).issubset(allowed))
        self.assertIn("soroban", allowed)
        self.assertIn("unknown", allowed)

    def test_k2_shaped_workspace_gets_expected_requirements(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-auto-") as tmp:
            ws = Path(tmp)
            _write(ws / "AUDIT.md", "# K2\nCode4rena lending Soroban workspace\n")
            _write(ws / "FINDINGS.md", "# Findings\n")
            _write(ws / "SESSION_LOG.md", "# Session\n")
            _write(ws / "SCOPE.md", "# Scope\nSoroban Rust C4 PoC required\n")
            _write(ws / "OOS_CHECKLIST.md", "- [ ] **OOS-1** V12 findings\n")
            _write(ws / "SEVERITY_CAPS.md", "# Severity\nHigh/Medium only\n")
            _write(ws / "PRIOR_CONCERNS.md", "# Prior\n")
            _write(ws / "SCAN_REPORT.md", "# Scan\n")
            _write(ws / "PATTERN_HITS.md", "# Hits\n")
            _write(
                ws / "engage_report.md",
                "# Engagement Report\n\n"
                "- Total hits: **1**\n"
                "- Severity: HIGH=1  MEDIUM=0  LOW=0\n"
                "- Distinct detectors: **1**\n"
                "- Analogical clusters: **1**\n",
            )
            _write(ws / "src/contracts/router/src/lib.rs", "pub fn router() {}\n")
            _write(ws / "src/tests/c4/src/lib.rs", "#[test]\nfn test_submission_validity() {}\n")
            _write(ws / "swarm/brief_candidates.json", '[{"id":"B1"}]\n')

            doc = AUTO.build_requirements(ws)
            ids = {req["requirement_id"] for req in doc["requirements"]}

            self.assertIn("base.resume", ids)
            self.assertIn("base.knowledge-gap", ids)
            self.assertIn("audit.engage-report", ids)
            self.assertIn("exploit.surface", ids)
            self.assertIn("harness.language", ids)
            self.assertIn("prior.oos", ids)
            self.assertEqual(doc["workspace_facts"]["platform"], "code4rena")
            self.assertIn("rust", doc["workspace_facts"]["languages"])
            self.assertIn("soroban", doc["workspace_facts"]["languages"])
            self.assertEqual(AUTO.validate_requirements(doc), [])

    def test_go_workspace_gets_go_memory_requirements(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-auto-go-") as tmp:
            ws = Path(tmp)
            _write(ws / "AUDIT.md", "# Spark\nGo Bitcoin Statechain FROST target\n")
            _write(ws / "FINDINGS.md", "# Findings\n")
            _write(ws / "SESSION_LOG.md", "# Session\n")
            _write(ws / "SCOPE.md", "# Scope\nImmunefi Go backend, Bitcoin, FROST, Lightning\n")
            _write(ws / "OOS_CHECKLIST.md", "- [ ] malicious operators\n")
            _write(ws / "SEVERITY_CAPS.md", "# Severity\nCritical direct loss\n")
            _write(ws / "targets.tsv", "external/spark\n")
            _write(ws / "external/spark/spark/so/handler/coop_exit_handler.go", "package handler\n")

            doc = AUTO.build_requirements(ws)
            ids = {req["requirement_id"] for req in doc["requirements"]}

            self.assertIn("go", doc["workspace_facts"]["languages"])
            self.assertIn("harness.language", ids)
            self.assertIn("language.go.surface", ids)
            self.assertIn("language.go.patterns", ids)
            self.assertEqual(doc["workspace_facts"]["platform"], "immunefi")
            self.assertEqual(doc["workspace_facts"]["protocol_family"], "bitcoin-statechain")
            self.assertEqual(AUTO.validate_requirements(doc), [])

    def test_check_missing_is_warn_by_default_fail_when_strict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-auto-") as tmp:
            ws = Path(tmp)
            rc, summary = AUTO.check_existing(ws, strict=False)
            self.assertEqual(rc, 2)
            self.assertEqual(summary["status"], "missing")
            rc, summary = AUTO.check_existing(ws, strict=True)
            self.assertEqual(rc, 1)
            self.assertEqual(summary["status"], "missing")


class MemoryContextLoadTest(unittest.TestCase):
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

    def _valid_engage_report_pack(self, ws: Path) -> dict:
        body = {
            "schema": "auditooor.vault_engage_report_context.v1",
            "kind": "engage_report_context",
            "workspace_path": str(ws),
            "report_path": str(ws / "engage_report.md"),
            "report_found": True,
            "total_hits": 1,
            "distinct_detectors": 1,
            "analogical_clusters": 1,
            "severity_summary": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
            "actionable_next_steps": {"triage": 1, "dupe_check": 0, "mine": 1},
            "clusters": [],
            "limit": 12,
            "clusters_returned": 0,
            "privacy_guards": [],
        }
        digest = LOAD.sha256_text(LOAD.canonical_json(body))
        return {
            "context_pack_id": f"auditooor.vault_engage_report_context.v1:engage_report:{digest[:16]}",
            "context_pack_hash": digest,
            **body,
        }

    def test_receipt_check_validates_pack_hash_and_requirement_coverage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-load-") as tmp:
            ws = Path(tmp)
            req = {
                "schema": "auditooor.workspace_memory_requirements.v1",
                "workspace": "demo",
                "workspace_path": str(ws),
                "generated_at": "2026-05-06T00:00:00Z",
                "generator": "tools/memory-auto-link.py",
                "workspace_facts": {"languages": ["unknown"], "artifact_predicates": [], "newest_input_mtime": None},
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
            req_path = LOAD.requirements_path(ws)
            req_path.parent.mkdir(parents=True)
            req_path.write_text(json.dumps(req, indent=2, sort_keys=True) + "\n")
            pack = self._valid_resume_pack()
            pack_path = LOAD.write_pack(ws, pack)
            receipt = {
                "schema": "auditooor.memory_context_receipt.v1",
                "workspace": "demo",
                "workspace_path": str(ws),
                "generated_at": "2026-05-06T00:01:00Z",
                "loader": {
                    "tool": "tools/memory-context-load.py",
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
                        "args_hash": LOAD.sha256_text(LOAD.canonical_json(req["requirements"][0]["args"])),
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
            LOAD.receipt_path(ws).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")

            rc, summary = LOAD.check_receipt(ws)

            self.assertEqual(rc, 0, summary)
            self.assertEqual(summary["status"], "ok")

    def test_receipt_check_accepts_engage_report_context_pack(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-load-engage-") as tmp:
            ws = Path(tmp)
            _write(ws / "engage_report.md", "# Engagement Report\n")
            req = {
                "schema": "auditooor.workspace_memory_requirements.v1",
                "workspace": "demo",
                "workspace_path": str(ws),
                "generated_at": "2026-05-06T00:00:00Z",
                "generator": "tools/memory-auto-link.py",
                "workspace_facts": {"languages": ["unknown"], "artifact_predicates": ["has_engage_report"], "newest_input_mtime": None},
                "requirements": [
                    {
                        "requirement_id": "audit.engage-report",
                        "context_kind": "engage_report_context",
                        "tool": "vault_engage_report_context",
                        "args": {"workspace_path": str(ws), "limit": 12},
                        "required_by": ["scan", "dispatch", "audit-deep", "closeout"],
                        "reason": "detector clusters",
                        "matched_predicates": ["has_engage_report"],
                        "fresh_after_refs": ["engage_report.md"],
                        "strictness": "warn_default",
                    }
                ],
            }
            req_path = LOAD.requirements_path(ws)
            req_path.parent.mkdir(parents=True)
            req_path.write_text(json.dumps(req, indent=2, sort_keys=True) + "\n")
            pack = self._valid_engage_report_pack(ws)
            pack_path = LOAD.write_pack(ws, pack)
            receipt = {
                "schema": "auditooor.memory_context_receipt.v1",
                "workspace": "demo",
                "workspace_path": str(ws),
                "generated_at": "2026-05-06T00:01:00Z",
                "loader": {
                    "tool": "tools/memory-context-load.py",
                    "command": "python3 tools/memory-context-load.py --workspace demo --from-requirements --write-receipt",
                    "argv_hash": "0" * 64,
                },
                "requirements_path": str(req_path),
                "requirements_hash": LOAD.sha256_file(req_path),
                "loaded_contexts": [
                    {
                        "requirement_id": "audit.engage-report",
                        "context_kind": "engage_report_context",
                        "tool": "vault_engage_report_context",
                        "args_hash": LOAD.sha256_text(LOAD.canonical_json(req["requirements"][0]["args"])),
                        "context_pack_id": pack["context_pack_id"],
                        "context_pack_hash": pack["context_pack_hash"],
                        "pack_path": str(pack_path),
                        "pack_schema": pack["schema"],
                        "loaded_at": "2030-05-06T00:02:00Z",
                        "status": "loaded",
                        "source_refs": [],
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
            LOAD.receipt_path(ws).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")

            rc, summary = LOAD.check_receipt(ws)

            self.assertEqual(rc, 0, summary)
            self.assertEqual(summary["status"], "ok")

    def test_missing_receipt_warns_by_default_and_fails_when_strict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-load-") as tmp:
            ws = Path(tmp)
            req = {
                "schema": "auditooor.workspace_memory_requirements.v1",
                "workspace": "demo",
                "workspace_path": str(ws),
                "generated_at": "2026-05-06T00:00:00Z",
                "generator": "tools/memory-auto-link.py",
                "workspace_facts": {"languages": ["unknown"], "artifact_predicates": []},
                "requirements": [
                    {
                        "requirement_id": "base.resume",
                        "context_kind": "resume",
                        "tool": "vault_resume_context",
                        "args": {"workspace_path": str(ws), "limit": 8},
                        "required_by": ["flow-gate"],
                        "reason": "resume",
                        "matched_predicates": ["workspace_exists"],
                        "fresh_after_refs": [],
                        "strictness": "warn_default",
                    }
                ],
            }
            req_path = LOAD.requirements_path(ws)
            req_path.parent.mkdir(parents=True)
            req_path.write_text(json.dumps(req) + "\n")

            rc, summary = LOAD.check_receipt(ws, strict=False)
            self.assertEqual(rc, 2)
            self.assertEqual(summary["status"], "missing_receipt")
            rc, summary = LOAD.check_receipt(ws, strict=True)
            self.assertEqual(rc, 1)
            self.assertEqual(summary["status"], "missing_receipt")

    def test_stale_receipt_names_fresh_after_refs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mem-load-") as tmp:
            ws = Path(tmp)
            stale_ref = ws / "PRIOR_CONCERNS.md"
            _write(stale_ref, "# Prior concerns\n")
            ref_mtime = int(LOAD.parse_utc("2026-05-06T00:03:00Z").timestamp())
            os.utime(stale_ref, (ref_mtime, ref_mtime))
            req = {
                "schema": "auditooor.workspace_memory_requirements.v1",
                "workspace": "demo",
                "workspace_path": str(ws),
                "generated_at": "2026-05-06T00:00:00Z",
                "generator": "tools/memory-auto-link.py",
                "workspace_facts": {"languages": ["go"], "artifact_predicates": [], "newest_input_mtime": 0},
                "requirements": [
                    {
                        "requirement_id": "prior.oos",
                        "context_kind": "resume",
                        "tool": "vault_resume_context",
                        "args": {"workspace_path": str(ws), "limit": 8},
                        "required_by": ["closeout"],
                        "reason": "prior",
                        "matched_predicates": ["has_prior_audits"],
                        "fresh_after_refs": ["PRIOR_CONCERNS.md"],
                        "strictness": "warn_default",
                    }
                ],
            }
            req_path = LOAD.requirements_path(ws)
            req_path.parent.mkdir(parents=True)
            req_path.write_text(json.dumps(req, indent=2, sort_keys=True) + "\n")
            pack = self._valid_resume_pack()
            pack_path = LOAD.write_pack(ws, pack)
            receipt = {
                "schema": "auditooor.memory_context_receipt.v1",
                "workspace": "demo",
                "workspace_path": str(ws),
                "generated_at": "2026-05-06T00:02:00Z",
                "loader": {
                    "tool": "tools/memory-context-load.py",
                    "command": "python3 tools/memory-context-load.py --workspace demo --from-requirements --write-receipt",
                    "argv_hash": "0" * 64,
                },
                "requirements_path": str(req_path),
                "requirements_hash": LOAD.sha256_file(req_path),
                "loaded_contexts": [
                    {
                        "requirement_id": "prior.oos",
                        "context_kind": "resume",
                        "tool": "vault_resume_context",
                        "args_hash": LOAD.sha256_text(LOAD.canonical_json(req["requirements"][0]["args"])),
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
            LOAD.receipt_path(ws).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")

            rc, summary = LOAD.check_receipt(ws)

            self.assertEqual(rc, 2)
            self.assertEqual(summary["status"], "incomplete")
            self.assertEqual(summary["stale_contexts"][0]["requirement_id"], "prior.oos")
            self.assertEqual(summary["stale_contexts"][0]["fresh_after_mtime"], ref_mtime)
            refs = summary["stale_contexts"][0]["fresh_after_refs"]
            self.assertEqual(refs[0]["ref"], "PRIOR_CONCERNS.md")
            self.assertTrue(refs[0]["exists"])
            self.assertEqual(refs[0]["kind"], "file")
            self.assertEqual(refs[0]["mtime"], ref_mtime)


if __name__ == "__main__":
    unittest.main()
