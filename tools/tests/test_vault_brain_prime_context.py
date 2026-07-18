"""Tests for the vault_brain_prime_context MCP callable."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_brain_prime", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp = _load_module()


def _make_vault(repo_root: Path):
    vault_dir = repo_root / "obsidian-vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_mcp.VaultQuery(vault_dir, repo_root)


def _write_receipt(workspace: Path, *, lanes: int = 2, tamper_hash: bool = False) -> None:
    (workspace / ".auditooor").mkdir(parents=True, exist_ok=True)
    report_text = "# Brain Priming Report\n\nfixture lane summary\n"
    report_path = workspace / "BRAIN_PRIMING_REPORT.md"
    report_path.write_text(report_text, encoding="utf-8")
    receipt = {
        "schema": "auditooor.brain_prime_receipt.v1",
        "generated_at": "2026-05-17T10:00:00Z",
        "generated_ts": 1747476000,
        "tool": "tools/brain-prime.py",
        "workspace_path": str(workspace.resolve()),
        "engagement": workspace.name,
        "audit_pin": "cafebabe",
        "target_repo": "owner/repo",
        "report_path": str(report_path.resolve()),
        "report_sha256": hashlib.sha256(report_text.encode("utf-8")).hexdigest(),
        "report_mtime_epoch": report_path.stat().st_mtime,
        "scope_globs": "external/**/*.go",
        "scope_globs_hash": "scope-hash-1",
        "scope": {
            "language": "go",
            "auto_detected": True,
            "candidate_dirs": [str((workspace / "external" / "v4-chain").resolve())],
        },
        "corpus_tag_hash": "tag-hash-1",
        "context_pack_id": "ctx-123",
        "context_pack_hash": "hash-123",
        "mcp": {
            "skipped": False,
            "callables_attempted": 10,
            "callables_succeeded": 8,
            "callables_failed": ["vault_goal_state", "vault_next_loop"],
            "duration_seconds": 2.75,
        },
        "summary": {
            "functions_extracted": 11,
            "phase_d_files": 4,
            "phase_e_sources": 3,
            "phase_f_lanes": lanes,
            "strict_ready": True,
            "top_functions_per_file": 5,
            "min_confidence": 0.4,
            "max_files": 20,
        },
        "top_phase_f_lanes": [
            {
                "lane_id": f"LANE-{idx}",
                "attack_class": f"class-{idx}",
                "max_confidence": 0.9 - (idx * 0.1),
                "severity_guess": "HIGH",
                "provenance": "fixture",
            }
            for idx in range(1, lanes + 1)
        ],
    }
    receipt_hash = hashlib.sha256(
        json.dumps(
            {k: v for k, v in receipt.items() if k != "receipt_hash"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    receipt["receipt_hash"] = "bad-hash" if tamper_hash else receipt_hash
    (workspace / ".auditooor" / "brain_prime_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class TestVaultBrainPrimeContext(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-brain-prime-")
        self.root = Path(self.tmp.name)
        self.vault = _make_vault(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_missing_workspace_returns_degraded_envelope(self) -> None:
        result = self.vault.vault_brain_prime_context(workspace_path=str(self.root / "missing-ws"))
        self.assertEqual(result["schema"], vault_mcp.BRAIN_PRIME_CONTEXT_SCHEMA)
        self.assertTrue(result["degraded"])
        self.assertEqual(result["error"], "workspace_not_found")
        self.assertFalse(result["receipt_found"])

    def test_valid_receipt_returns_bounded_summary_and_no_absolute_path_leak(self) -> None:
        ws = self.root / "spark"
        ws.mkdir()
        _write_receipt(ws, lanes=2)
        result = self.vault.vault_brain_prime_context(workspace_path=str(ws))
        self.assertFalse(result["degraded"])
        self.assertTrue(result["dispatch_ready"])
        self.assertEqual(result["workspace"], "spark")
        self.assertEqual(result["summary"]["functions_extracted"], 11)
        self.assertEqual(result["mcp"]["callables_failed_count"], 2)
        self.assertEqual(result["scope"]["candidate_dir_count"], 1)
        self.assertEqual(result["receipt_path"], "workspace:.auditooor/brain_prime_receipt.json")
        self.assertEqual(result["report_path"], "workspace:BRAIN_PRIMING_REPORT.md")
        self.assertEqual(len(result["top_phase_f_lanes"]), 2)
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(ws.resolve()), serialized)
        self.assertNotIn(str((ws / "external").resolve()), serialized)

    def test_limit_caps_top_phase_f_lanes(self) -> None:
        ws = self.root / "spark-limit"
        ws.mkdir()
        _write_receipt(ws, lanes=4)
        result = self.vault.vault_brain_prime_context(workspace_path=str(ws), limit=2)
        self.assertEqual(result["lanes_returned"], 2)
        self.assertEqual([row["lane_id"] for row in result["top_phase_f_lanes"]], ["LANE-1", "LANE-2"])

    def test_invalid_receipt_hash_clears_dispatch_ready(self) -> None:
        ws = self.root / "spark-bad-hash"
        ws.mkdir()
        _write_receipt(ws, tamper_hash=True)
        result = self.vault.vault_brain_prime_context(workspace_path=str(ws))
        self.assertFalse(result["integrity"]["receipt_hash_valid"])
        self.assertFalse(result["dispatch_ready"])


if __name__ == "__main__":
    unittest.main()
