"""Tests for vault_global_chain_template_match MCP callable (P3.2).

<!-- r36-rebuttal: pathspec registered via agent-pathspec-register.py for lane LIFT-PHASE-3-CODEX-TAKEOVER -->

Schema asserted: auditooor.vault_global_chain_template_match.v1
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
EXPECTED_SCHEMA = "auditooor.vault_global_chain_template_match.v1"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_global_template_match", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _tpl(
    chain_template_id: str,
    member_ids: list[str],
    *,
    tuple_size: int | None = None,
    score: float = 0.7,
    tier: str = "tier-2-verified-public-archive",
    rationale: str = "test composition",
    evidence: list[str] | None = None,
) -> dict:
    return {
        "schema_version": "auditooor.global_chain_template.v1",
        "chain_template_id": chain_template_id,
        "member_invariant_ids": sorted(member_ids),
        "tuple_size": tuple_size or len(member_ids),
        "composition_score": score,
        "composition_rationale": rationale,
        "verification_tier": tier,
        "evidence_incidents": evidence or [],
        "advisory_only": True,
        "submission_posture": "NOT_SUBMIT_READY",
    }


class VaultGlobalChainTemplateMatchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-gct-match-")
        self.base = Path(self.tmp.name)
        self.vault_dir = self.base / "vault"
        self.repo = self.base / "repo"
        self.ws = self.base / "workspace"
        self.vault_dir.mkdir()
        self.repo.mkdir()
        self.ws.mkdir()
        self.vault_mcp = _load_vault_mcp()
        self.vault = self.vault_mcp.VaultQuery(self.vault_dir, repo_root=self.repo)
        # canonical templates jsonl location relative to repo_root
        self.tpl_path = (
            self.repo
            / "audit"
            / "corpus_tags"
            / "derived"
            / "global_chain_templates.jsonl"
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # --- Test 1: missing workspace_path ---
    def test_missing_workspace_path_returns_error(self) -> None:
        result = self.vault.vault_global_chain_template_match()
        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertEqual(result["error"], "workspace_path_required")
        self.assertTrue(result["degraded"])
        self.assertEqual(result["matched_templates"], [])

    # --- Test 2: templates jsonl missing -> degraded ---
    def test_missing_templates_jsonl(self) -> None:
        # Don't write the file; expect graceful degrade.
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=["INV-X-001"],
        )
        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertEqual(result["error"], "global_chain_templates_jsonl_missing")
        self.assertTrue(result["degraded"])

    # --- Test 3: empty broken set returns no matches ---
    def test_empty_broken_set_returns_no_matches(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [_tpl("GCT-aaa", ["INV-001", "INV-002"])],
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
        )
        self.assertEqual(result["matched_templates"], [])
        self.assertEqual(result["summary"]["broken_invariant_id_count"], 0)
        self.assertGreaterEqual(result["summary"]["total_templates_available"], 1)

    # --- Test 4: full match (all members in broken set) ---
    def test_full_match(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [_tpl("GCT-aaa", ["INV-001", "INV-002"])],
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=["INV-001", "INV-002"],
            min_match_density=0.5,
        )
        self.assertEqual(len(result["matched_templates"]), 1)
        m = result["matched_templates"][0]
        self.assertEqual(m["chain_template_id"], "GCT-aaa")
        self.assertEqual(m["match_density"], 1.0)
        self.assertEqual(sorted(m["matched_invariant_ids"]), ["INV-001", "INV-002"])

    # --- Test 5: partial match below density threshold dropped ---
    def test_density_threshold_drops_partial(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [_tpl("GCT-bbb", ["INV-001", "INV-002", "INV-003", "INV-004"])],
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=["INV-001"],  # only 1/4 = 0.25
            min_match_density=0.5,
        )
        self.assertEqual(len(result["matched_templates"]), 0)

    # --- Test 6: max_matches cap ---
    def test_max_matches_cap(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [
                _tpl(f"GCT-{i:03d}", [f"INV-{i:03d}-A", f"INV-{i:03d}-B"])
                for i in range(20)
            ],
        )
        broken = [f"INV-{i:03d}-A" for i in range(20)] + [f"INV-{i:03d}-B" for i in range(20)]
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=broken,
            max_matches=5,
        )
        self.assertEqual(len(result["matched_templates"]), 5)
        self.assertEqual(result["summary"]["templates_matched"], 20)
        self.assertEqual(result["summary"]["templates_returned"], 5)

    # --- Test 7: ordering by density desc then tuple_size desc ---
    def test_ordering_by_density_then_tuple_size(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [
                _tpl("GCT-quad", ["INV-A", "INV-B", "INV-C", "INV-D"]),
                _tpl("GCT-pair", ["INV-A", "INV-B"]),
            ],
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=["INV-A", "INV-B"],
            min_match_density=0.4,
        )
        # GCT-pair has density 1.0; GCT-quad has density 0.5.
        ids = [m["chain_template_id"] for m in result["matched_templates"]]
        self.assertEqual(ids[0], "GCT-pair")

    # --- Test 8: exploit_queue.json auto-inference ---
    def test_exploit_queue_inference(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [_tpl("GCT-eq-001", ["INV-FROM-QUEUE-1", "INV-FROM-QUEUE-2"])],
        )
        queue_path = self.ws / ".auditooor" / "exploit_queue.json"
        queue_path.parent.mkdir(parents=True, exist_ok=True)
        queue_path.write_text(
            json.dumps(
                {
                    "broken_invariant_ids": [
                        "INV-FROM-QUEUE-1",
                        "INV-FROM-QUEUE-2",
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
        )
        self.assertEqual(len(result["matched_templates"]), 1)
        self.assertEqual(
            result["matched_templates"][0]["chain_template_id"], "GCT-eq-001"
        )
        self.assertEqual(result["summary"]["broken_invariant_id_count"], 2)

    # --- Test 9: schema + context_pack_id present ---
    def test_envelope_fields(self) -> None:
        _write_jsonl(self.tpl_path, [_tpl("GCT-env", ["INV-X"])])
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=["INV-X"],
        )
        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertTrue(result["context_pack_id"].startswith(EXPECTED_SCHEMA))
        self.assertEqual(len(result["context_pack_hash"]), 64)  # sha256
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
        self.assertTrue(result["advisory_only"])

    # --- Test 10: malformed jsonl line skipped ---
    def test_malformed_lines_skipped(self) -> None:
        self.tpl_path.parent.mkdir(parents=True, exist_ok=True)
        with self.tpl_path.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps(_tpl("GCT-good", ["INV-A", "INV-B"])) + "\n")
            fh.write("not-valid-json\n")
            fh.write(json.dumps({"not_a_template": True}) + "\n")
            fh.write(json.dumps(_tpl("GCT-also-good", ["INV-A", "INV-B"])) + "\n")
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=["INV-A", "INV-B"],
            min_match_density=0.5,
        )
        ids = [m["chain_template_id"] for m in result["matched_templates"]]
        self.assertEqual(sorted(ids), ["GCT-also-good", "GCT-good"])

    # --- Test 11: matched_invariant_ids is the intersection only ---
    def test_matched_invariant_ids_is_intersection(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [_tpl("GCT-inter", ["INV-A", "INV-B", "INV-C"])],
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=["INV-A", "INV-B", "INV-IRRELEVANT"],
            min_match_density=0.5,
        )
        self.assertEqual(len(result["matched_templates"]), 1)
        m = result["matched_templates"][0]
        self.assertEqual(m["matched_invariant_ids"], ["INV-A", "INV-B"])
        self.assertEqual(m["member_invariant_ids"], ["INV-A", "INV-B", "INV-C"])

    # --- Test 12: explicit broken_invariant_ids overrides exploit_queue.json ---
    def test_explicit_args_override_queue(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [_tpl("GCT-ovr", ["INV-EXPLICIT-1", "INV-EXPLICIT-2"])],
        )
        queue_path = self.ws / ".auditooor" / "exploit_queue.json"
        queue_path.parent.mkdir(parents=True, exist_ok=True)
        queue_path.write_text(
            json.dumps({"broken_invariant_ids": ["INV-FROM-QUEUE-ONLY"]}),
            encoding="utf-8",
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=["INV-EXPLICIT-1", "INV-EXPLICIT-2"],
        )
        self.assertEqual(len(result["matched_templates"]), 1)
        self.assertEqual(
            sorted(result["broken_invariant_ids_input"]),
            ["INV-EXPLICIT-1", "INV-EXPLICIT-2"],
        )


if __name__ == "__main__":
    unittest.main()
