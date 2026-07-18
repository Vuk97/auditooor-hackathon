"""LIFT-25 Phase 3.3 closure tests.

Covers the `seed_from_global_templates` kwarg on
`vault_chained_attack_plan_context`. The kwarg was added in LIFT-21 but
silently discarded; LIFT-25 wires the actual computation.

# r36-rebuttal: lane LIFT-25-PHASE-3-3-CLOSURE registered via
# tools/agent-pathspec-register.py.
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
EXPECTED_SCHEMA = "auditooor.vault_chained_attack_plan_context.v1"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_chained_attack_plan_phase33",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _plan(idx: int, workspace: Path) -> dict:
    source_file = workspace / "src" / f"Vault{idx}.sol"
    return {
        "chain_id": f"CHAIN-{idx:03d}",
        "status": "candidate_not_submit_ready",
        "score": 100 - idx,
        "title": f"candidate chain {idx}",
        "composition_rationale": (
            "shared source refs need proof before any submission posture "
            "can change"
        ),
        "primitives": [],
        "chain_steps": [],
        "shared_evidence": [],
        "source_refs": [str(source_file) + ":42"],
        "proof_steps": ["confirm file:line exploitability"],
        "blockers": ["pre-submit gate has not passed"],
    }


def _make_chain_plans_payload(workspace: Path) -> dict:
    return {
        "schema_version": "auditooor.chained_attack_plans.v1",
        "workspace": "<workspace>",
        "advisory_only": True,
        "submission_posture": "candidate_not_submit_ready",
        "summary": {"plan_count": 3, "max_plans": 3},
        "plans": [_plan(idx, workspace) for idx in range(1, 4)],
        "source_refs": [
            str(workspace / "swarm" / "chained_attack_plans.json"),
        ],
    }


def _make_templates_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")


def _zetachain_record() -> dict:
    """Minimal ZetaChain GCT record matching the demo expectation."""
    return {
        "advisory_only": True,
        "chain_template_id": "GCT-382aa92a72e7c9de",
        "composition_score": 1.0,
        "composition_rationale": (
            "ZetaChain arbitrary-call allowance-residue 4-tuple "
            "(bridge custody)."
        ),
        "evidence_incidents": [
            "zetachain:2026-04-26-arbcall-allowance-residue-drain",
        ],
        "member_categories": [
            "bridge-arbitrary-call-with-allowance-residue-drain",
            "erc20-allowance-residue-on-bridge",
            "msg-sender-zeroing-downstream-authorization-uplift",
            "selector-deny-list-incomplete",
        ],
        "member_invariant_ids": [
            "INV-BRIDGE-ALLOWANCE-001",
            "INV-BRIDGE-ARBCALL-001",
            "INV-BRIDGE-SELECTOR-DENY-001",
            "INV-BRIDGE-SENDER-ZEROING-001",
        ],
        "schema_version": "auditooor.global_chain_template.v1",
        "submission_posture": "NOT_SUBMIT_READY",
        "tuple_size": 4,
        "verification_tier": "tier-2-verified-public-archive",
    }


def _half_match_record(template_id: str) -> dict:
    return {
        "advisory_only": True,
        "chain_template_id": template_id,
        "composition_score": 0.7,
        "composition_rationale": "partial overlap",
        "evidence_incidents": ["incident:half-match"],
        "member_categories": ["bridge-x", "bridge-y"],
        "member_invariant_ids": [
            "INV-BRIDGE-ALLOWANCE-001",
            "INV-UNRELATED-001",
        ],
        "schema_version": "auditooor.global_chain_template.v1",
        "submission_posture": "NOT_SUBMIT_READY",
        "tuple_size": 2,
        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
    }


def _write_invariant_ledger(workspace: Path, broken_ids: list[str]) -> None:
    """Write workspace .auditooor/invariant_ledger.json with broken rows."""
    rows = [
        {"invariant_id": iid, "status": "broken"} for iid in broken_ids
    ]
    _write_json(
        workspace / ".auditooor" / "invariant_ledger.json",
        {"rows": rows},
    )


class Phase33SeedFromGlobalTemplatesTest(unittest.TestCase):
    """LIFT-25 wires the seed_from_global_templates kwarg."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(
            prefix="vault-chained-plan-phase33-",
        )
        self.base = Path(self.tmp.name)
        self.vault_dir = self.base / "vault"
        self.repo = self.base / "repo"
        self.ws = self.base / "workspace"
        self.vault_dir.mkdir()
        self.repo.mkdir()
        self.ws.mkdir()
        # Make the templates JSONL path predictable for the helper:
        self.templates_path = (
            self.repo / "audit" / "corpus_tags" / "derived"
            / "global_chain_templates.jsonl"
        )
        # Always write the chained_attack_plans.json so the base
        # behavior succeeds.
        _write_json(
            self.ws / "swarm" / "chained_attack_plans.json",
            _make_chain_plans_payload(self.ws),
        )
        # We also need a working seed library available; the repo_root
        # passed below is self.repo, so make a stub tools/lib path.
        # The real implementation imports from self.repo_root / "tools"
        # / "lib" / "global_chain_templates_seed.py". For tests, point at
        # the REAL repo's lib by symlinking it under self.repo.
        (self.repo / "tools" / "lib").mkdir(parents=True, exist_ok=True)
        real_seed = (
            Path(__file__).resolve().parents[1] / "lib"
            / "global_chain_templates_seed.py"
        )
        target = self.repo / "tools" / "lib" / "global_chain_templates_seed.py"
        if not target.exists() and real_seed.is_file():
            target.write_text(
                real_seed.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        self.vault_mcp = _load_vault_mcp()
        self.vault = self.vault_mcp.VaultQuery(
            self.vault_dir, repo_root=self.repo,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # --- Case 1: default (kwarg omitted) preserves shape ---
    def test_default_no_new_fields(self) -> None:
        result = self.vault.vault_chained_attack_plan_context(
            workspace_path=str(self.ws),
            max_plans=2,
        )
        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertNotIn("global_template_seeds", result)
        self.assertNotIn("global_template_seeds_summary", result)
        # plans still populated normally
        self.assertGreaterEqual(len(result["plans"]), 1)

    # --- Case 2: kwarg=False also preserves shape ---
    def test_false_no_new_fields(self) -> None:
        result = self.vault.vault_chained_attack_plan_context(
            workspace_path=str(self.ws),
            max_plans=2,
            seed_from_global_templates=False,
        )
        self.assertNotIn("global_template_seeds", result)
        self.assertNotIn("global_template_seeds_summary", result)

    # --- Case 3: kwarg=True adds the fields even with no matches ---
    def test_true_adds_empty_seeds_when_no_broken_invariants(
        self,
    ) -> None:
        # Templates file exists but workspace has no broken invariants.
        _make_templates_jsonl(self.templates_path, [_zetachain_record()])
        result = self.vault.vault_chained_attack_plan_context(
            workspace_path=str(self.ws),
            max_plans=2,
            seed_from_global_templates=True,
        )
        self.assertIn("global_template_seeds", result)
        self.assertIn("global_template_seeds_summary", result)
        self.assertEqual(result["global_template_seeds"], [])
        summary = result["global_template_seeds_summary"]
        self.assertEqual(summary["total_seeds_matched"], 0)
        self.assertEqual(summary["broken_invariant_id_count"], 0)
        # degraded reason for the empty-broken-set branch
        self.assertIn("degraded_reason", summary)
        self.assertEqual(
            summary["degraded_reason"], "broken_invariant_set_empty",
        )

    # --- Case 4: ZetaChain 4-tuple full match returns density=1.0 ---
    def test_zetachain_4tuple_full_match(self) -> None:
        # Inject the 4 ZetaChain bridge invariants as broken.
        _write_invariant_ledger(
            self.ws,
            [
                "INV-BRIDGE-ALLOWANCE-001",
                "INV-BRIDGE-ARBCALL-001",
                "INV-BRIDGE-SELECTOR-DENY-001",
                "INV-BRIDGE-SENDER-ZEROING-001",
            ],
        )
        _make_templates_jsonl(
            self.templates_path,
            [_zetachain_record(), _half_match_record("GCT-half-aaaa")],
        )
        result = self.vault.vault_chained_attack_plan_context(
            workspace_path=str(self.ws),
            max_plans=3,
            seed_from_global_templates=True,
        )
        seeds = result["global_template_seeds"]
        self.assertGreaterEqual(len(seeds), 1)
        top = seeds[0]
        self.assertEqual(top["chain_template_id"], "GCT-382aa92a72e7c9de")
        self.assertAlmostEqual(top["match_density"], 1.0, places=6)
        self.assertEqual(sorted(top["matched_invariant_ids"]), [
            "INV-BRIDGE-ALLOWANCE-001",
            "INV-BRIDGE-ARBCALL-001",
            "INV-BRIDGE-SELECTOR-DENY-001",
            "INV-BRIDGE-SENDER-ZEROING-001",
        ])
        self.assertTrue(top["advisory_only"])
        self.assertEqual(top["submission_posture"], "NOT_SUBMIT_READY")
        summary = result["global_template_seeds_summary"]
        self.assertEqual(summary["total_seeds_matched"], 2)
        self.assertAlmostEqual(summary["max_density"], 1.0, places=6)
        self.assertGreater(summary["avg_density"], 0.0)
        self.assertGreaterEqual(summary["broken_invariant_id_count"], 4)

    # --- Case 5: explicit broken_invariant_ids kwarg ---
    def test_explicit_broken_invariant_ids_override(self) -> None:
        # No ledger file; pass explicitly instead.
        _make_templates_jsonl(self.templates_path, [_zetachain_record()])
        result = self.vault.vault_chained_attack_plan_context(
            workspace_path=str(self.ws),
            max_plans=3,
            seed_from_global_templates=True,
            broken_invariant_ids=[
                "INV-BRIDGE-ALLOWANCE-001",
                "INV-BRIDGE-ARBCALL-001",
                "INV-BRIDGE-SELECTOR-DENY-001",
                "INV-BRIDGE-SENDER-ZEROING-001",
            ],
        )
        seeds = result["global_template_seeds"]
        self.assertEqual(len(seeds), 1)
        self.assertEqual(
            seeds[0]["chain_template_id"], "GCT-382aa92a72e7c9de",
        )
        self.assertAlmostEqual(seeds[0]["match_density"], 1.0, places=6)
        summary = result["global_template_seeds_summary"]
        self.assertEqual(summary["broken_invariant_source"], "explicit_kwarg")

    # --- Case 6: missing global_chain_templates.jsonl is degraded ---
    def test_missing_templates_jsonl_returns_degraded(self) -> None:
        # Do NOT write the templates file.
        result = self.vault.vault_chained_attack_plan_context(
            workspace_path=str(self.ws),
            max_plans=2,
            seed_from_global_templates=True,
            broken_invariant_ids=["INV-X-001"],
        )
        self.assertIn("global_template_seeds", result)
        self.assertEqual(result["global_template_seeds"], [])
        summary = result["global_template_seeds_summary"]
        self.assertEqual(
            summary["degraded_reason"],
            "global_chain_templates_jsonl_missing",
        )

    # --- Case 7: tools/list exposes the new schema property ---
    def test_tools_list_includes_seed_kwarg(self) -> None:
        listed = self.vault_mcp.handle_request(
            self.vault,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        by_name = {
            tool["name"]: tool for tool in listed["result"]["tools"]
        }
        self.assertIn("vault_chained_attack_plan_context", by_name)
        props = by_name[
            "vault_chained_attack_plan_context"
        ]["inputSchema"]["properties"]
        self.assertIn("seed_from_global_templates", props)
        self.assertIn("broken_invariant_ids", props)
        self.assertIn("templates_jsonl_path", props)
        # Workspace_path remains required.
        required = by_name[
            "vault_chained_attack_plan_context"
        ]["inputSchema"]["required"]
        self.assertIn("workspace_path", required)


if __name__ == "__main__":
    unittest.main()
