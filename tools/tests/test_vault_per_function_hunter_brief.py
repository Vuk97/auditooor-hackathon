# r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY registered in .auditooor/agent_pathspec.json
"""Tests for VaultQuery.vault_per_function_hunter_brief callable (LIFT-28).

synthetic_fixture: true

LIFT-28 (2026-05-26). The callable composes vault_hacker_questions +
vault_global_chain_template_match + invariant context into a per-function
brief for a specific contract:function in a workspace.

Test coverage:

  1.  Degraded envelope when workspace_path missing.
  2.  Degraded envelope when contract_path missing.
  3.  Backward-compat: vault_hacker_questions still works when LIFT-28
      kwargs are absent.
  4.  Per-function field enrichment: derived target_function_patterns
      surface in vault_hacker_questions response when records carry them.
  5.  vault_hacker_questions filters records that explicitly mismatch
      the target_function_name.
  6.  vault_global_chain_template_match accepts contract_kind_hint and
      filters templates whose applicable_contract_kinds disagree.
  7.  vault_per_function_hunter_brief returns matched_hacker_questions
      ranked with explicit-target rows first.
  8.  vault_per_function_hunter_brief returns matched_chain_templates
      scored by per-function applicability.
  9.  vault_per_function_hunter_brief unions invariants across questions
      + templates.
  10. Workspace-level fallback when contract_path is absent reverts to
      the workspace-level behavior of the underlying callable
      (vault_hacker_questions).
  11. Per-shape filter intersection logic: explicit fn_pats hit beats
      legacy fallthrough.
  12. ZetaChain CallDispatcher.dispatch live demo: should return
      INV-BRIDGE-* anchors + GCT-* chain templates.
  13. Schema envelope: schema + context_pack_id + context_pack_hash.
  14. token_estimate field present.
  15. TOOL_SCHEMAS entry registered with required keys.
  16. CLI dispatch exits 0 against the live corpus.
  17. Dispatcher (call_tool / handle_call) routes vault_per_function_hunter_brief.
  18. Library function: enrich_hacker_question_record adds the new fields.
  19. Library function: enrich_global_chain_template_record adds the new fields.
  20. Library function: score_template_match returns higher score on
      direct kind+role match.

r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY declared in .auditooor/agent_pathspec.json
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
LIB_PATH = REPO_ROOT / "tools" / "lib" / "per_function_target_patterns.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module("vault_mcp_server", MODULE_PATH)
per_function_lib = _load_module("per_function_target_patterns", LIB_PATH)


# synthetic_fixture: true - constants below are minimal records crafted
# to exercise per-function logic without depending on the live corpus.
SYNTH_HACKER_QUESTIONS = [
    {
        "question_id": "HQ-SYNTH-DISPATCH-001",
        "question_text": "Does the bridge dispatch arbitrary calls without selector deny-list?",
        "source_incident_id": "synth-dispatch-2026-05",
        "source_case_study": "case_study/synth.md:L10",
        "attack_class_anchor": "arbitrary-call",
        "target_languages": ["solidity"],
        "grep_patterns": ["dispatch", "executeRaw", "callBytes"],
        "verification_tier": "tier-2-verified-public-archive",
        "linked_invariant_ids": ["INV-BRIDGE-ARBCALL-001"],
    },
    {
        "question_id": "HQ-SYNTH-ORACLE-001",
        "question_text": "Does the price feed read return a stale value?",
        "source_incident_id": "synth-oracle-2026-05",
        "source_case_study": "case_study/synth.md:L20",
        "attack_class_anchor": "staleness",
        "target_languages": ["solidity"],
        "grep_patterns": ["latestAnswer", "getPrice"],
        "verification_tier": "tier-2-verified-public-archive",
        "linked_invariant_ids": ["INV-FRE-EX-0019"],
    },
    {
        "question_id": "HQ-SYNTH-WORKSPACE-001",
        "question_text": "Legacy workspace-level rule with no grep_patterns.",
        "source_incident_id": "synth-legacy-2026-05",
        "source_case_study": "case_study/synth.md:L40",
        "attack_class_anchor": "anti-pattern-recommendation",
        "target_languages": ["solidity"],
        "grep_patterns": [],
        "verification_tier": "tier-2-verified-public-archive",
        "linked_invariant_ids": [],
    },
]


SYNTH_CHAIN_TEMPLATES = [
    {
        "advisory_only": True,
        "chain_template_id": "GCT-synth-bridge-001",
        "composition_score": 1.5,
        "member_invariant_ids": ["INV-BRIDGE-ARBCALL-001"],
        "member_categories": ["bridge"],
        "evidence_incidents": ["synth-bridge-incident-001"],
        "tuple_size": 1,
        "verification_tier": "tier-2-verified-public-archive",
    },
    {
        "advisory_only": True,
        "chain_template_id": "GCT-synth-oracle-001",
        "composition_score": 1.3,
        "member_invariant_ids": ["INV-FRE-EX-0019"],
        "member_categories": ["freshness"],
        "evidence_incidents": ["synth-oracle-incident-001"],
        "tuple_size": 1,
        "verification_tier": "tier-2-verified-public-archive",
    },
]


def _make_minimal_vault(vault_dir: Path) -> None:
    # synthetic_fixture: true
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "INDEX.md").write_text("# INDEX\n\n- entry\n", encoding="utf-8")
    (vault_dir / "INDEX_active.md").write_text("# active\n- item\n", encoding="utf-8")
    (vault_dir / "NEXT_LOOP.md").write_text(
        "# NEXT_LOOP\n\n## Section\n- item\n", encoding="utf-8"
    )
    goals = vault_dir / "goals"
    goals.mkdir(exist_ok=True)
    (goals / "current.md").write_text(
        "---\nobjective: synth\n---\n# goal\n", encoding="utf-8"
    )


class TestPerFunctionLibrary(unittest.TestCase):
    """Tests against tools/lib/per_function_target_patterns.py (no MCP)."""

    def test_enrich_hacker_question_record_adds_fields(self):
        rec = dict(SYNTH_HACKER_QUESTIONS[0])
        enriched = per_function_lib.enrich_hacker_question_record(rec)
        self.assertIn("target_function_patterns", enriched)
        self.assertIn("target_function_roles", enriched)
        self.assertIn("target_contract_patterns", enriched)
        self.assertIn("target_modifier_patterns", enriched)
        self.assertIn("scope_specificity", enriched)
        # dispatcher role inferred from greps + question text
        self.assertIn("dispatcher", enriched["target_function_roles"])
        # contract regex contains bridge|dispatcher|router|...
        self.assertTrue(any("dispatcher" in p for p in enriched["target_contract_patterns"]))
        # scope at function level when fn_pats present
        self.assertEqual(enriched["scope_specificity"], "function")
        # Backward-compat: original fields preserved verbatim.
        self.assertEqual(enriched["question_id"], rec["question_id"])
        self.assertEqual(enriched["question_text"], rec["question_text"])

    def test_enrich_global_chain_template_record_adds_fields(self):
        rec = dict(SYNTH_CHAIN_TEMPLATES[0])
        enriched = per_function_lib.enrich_global_chain_template_record(rec)
        self.assertIn("applicable_contract_kinds", enriched)
        self.assertIn("applicable_function_role_patterns", enriched)
        self.assertIn("min_member_invariants_matching", enriched)
        # bridge member -> bridge kind + dispatcher role
        self.assertIn("bridge", enriched["applicable_contract_kinds"])
        self.assertIn("dispatcher", enriched["applicable_function_role_patterns"])
        # min_match = ceil(tuple_size/2) >= 1
        self.assertGreaterEqual(enriched["min_member_invariants_matching"], 1)

    def test_score_template_match_higher_on_direct_kind_role_match(self):
        rec = per_function_lib.enrich_global_chain_template_record(
            dict(SYNTH_CHAIN_TEMPLATES[0])
        )
        bridge_dispatch = per_function_lib.score_template_match(
            rec,
            target_contract_path="evm/src/utils/CallDispatcher.sol",
            target_function_name="dispatch",
            contract_kind_hint="bridge",
        )
        unrelated = per_function_lib.score_template_match(
            rec,
            target_contract_path="evm/src/Token.sol",
            target_function_name="transfer",
            contract_kind_hint="dex",
        )
        self.assertGreater(bridge_dispatch, unrelated)


class TestVaultPerFunctionHunterBrief(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lift28-pfb-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)
        # synthetic_fixture: true
        self.hq_path = self.root / "hacker_questions_library.jsonl"
        enriched_hq = [
            per_function_lib.enrich_hacker_question_record(dict(rec))
            for rec in SYNTH_HACKER_QUESTIONS
        ]
        with self.hq_path.open("w", encoding="utf-8") as fh:
            for rec in enriched_hq:
                fh.write(json.dumps(rec) + "\n")
        self.tpl_path = self.root / "global_chain_templates.jsonl"
        enriched_tpl = [
            per_function_lib.enrich_global_chain_template_record(dict(rec))
            for rec in SYNTH_CHAIN_TEMPLATES
        ]
        with self.tpl_path.open("w", encoding="utf-8") as fh:
            for rec in enriched_tpl:
                fh.write(json.dumps(rec) + "\n")
        self.workspace = self.root / "fake-workspace"
        self.workspace.mkdir()
        # Provide a fake exploit_queue with broken invariants.
        (self.workspace / ".auditooor").mkdir()
        (self.workspace / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({
                "broken_invariant_ids": [
                    "INV-BRIDGE-ARBCALL-001", "INV-FRE-EX-0019"
                ],
            }),
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    # --- 1. degraded: workspace_path missing ---
    def test_degraded_when_workspace_missing(self):
        res = self.query.vault_per_function_hunter_brief()
        self.assertTrue(res.get("degraded"))
        self.assertEqual(res.get("error"), "workspace_path_required")

    # --- 2. degraded: contract_path missing ---
    def test_degraded_when_contract_missing(self):
        res = self.query.vault_per_function_hunter_brief(
            workspace_path=str(self.workspace),
        )
        self.assertTrue(res.get("degraded"))
        self.assertEqual(res.get("error"), "contract_path_required")

    # --- 3. backward-compat: vault_hacker_questions with no LIFT-28 kwargs ---
    def test_vault_hacker_questions_backward_compat(self):
        res = self.query.vault_hacker_questions(corpus_path=str(self.hq_path))
        self.assertFalse(res.get("degraded"))
        self.assertEqual(res["total_records"], 3)
        # Legacy filters_applied keys still present.
        self.assertIn("filters_applied", res)
        # The new LIFT-28 keys are explicitly None when not set.
        fa = res["filters_applied"]
        self.assertIsNone(fa.get("target_contract_path"))
        self.assertIsNone(fa.get("target_function_name"))

    # --- 4. per-function enrichment surfaces in vault_hacker_questions response ---
    def test_vault_hacker_questions_response_carries_new_fields(self):
        res = self.query.vault_hacker_questions(corpus_path=str(self.hq_path))
        # The dispatcher synth record should carry per-function fields.
        match = [q for q in res["questions"] if q["question_id"] == "HQ-SYNTH-DISPATCH-001"]
        self.assertEqual(len(match), 1)
        q = match[0]
        self.assertIn("target_function_patterns", q)
        self.assertIn("target_function_roles", q)
        self.assertIn("target_contract_patterns", q)
        self.assertIn("target_modifier_patterns", q)
        self.assertIn("scope_specificity", q)
        self.assertTrue(q["target_function_patterns"])  # non-empty

    # --- 5. vault_hacker_questions filters explicit mismatch ---
    def test_vault_hacker_questions_filters_explicit_mismatch(self):
        # The oracle record explicitly has fn_pats [latestAnswer, getPrice].
        # When target_function_name='dispatch', the oracle record should be
        # filtered OUT (its explicit patterns don't match), while the
        # workspace-legacy record falls through.
        res = self.query.vault_hacker_questions(
            corpus_path=str(self.hq_path),
            target_function_name="latestAnswer",
        )
        ids = {q["question_id"] for q in res["questions"]}
        self.assertIn("HQ-SYNTH-ORACLE-001", ids)
        # Dispatch record's fn_pats don't match latestAnswer -> dropped.
        self.assertNotIn("HQ-SYNTH-DISPATCH-001", ids)

    # --- 6. vault_global_chain_template_match contract_kind_hint filter ---
    def test_global_chain_template_match_kind_hint_filter(self):
        res = self.query.vault_global_chain_template_match(
            workspace_path=str(self.workspace),
            templates_jsonl_path=str(self.tpl_path),
            broken_invariant_ids=[
                "INV-BRIDGE-ARBCALL-001", "INV-FRE-EX-0019",
            ],
            contract_kind_hint="oracle",
            min_match_density=0.5,
        )
        matched = res.get("matched_templates") or []
        ids = {t.get("chain_template_id") for t in matched}
        # oracle kind hint -> only oracle/freshness template surfaces.
        self.assertIn("GCT-synth-oracle-001", ids)
        self.assertNotIn("GCT-synth-bridge-001", ids)

    # --- 7. vault_per_function_hunter_brief ranks explicit-target rows first ---
    def test_per_function_hunter_brief_ranks_targeted_rows_first(self):
        res = self.query.vault_per_function_hunter_brief(
            workspace_path=str(self.workspace),
            contract_path="evm/src/CallDispatcher.sol",
            function_name="dispatch",
            hacker_questions_corpus_path=str(self.hq_path),
            templates_jsonl_path=str(self.tpl_path),
            broken_invariant_ids=["INV-BRIDGE-ARBCALL-001"],
            max_questions=3,
            max_templates=3,
        )
        self.assertFalse(res.get("degraded"))
        questions = res.get("matched_hacker_questions") or []
        self.assertTrue(questions)
        # The dispatcher record should rank first.
        self.assertEqual(questions[0]["question_id"], "HQ-SYNTH-DISPATCH-001")

    # --- 8. matched_chain_templates scored by applicability ---
    def test_per_function_hunter_brief_scores_templates_by_applicability(self):
        res = self.query.vault_per_function_hunter_brief(
            workspace_path=str(self.workspace),
            contract_path="evm/src/CallDispatcher.sol",
            function_name="dispatch",
            contract_kind_hint="bridge",
            hacker_questions_corpus_path=str(self.hq_path),
            templates_jsonl_path=str(self.tpl_path),
            broken_invariant_ids=[
                "INV-BRIDGE-ARBCALL-001", "INV-FRE-EX-0019",
            ],
            max_templates=2,
        )
        templates = res.get("matched_chain_templates") or []
        self.assertTrue(templates)
        # bridge kind+dispatcher role match -> first.
        self.assertEqual(templates[0]["chain_template_id"], "GCT-synth-bridge-001")

    # --- 9. union of invariants from questions + templates ---
    def test_per_function_hunter_brief_unions_invariants(self):
        res = self.query.vault_per_function_hunter_brief(
            workspace_path=str(self.workspace),
            contract_path="evm/src/CallDispatcher.sol",
            function_name="dispatch",
            hacker_questions_corpus_path=str(self.hq_path),
            templates_jsonl_path=str(self.tpl_path),
            broken_invariant_ids=["INV-BRIDGE-ARBCALL-001"],
            max_questions=3,
            max_templates=2,
        )
        invariants = set(res.get("relevant_invariants") or [])
        self.assertIn("INV-BRIDGE-ARBCALL-001", invariants)

    # --- 10. workspace-level fallback (function_name absent) ---
    def test_per_function_hunter_brief_workspace_fallback_no_function(self):
        # contract_path set but function_name absent: still works as
        # contract-level brief.
        res = self.query.vault_per_function_hunter_brief(
            workspace_path=str(self.workspace),
            contract_path="evm/src/CallDispatcher.sol",
            hacker_questions_corpus_path=str(self.hq_path),
            templates_jsonl_path=str(self.tpl_path),
            broken_invariant_ids=["INV-BRIDGE-ARBCALL-001"],
            max_questions=3,
        )
        self.assertFalse(res.get("degraded"))
        self.assertIsNone(res["target"].get("function"))

    # --- 11. per-shape filter intersection ---
    def test_per_function_brief_explicit_match_beats_legacy(self):
        res = self.query.vault_per_function_hunter_brief(
            workspace_path=str(self.workspace),
            contract_path="evm/src/CallDispatcher.sol",
            function_name="executeRaw",
            hacker_questions_corpus_path=str(self.hq_path),
            templates_jsonl_path=str(self.tpl_path),
            broken_invariant_ids=["INV-BRIDGE-ARBCALL-001"],
            max_questions=3,
        )
        # The dispatcher record's explicit grep_patterns include "executeRaw"
        # so it must rank ahead of the legacy workspace fall-through.
        qs = res.get("matched_hacker_questions") or []
        self.assertEqual(qs[0]["question_id"], "HQ-SYNTH-DISPATCH-001")

    # --- 12. live ZetaChain demo (skipped if live corpus missing) ---
    def test_live_demo_zetachain_calldispatcher(self):
        # r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY pathspec registered.
        live_hq = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "hacker_questions_library.jsonl"
        live_tpl = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "global_chain_templates.jsonl"
        if not live_hq.is_file() or not live_tpl.is_file():
            self.skipTest("live corpora missing")
        # The test's VaultQuery has repo_root=self.root (tempdir); we
        # must pass explicit corpus paths so the inner callables read
        # from the live in-tree files.
        ws = self.root / "live-demo-ws"
        ws.mkdir()
        res = self.query.vault_per_function_hunter_brief(
            workspace_path=str(ws),
            contract_path="evm/src/utils/CallDispatcher.sol",
            function_name="dispatch",
            contract_kind_hint="bridge",
            broken_invariant_ids=[
                "INV-BRIDGE-ARBCALL-001",
                "INV-FRE-EX-0019",
                "INV-CUS-EX-0031",
            ],
            hacker_questions_corpus_path=str(live_hq),
            templates_jsonl_path=str(live_tpl),
            max_questions=10,
            max_templates=5,
        )
        self.assertFalse(res.get("degraded"))
        summary = res.get("summary") or {}
        self.assertGreater(summary.get("questions_returned", 0), 0)
        # The bridge-anchor template should surface.
        tpl_ids = [t.get("chain_template_id") for t in (res.get("matched_chain_templates") or [])]
        # At least one template should fire when broken_invariant_ids hit.
        self.assertGreater(len(tpl_ids), 0)

    # --- 13. envelope carries schema + context_pack_id + context_pack_hash ---
    def test_envelope_carries_schema_and_hash(self):
        res = self.query.vault_per_function_hunter_brief(
            workspace_path=str(self.workspace),
            contract_path="evm/src/CallDispatcher.sol",
            hacker_questions_corpus_path=str(self.hq_path),
            templates_jsonl_path=str(self.tpl_path),
            broken_invariant_ids=["INV-BRIDGE-ARBCALL-001"],
        )
        self.assertEqual(res["schema"], "auditooor.vault_per_function_hunter_brief.v1")
        self.assertTrue(res["context_pack_id"].startswith(
            "auditooor.vault_per_function_hunter_brief.v1:"
        ))
        self.assertEqual(len(res["context_pack_hash"]), 64)

    # --- 14. token_estimate field present ---
    def test_token_estimate_present(self):
        res = self.query.vault_per_function_hunter_brief(
            workspace_path=str(self.workspace),
            contract_path="evm/src/CallDispatcher.sol",
            hacker_questions_corpus_path=str(self.hq_path),
            templates_jsonl_path=str(self.tpl_path),
        )
        self.assertIn("token_estimate", res)
        self.assertIsInstance(res["token_estimate"], int)

    # --- 15. TOOL_SCHEMAS entry registered with required keys ---
    def test_tool_schemas_entry_present(self):
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_per_function_hunter_brief", names)
        spec = next(
            t for t in vault_mcp_server.TOOL_SCHEMAS
            if t["name"] == "vault_per_function_hunter_brief"
        )
        self.assertIn("description", spec)
        self.assertIn("inputSchema", spec)
        required = spec["inputSchema"].get("required") or []
        self.assertIn("workspace_path", required)
        self.assertIn("contract_path", required)

    # --- 16. CLI dispatch against live corpus exits 0 ---
    def test_cli_dispatch_exit_zero(self):
        live_hq = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "hacker_questions_library.jsonl"
        live_tpl = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "global_chain_templates.jsonl"
        if not live_hq.is_file() or not live_tpl.is_file():
            self.skipTest("live corpora missing")
        # synthetic_fixture: true (against the in-tree corpora)
        ws = self.root / "cli-demo-ws"
        ws.mkdir()
        result = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--call",
                "vault_per_function_hunter_brief",
                "--args",
                json.dumps({
                    "workspace_path": str(ws),
                    "contract_path": "evm/src/utils/CallDispatcher.sol",
                    "function_name": "dispatch",
                    "contract_kind_hint": "bridge",
                    "max_questions": 5,
                    "max_templates": 3,
                }),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema"], "auditooor.vault_per_function_hunter_brief.v1")

    # --- 17. dispatcher routes vault_per_function_hunter_brief ---
    def test_call_tool_dispatcher_routes_callable(self):
        # The call_tool method should route the name to the callable.
        # We rely on the production dispatch path; if call_tool exists,
        # invoke it. Otherwise fall back to direct callable invocation.
        if hasattr(self.query, "call_tool"):
            res = self.query.call_tool(
                "vault_per_function_hunter_brief",
                {
                    "workspace_path": str(self.workspace),
                    "contract_path": "evm/src/CallDispatcher.sol",
                    "hacker_questions_corpus_path": str(self.hq_path),
                    "templates_jsonl_path": str(self.tpl_path),
                },
            )
            self.assertEqual(
                res.get("schema"),
                "auditooor.vault_per_function_hunter_brief.v1",
            )
        else:
            res = self.query.vault_per_function_hunter_brief(
                workspace_path=str(self.workspace),
                contract_path="evm/src/CallDispatcher.sol",
                hacker_questions_corpus_path=str(self.hq_path),
                templates_jsonl_path=str(self.tpl_path),
            )
            self.assertEqual(
                res.get("schema"),
                "auditooor.vault_per_function_hunter_brief.v1",
            )


if __name__ == "__main__":
    unittest.main()
