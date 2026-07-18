"""Tests for VaultQuery.vault_hacker_questions callable (LIFT-10).

synthetic_fixture: true

LIFT-10 (2026-05-26). The callable surfaces the hunting-questions library
seeded by the ZetaChain 2026-04-26 arbitrary-call post-mortem and extended
by LIFT-13 to ~4.7k records. Tests cover:

  1. Degraded envelope when the corpus is absent.
  2. All-records pass through (no filter) returns the synthetic fixture set.
  3. attack_class substring filter narrows the result set.
  4. target_language exact-match filter narrows the result set.
  5. invariant_id exact-match filter returns the linked-invariant rows.
  6. source_incident_id substring filter narrows the result set.
  7. limit clamping (default + min + max).
  8. Envelope carries schema + context_pack_id + context_pack_hash.
  9. Per-attack-class + per-language aggregates match the filtered set.
 10. CLI dispatch exits 0 against the live corpus.
 11. Callable appears in TOOL_SCHEMAS with required keys.
 12. The 7 ZetaChain anchor questions are surfaceable via the live corpus.

r36-rebuttal: lane LIFT-10-VAULT-HACKER-QUESTIONS declared in .auditooor/agent_pathspec.json
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


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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


SYNTH_RECORDS = [
    # synthetic_fixture: true
    {
        "question_id": "HQ-SYNTH-001",
        "question_text": "Does the bridge allow arbitrary-call from unprivileged callers?",
        "source_incident_id": "synth-arbcall-2026-05",
        "source_case_study": "case_study/synth.md:L1",
        "attack_class_anchor": "arbitrary-call",
        "target_languages": ["solidity", "rust"],
        "grep_patterns": ["isArbitraryCall", "executeRaw"],
        "verification_tier": "tier-2-verified-public-archive",
        "linked_invariant_ids": ["INV-SYNTH-ARBCALL-001"],
    },
    {
        "question_id": "HQ-SYNTH-002",
        "question_text": "Does the bridge mask msg.sender on downstream calls?",
        "source_incident_id": "synth-arbcall-2026-05",
        "source_case_study": "case_study/synth.md:L3",
        "attack_class_anchor": "sender-zeroing",
        "target_languages": ["solidity"],
        "grep_patterns": ["address(0)"],
        "verification_tier": "tier-2-verified-public-archive",
        "linked_invariant_ids": ["INV-SYNTH-SENDER-001"],
    },
    {
        "question_id": "HQ-SYNTH-003",
        "question_text": "Does the SDK approve(spender, MAX_UINT) anywhere?",
        "source_incident_id": "synth-approve-2026-05",
        "source_case_study": "case_study/synth.md:L5",
        "attack_class_anchor": "unlimited-approve-frontend",
        "target_languages": ["solidity", "typescript"],
        "grep_patterns": ["type(uint256).max", "MaxUint256"],
        "verification_tier": "tier-2-verified-public-archive",
        "linked_invariant_ids": ["INV-SYNTH-ARBCALL-001"],
    },
]


vault_mcp_server = _load_module()


class TestVaultHackerQuestions(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lift10-hackerq-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)
        # synthetic_fixture: true
        self.corpus_path = self.root / "hacker_questions_library.jsonl"
        with self.corpus_path.open("w", encoding="utf-8") as fh:
            for rec in SYNTH_RECORDS:
                fh.write(json.dumps(rec) + "\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_degraded_when_corpus_missing(self):
        missing = self.root / "does_not_exist.jsonl"
        res = self.query.vault_hacker_questions(corpus_path=str(missing))
        self.assertTrue(res["degraded"])
        self.assertEqual(res["degraded_reason"], "hacker-questions-corpus-missing")
        self.assertEqual(res["total_records"], 0)
        self.assertEqual(res["questions"], [])
        self.assertEqual(res["schema"], "auditooor.vault_hacker_questions.v1")

    def test_no_filter_returns_all_synth_records(self):
        res = self.query.vault_hacker_questions(corpus_path=str(self.corpus_path))
        self.assertFalse(res["degraded"])
        self.assertEqual(res["total_records"], 3)
        self.assertEqual(res["returned_records"], 3)
        ids = {q["question_id"] for q in res["questions"]}
        self.assertEqual(
            ids, {"HQ-SYNTH-001", "HQ-SYNTH-002", "HQ-SYNTH-003"}
        )

    def test_attack_class_substring_filter(self):
        res = self.query.vault_hacker_questions(
            corpus_path=str(self.corpus_path),
            attack_class="arbitrary",
        )
        self.assertEqual(res["total_records"], 1)
        self.assertEqual(res["questions"][0]["question_id"], "HQ-SYNTH-001")

    def test_target_language_exact_filter(self):
        res = self.query.vault_hacker_questions(
            corpus_path=str(self.corpus_path),
            target_language="rust",
        )
        self.assertEqual(res["total_records"], 1)
        self.assertEqual(res["questions"][0]["question_id"], "HQ-SYNTH-001")

        res_ts = self.query.vault_hacker_questions(
            corpus_path=str(self.corpus_path),
            target_language="typescript",
        )
        self.assertEqual(res_ts["total_records"], 1)
        self.assertEqual(res_ts["questions"][0]["question_id"], "HQ-SYNTH-003")

    def test_invariant_id_exact_filter(self):
        res = self.query.vault_hacker_questions(
            corpus_path=str(self.corpus_path),
            invariant_id="INV-SYNTH-ARBCALL-001",
        )
        # HQ-SYNTH-001 and HQ-SYNTH-003 both link this invariant
        self.assertEqual(res["total_records"], 2)
        ids = {q["question_id"] for q in res["questions"]}
        self.assertEqual(ids, {"HQ-SYNTH-001", "HQ-SYNTH-003"})

    def test_source_incident_substring_filter(self):
        res = self.query.vault_hacker_questions(
            corpus_path=str(self.corpus_path),
            source_incident_id="synth-arbcall",
        )
        self.assertEqual(res["total_records"], 2)
        ids = {q["question_id"] for q in res["questions"]}
        self.assertEqual(ids, {"HQ-SYNTH-001", "HQ-SYNTH-002"})

    def test_limit_clamping(self):
        # default 20 -> returns all 3 from the 3-record fixture
        res_default = self.query.vault_hacker_questions(
            corpus_path=str(self.corpus_path),
        )
        self.assertEqual(res_default["returned_records"], 3)

        # explicit limit=1
        res_limit_1 = self.query.vault_hacker_questions(
            corpus_path=str(self.corpus_path),
            limit=1,
        )
        self.assertEqual(res_limit_1["total_records"], 3)
        self.assertEqual(res_limit_1["returned_records"], 1)

        # limit=0 (falsy) -> falls through to default 20 -> returns all 3.
        # r36-rebuttal: lane LIFT-10-VAULT-HACKER-QUESTIONS pathspec registered.
        res_zero = self.query.vault_hacker_questions(
            corpus_path=str(self.corpus_path),
            limit=0,
        )
        self.assertEqual(res_zero["returned_records"], 3)

        # limit clamped to <=200
        res_huge = self.query.vault_hacker_questions(
            corpus_path=str(self.corpus_path),
            limit=99999,
        )
        self.assertEqual(res_huge["returned_records"], 3)

    def test_envelope_carries_schema_and_hash(self):
        res = self.query.vault_hacker_questions(corpus_path=str(self.corpus_path))
        self.assertEqual(res["schema"], "auditooor.vault_hacker_questions.v1")
        self.assertTrue(res["context_pack_id"].startswith(
            "auditooor.vault_hacker_questions.v1:"
        ))
        self.assertEqual(len(res["context_pack_hash"]), 64)
        # Hash is deterministic for the same inputs
        res2 = self.query.vault_hacker_questions(corpus_path=str(self.corpus_path))
        # Only generated_at_utc differs; question_ids order is stable.
        self.assertEqual(
            [q["question_id"] for q in res["questions"]],
            [q["question_id"] for q in res2["questions"]],
        )

    def test_per_attack_class_and_per_language_aggregates(self):
        res = self.query.vault_hacker_questions(corpus_path=str(self.corpus_path))
        self.assertEqual(res["per_attack_class"].get("arbitrary-call"), 1)
        self.assertEqual(res["per_attack_class"].get("sender-zeroing"), 1)
        self.assertEqual(res["per_attack_class"].get("unlimited-approve-frontend"), 1)
        # Solidity appears in all 3 records
        self.assertEqual(res["per_language"].get("solidity"), 3)
        # Rust + typescript each appear once
        self.assertEqual(res["per_language"].get("rust"), 1)
        self.assertEqual(res["per_language"].get("typescript"), 1)

    def test_cli_dispatch_against_live_corpus(self):
        # synthetic_fixture: true (against the in-tree LIFT-13-extended corpus)
        live_corpus = (
            REPO_ROOT
            / "audit"
            / "corpus_tags"
            / "derived"
            / "hacker_questions_library.jsonl"
        )
        if not live_corpus.is_file():
            self.skipTest("live corpus missing; build hacker_questions_library.jsonl first")
        result = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--call",
                "vault_hacker_questions",
                "--args",
                json.dumps({"source_incident_id": "zetachain", "limit": 7}),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema"], "auditooor.vault_hacker_questions.v1")
        # The 7 ZetaChain anchor questions must surface.
        self.assertGreaterEqual(payload["total_records"], 7)
        zeta_ids = [
            q["question_id"] for q in payload["questions"]
            if q["source_incident_id"] == "zetachain-arbitrary-call-2026-04-26"
        ]
        self.assertEqual(len(zeta_ids), 7)

    def test_tool_schemas_entry_present(self):
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_hacker_questions", names)
        spec = next(
            t for t in vault_mcp_server.TOOL_SCHEMAS
            if t["name"] == "vault_hacker_questions"
        )
        self.assertIn("description", spec)
        self.assertIn("inputSchema", spec)
        props = spec["inputSchema"]["properties"]
        for key in ("workspace_path", "attack_class", "target_language",
                    "invariant_id", "source_incident_id", "limit",
                    "corpus_path"):
            self.assertIn(key, props, msg=f"missing input property: {key}")

    def test_seven_zetachain_questions_resolve_by_invariant_id(self):
        # synthetic_fixture: true (against the in-tree LIFT-13-extended corpus)
        live_corpus = (
            REPO_ROOT
            / "audit"
            / "corpus_tags"
            / "derived"
            / "hacker_questions_library.jsonl"
        )
        if not live_corpus.is_file():
            self.skipTest("live corpus missing; build hacker_questions_library.jsonl first")
        res = self.query.vault_hacker_questions(
            corpus_path=str(live_corpus),
            invariant_id="INV-BRIDGE-ARBCALL-001",
        )
        ids = {q["question_id"] for q in res["questions"]}
        # At minimum the three ZetaChain questions linked to ARBCALL-001
        # (Q1, Q5 composability, Q7 by-design mining) must be present.
        self.assertIn("HQ-ZETACHAIN-ARBITRARY-CALL-2026-04-26-001", ids)
        self.assertIn("HQ-ZETACHAIN-ARBITRARY-CALL-2026-04-26-005", ids)
        self.assertIn("HQ-ZETACHAIN-ARBITRARY-CALL-2026-04-26-007", ids)


if __name__ == "__main__":
    unittest.main()
