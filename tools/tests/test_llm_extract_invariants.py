"""Tests for ``tools/llm-extract-invariants.py`` + ``vault_invariant_library``.

Pillar-P1 MVP build (iter18 phase A, lane-PILLAR-P1-MVP-BUILD).

Exercises:

- All 10 categories classified by keyword heuristic.
- hand-extract mode end-to-end on a synthetic seed JSONL.
- llm-sweep mode refuses cleanly without API key.
- llm-sweep mode refuses cleanly even with API key (operator-auth required).
- Spot-check Y-rate calculation.
- JSON schema validity of emitted rows.
- vault_invariant_library MCP callable filter logic.
- Idempotent re-run (no duplicate invariant emit).
- Verification-tier inheritance per Rule 37.
- Build-index aggregates correctly.
- Statement template uses MUST / MUST-NOT phrasing.
- Per-category statement coverage (all 10 cats emit valid statements).
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "llm-extract-invariants.py"
SWEEP_PATH = REPO_ROOT / "tools" / "llm-sweep-invariants-mvp.py"
MCP_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_tool() -> Any:
    return _load_module("llm_extract_invariants_test", TOOL_PATH)


def _load_sweep_tool() -> Any:
    return _load_module("llm_sweep_invariants_mvp_test", SWEEP_PATH)


def _load_mcp() -> Any:
    return _load_module("vault_mcp_server_invariant_lib_test", MCP_PATH)


def _seed_index(tmp_dir: Path) -> Path:
    """Write a synthetic by_attack_class.jsonl that exercises all 10 categories.

    The tag YAML lookup falls back to the index row when the tag file is
    missing, so we can drive the whole pipeline from a single JSONL file.
    """
    rows = [
        # uniqueness x4 -- enough variety for distinct attack signatures
        {
            "record_id": "test:uni:001",
            "tag_file": "_missing.yaml",
            "attack_class": "signature-replay",
            "bug_class": "replay",
            "target_repo": "test-org/repo-a",
            "target_language": "solidity",
            "fix_pattern": "increment nonce before transfer",
            "attacker_action_sequence": "Attacker replays a permit signature; nonce never advances; duplicate withdraw is permitted.",
            "verification_tier": "tier-2-verified-public-archive",
        },
        {
            "record_id": "test:uni:002",
            "tag_file": "_missing.yaml",
            "attack_class": "signature-replay",
            "bug_class": "duplicate-consumption",
            "target_repo": "test-org/repo-b",
            "target_language": "solidity",
            "fix_pattern": "mark consumed nonce",
            "attacker_action_sequence": "Duplicate processed_txid acceptance; nonce stuck on failure.",
            "verification_tier": "tier-2-verified-public-archive",
        },
        # ordering
        {
            "record_id": "test:ord:001",
            "tag_file": "_missing.yaml",
            "attack_class": "out-of-order-execution",
            "bug_class": "operation-order-violation",
            "target_repo": "test-org/repo-c",
            "target_language": "solidity",
            "fix_pattern": "hook ordering enforced",
            "attacker_action_sequence": "Performance-fee accrual step skipped via direct user-callable; operation order broken.",
            "verification_tier": "tier-2-verified-public-archive",
        },
        # monotonicity
        {
            "record_id": "test:mon:001",
            "tag_file": "_missing.yaml",
            "attack_class": "monotonicity-violation",
            "bug_class": "counter-decrement",
            "target_repo": "test-org/repo-d",
            "target_language": "go",
            "fix_pattern": "always-increment counter regardless of branch",
            "attacker_action_sequence": "Nonce stuck on failure; monotonic counter never advances after error branch.",
            "verification_tier": "tier-1-officially-disclosed",
        },
        # custody
        {
            "record_id": "test:cus:001",
            "tag_file": "_missing.yaml",
            "attack_class": "custody-violation",
            "bug_class": "missing-owner-check",
            "target_repo": "test-org/repo-e",
            "target_language": "solidity",
            "fix_pattern": "msg.sender == owner check before transfer-from",
            "attacker_action_sequence": "Withdraw path lacks owner-only modifier; token transfer to attacker.",
            "verification_tier": "tier-2-verified-public-archive",
        },
        # atomicity (multiple variants)
        {
            "record_id": "test:atm:001",
            "tag_file": "_missing.yaml",
            "attack_class": "reentrancy",
            "bug_class": "missing-cei",
            "target_repo": "test-org/repo-f",
            "target_language": "solidity",
            "fix_pattern": "checks-effects-interactions pattern + nonReentrant",
            "attacker_action_sequence": "External callback re-enters vault before balance write; vault-reentry drains.",
            "verification_tier": "tier-2-verified-public-archive",
        },
        # conservation (totalSupply skew)
        {
            "record_id": "test:con:001",
            "tag_file": "_missing.yaml",
            "attack_class": "conservation-break",
            "bug_class": "share-supply-skew",
            "target_repo": "test-org/repo-g",
            "target_language": "solidity",
            "fix_pattern": "totalSupply invariant + dead shares",
            "attacker_action_sequence": "First-deposit attack on ERC-4626; 1-wei donation breaks share-supply invariant.",
            "verification_tier": "tier-2-verified-public-archive",
        },
        # authorization (UUPS)
        {
            "record_id": "test:aut:001",
            "tag_file": "_missing.yaml",
            "attack_class": "missing-modifier",
            "bug_class": "uups-no-auth",
            "target_repo": "test-org/repo-h",
            "target_language": "solidity",
            "fix_pattern": "authorize before mutating implementation slot",
            "attacker_action_sequence": "_authorizeUpgrade missing onlyOwner; attacker upgrades implementation; access control broken.",
            "verification_tier": "tier-2-verified-public-archive",
        },
        # freshness
        {
            "record_id": "test:fre:001",
            "tag_file": "_missing.yaml",
            "attack_class": "stale-oracle",
            "bug_class": "freshness-check-broken",
            "target_repo": "test-org/repo-i",
            "target_language": "solidity",
            "fix_pattern": "updatedAt staleness check + heartbeat",
            "attacker_action_sequence": "Chainlink updatedAt check uses wrong semantics; oracle stale data accepted.",
            "verification_tier": "tier-2-verified-public-archive",
        },
        # bounds
        {
            "record_id": "test:bnd:001",
            "tag_file": "_missing.yaml",
            "attack_class": "array-bound-violation",
            "bug_class": "unbounded-array",
            "target_repo": "test-org/repo-j",
            "target_language": "rust",
            "fix_pattern": "bound check + max cap",
            "attacker_action_sequence": "Validator-set size unbounded; array length grows without cap; DoS via unbounded loop.",
            "verification_tier": "tier-2-verified-public-archive",
        },
        # determinism
        {
            "record_id": "test:det:001",
            "tag_file": "_missing.yaml",
            "attack_class": "non-determinism",
            "bug_class": "apphash-divergence",
            "target_repo": "test-org/repo-k",
            "target_language": "go",
            "fix_pattern": "deterministic serialization + canonical EIP-712 domain",
            "attacker_action_sequence": "AppHash divergence on identical inputs; non-determinism in consensus path; hashstruct ordering inconsistent.",
            "verification_tier": "tier-2-verified-public-archive",
        },
    ]
    path = tmp_dir / "by_attack_class.jsonl"
    path.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n",
        encoding="utf-8",
    )
    return path


class ClassifierTests(unittest.TestCase):
    """Exercises ``classify_record`` for each of the 10 categories."""

    def setUp(self) -> None:
        self.tool = _load_tool()

    def _classify(self, **kw: Any) -> tuple[str | None, int]:
        cat, score, _ = self.tool.classify_record(kw)
        return cat, score

    def test_uniqueness(self) -> None:
        cat, score = self._classify(
            attack_class="signature-replay",
            fix_pattern="increment nonce processed_txid",
            attacker_action_sequence="replay attack",
        )
        self.assertEqual(cat, "uniqueness")
        self.assertGreaterEqual(score, 2)

    def test_ordering(self) -> None:
        cat, _ = self._classify(
            attack_class="out-of-order-execution",
            fix_pattern="hook ordering enforced",
            attacker_action_sequence="step out of sequence; operation order broken",
        )
        self.assertEqual(cat, "ordering")

    def test_monotonicity(self) -> None:
        cat, _ = self._classify(
            attack_class="monotonicity-violation",
            attacker_action_sequence="monotonic counter never advances; nonce stuck on failure",
        )
        self.assertEqual(cat, "monotonicity")

    def test_custody(self) -> None:
        cat, _ = self._classify(
            attack_class="custody-violation",
            fix_pattern="owner-only modifier added",
            attacker_action_sequence="token transfer without owner check; withdraw drains",
        )
        self.assertEqual(cat, "custody")

    def test_atomicity(self) -> None:
        cat, _ = self._classify(
            attack_class="reentrancy",
            fix_pattern="checks-effects-interactions",
            attacker_action_sequence="callback re-enters vault; vault-reentry pre-state-write",
        )
        self.assertEqual(cat, "atomicity")

    def test_conservation(self) -> None:
        cat, _ = self._classify(
            attack_class="conservation-break",
            fix_pattern="totalSupply invariant",
            attacker_action_sequence="first-deposit attack on erc-4626 share-supply",
        )
        self.assertEqual(cat, "conservation")

    def test_authorization(self) -> None:
        cat, _ = self._classify(
            attack_class="admin-bypass",
            attacker_action_sequence="missing-modifier on _authorizeUpgrade allows access control bypass",
        )
        self.assertEqual(cat, "authorization")

    def test_freshness(self) -> None:
        cat, _ = self._classify(
            attack_class="stale-oracle",
            attacker_action_sequence="oracle updatedAt check fails; staleness window broken; chainlink heartbeat ignored",
        )
        self.assertEqual(cat, "freshness")

    def test_bounds(self) -> None:
        cat, _ = self._classify(
            attack_class="overflow",
            attacker_action_sequence="unbounded array length; array-bound exceeded; safety cap missing",
        )
        self.assertEqual(cat, "bounds")

    def test_determinism(self) -> None:
        cat, _ = self._classify(
            attack_class="non-determinism",
            attacker_action_sequence="apphash divergence; deterministic serialization broken; hashstruct unstable",
        )
        self.assertEqual(cat, "determinism")

    def test_unclassifiable_returns_none(self) -> None:
        cat, score = self._classify(
            attack_class="completely-unknown",
            fix_pattern="something orthogonal",
            attacker_action_sequence="zzz no keywords here",
        )
        self.assertIsNone(cat)
        self.assertEqual(score, 0)


class HandExtractEndToEndTests(unittest.TestCase):
    """End-to-end exercise of hand-extract mode + spot-check."""

    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.index = _seed_index(self.tmp_path)
        self.output = self.tmp_path / "extracted.jsonl"
        self.failed = self.tmp_path / "failed.jsonl"
        self.pilot = self.tmp_path / "pilot.jsonl"
        # Empty pilot for the test.
        self.pilot.write_text("", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, records: int = 100) -> dict[str, Any]:
        argv = [
            "--mode", "hand-extract",
            "--records", str(records),
            "--index", str(self.index),
            "--tags-dir", str(self.tmp_path),
            "--output", str(self.output),
            "--failed", str(self.failed),
            "--pilot", str(self.pilot),
        ]
        rc = self.tool.main(argv)
        self.assertEqual(rc, 0)
        rows = self.tool.load_jsonl(self.output)
        return {"rows": rows}

    def test_extract_emits_all_categories(self) -> None:
        result = self._run()
        cats = {r["category"] for r in result["rows"]}
        # Sample seeds cover all 10 categories.
        self.assertEqual(cats, set(self.tool.CATEGORIES))

    def test_schema_validity(self) -> None:
        result = self._run()
        for row in result["rows"]:
            self.assertEqual(row["schema_version"], self.tool.SCHEMA_VERSION)
            self.assertIn(row["category"], self.tool.CATEGORIES)
            self.assertIn(
                row["abstraction_level"], self.tool.VALID_ABSTRACTIONS
            )
            self.assertIsInstance(row["source_finding_ids"], list)
            self.assertTrue(row["statement"].strip())
            self.assertTrue(row["invariant_id"].startswith("INV-"))
            self.assertTrue(row["verification_tier"].startswith("tier-"))

    def test_statement_uses_must_phrasing(self) -> None:
        result = self._run()
        for row in result["rows"]:
            self.assertIn(
                "MUST",
                row["statement"].upper(),
                msg=f"Statement missing MUST: {row['statement']!r}",
            )

    def test_verification_tier_inherits_min(self) -> None:
        # Seed has tier-1-officially-disclosed on the monotonicity row.
        result = self._run()
        mono = [r for r in result["rows"] if r["category"] == "monotonicity"]
        self.assertTrue(mono, "expected at least one monotonicity row")
        self.assertEqual(
            mono[0]["verification_tier"], "tier-1-officially-disclosed"
        )

    def test_spot_check_yrate_above_80(self) -> None:
        self._run()
        result = self.tool.run_spot_check(
            self.tool.load_jsonl(self.output), sample_size=10
        )
        self.assertGreaterEqual(result["y_rate"], 0.80)

    def test_idempotent_rerun(self) -> None:
        self._run()
        first_count = len(self.tool.load_jsonl(self.output))
        # Run again on same data.
        self._run()
        second_count = len(self.tool.load_jsonl(self.output))
        # No additional rows because every group's (cat, attack_sig) is
        # already in the existing output.
        self.assertEqual(first_count, second_count)


class SourceBackedChainMetadataTests(unittest.TestCase):
    """Producer/consumer metadata is emitted only when source refs exist."""

    def setUp(self) -> None:
        self.tool = _load_tool()

    def _entry_for(self, record: dict[str, Any]) -> dict[str, Any]:
        groups = self.tool.group_records_by_signal([record])
        entries = self.tool.assemble_invariants_from_groups(
            groups,
            {cat: 0 for cat in self.tool.CATEGORIES},
            "unit-test",
            min_group_size=1,
        )
        self.assertEqual(len(entries), 1)
        return entries[0]

    def test_emits_source_backed_producer_consumer_metadata(self) -> None:
        entry = self._entry_for({
            "record_id": "src:chain:001",
            "tag_file": "_missing.yaml",
            "attack_class": "reentrancy",
            "bug_class": "missing-cei",
            "target_repo": "test-org/repo-chain",
            "target_language": "solidity",
            "fix_pattern": "checks-effects-interactions pattern",
            "attacker_action_sequence": "callback re-enters vault before state write",
            "source_audit_ref": "prior-audit:test:prior_audits/Test.txt:L42:S3",
            "source_ref": "contracts/Vault.sol:88",
            "produces_state": ["state:reentrant-execution-context"],
            "requires_state": ["state:attacker-controlled-callback"],
            "verification_tier": "tier-2-verified-public-archive",
        })

        self.assertEqual(
            entry["source_refs"],
            ["contracts/Vault.sol:88", "prior_audits/Test.txt:42"],
        )
        self.assertEqual(
            entry["produces_state"],
            ["state:reentrant-execution-context"],
        )
        self.assertEqual(
            entry["requires_state"],
            ["state:attacker-controlled-callback"],
        )
        self.assertEqual(entry["producer_source_refs"], entry["source_refs"])
        self.assertEqual(entry["consumer_source_refs"], entry["source_refs"])

    def test_omits_chain_metadata_without_source_refs(self) -> None:
        entry = self._entry_for({
            "record_id": "src:chain:002",
            "tag_file": "_missing.yaml",
            "attack_class": "reentrancy",
            "bug_class": "missing-cei",
            "target_repo": "test-org/repo-chain",
            "target_language": "solidity",
            "fix_pattern": "checks-effects-interactions pattern",
            "attacker_action_sequence": "callback re-enters vault before state write",
            "produces_state": ["state:reentrant-execution-context"],
            "requires_state": ["state:attacker-controlled-callback"],
            "verification_tier": "tier-2-verified-public-archive",
        })

        self.assertNotIn("source_refs", entry)
        self.assertNotIn("produces_state", entry)
        self.assertNotIn("requires_state", entry)
        self.assertNotIn("producer_source_refs", entry)
        self.assertNotIn("consumer_source_refs", entry)


class LLMSweepRefusalTests(unittest.TestCase):
    """LLM-sweep mode must refuse without API key AND with API key."""

    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_refuses_without_api_key(self) -> None:
        # Make sure ANTHROPIC_API_KEY is unset for this test.
        env_was = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            out = self.tool.llm_sweep(500, "anthropic")
        finally:
            if env_was is not None:
                os.environ["ANTHROPIC_API_KEY"] = env_was
        self.assertEqual(out["status"], "refused")
        self.assertEqual(out["reason"], "no_api_key")
        self.assertIn("remediation", out)

    def test_refuses_with_api_key_due_to_operator_auth(self) -> None:
        env_was = os.environ.get("ANTHROPIC_API_KEY")
        os.environ["ANTHROPIC_API_KEY"] = "fake-key-for-test"
        try:
            out = self.tool.llm_sweep(500, "anthropic")
        finally:
            if env_was is None:
                os.environ.pop("ANTHROPIC_API_KEY", None)
            else:
                os.environ["ANTHROPIC_API_KEY"] = env_was
        self.assertEqual(out["status"], "refused")
        self.assertEqual(out["reason"], "operator_authorization_required")

    def test_unknown_provider_refused(self) -> None:
        out = self.tool.llm_sweep(10, "fictional-provider")
        self.assertEqual(out["status"], "refused")
        self.assertEqual(out["reason"], "unknown_provider")


class SpotCheckHeuristicTests(unittest.TestCase):
    """Spot-check passes / fails on specific entry shapes."""

    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_pass_with_full_entry(self) -> None:
        entry = {
            "category": "custody",
            "statement": "A token balance MUST NOT be movable by an actor other than the owner.",
            "target_lang": "solidity",
            "abstraction_level": "protocol-invariant",
            "source_finding_ids": ["a:1", "b:2"],
            "defense_layer": "onlyOwner modifier",
        }
        ok, fails = self.tool.spot_check_entry(entry)
        self.assertTrue(ok, msg=fails)

    def test_fail_no_must(self) -> None:
        entry = {
            "category": "custody",
            "statement": "An owner check should be added.",
            "target_lang": "solidity",
            "abstraction_level": "protocol-invariant",
            "source_finding_ids": ["a:1", "b:2"],
            "defense_layer": "modifier",
        }
        ok, fails = self.tool.spot_check_entry(entry)
        self.assertFalse(ok)
        self.assertIn("statement_no_must", fails)

    def test_fail_insufficient_sources_unless_singleton(self) -> None:
        entry = {
            "category": "custody",
            "statement": "A token balance MUST be owner-bound.",
            "target_lang": "solidity",
            "abstraction_level": "protocol-invariant",
            "source_finding_ids": ["only:1"],
            "defense_layer": "modifier",
        }
        ok, fails = self.tool.spot_check_entry(entry)
        self.assertFalse(ok)
        self.assertIn("source_ids_lt_2", fails)

    def test_pass_singleton_with_flag(self) -> None:
        entry = {
            "category": "custody",
            "statement": "A token balance MUST be owner-bound.",
            "target_lang": "solidity",
            "abstraction_level": "protocol-invariant",
            "source_finding_ids": ["only:1"],
            "defense_layer": "modifier",
            "singleton": True,
        }
        ok, _ = self.tool.spot_check_entry(entry)
        self.assertTrue(ok)

    def test_paid_sweep_gate_requires_explicit_threshold(self) -> None:
        entries = [
            {
                "category": "custody",
                "statement": "A withdrawal MUST bind transfer authority to the recorded owner before moving assets.",
                "target_lang": "solidity",
                "abstraction_level": "protocol-invariant",
                "source_finding_ids": ["a:1", "b:2"],
                "defense_layer": "owner-bound transfer authorization",
                "commit_point_pattern": "owner == msg.sender",
            },
            {
                "category": "custody",
                "statement": "A withdrawal MUST bind transfer authority to the recorded owner before moving assets.",
                "target_lang": "solidity",
                "abstraction_level": "protocol-invariant",
                "source_finding_ids": ["c:1", "d:2"],
                "defense_layer": "owner-bound transfer authorization",
                "commit_point_pattern": "owner == msg.sender",
            },
            {
                "category": "custody",
                "statement": "A withdrawal should check ownership.",
                "target_lang": "solidity",
                "abstraction_level": "protocol-invariant",
                "source_finding_ids": ["e:1", "f:2"],
                "defense_layer": "owner-bound transfer authorization",
                "commit_point_pattern": "owner == msg.sender",
            },
        ]
        result = self.tool.evaluate_spot_check_gate(
            entries,
            sample_size=3,
            min_y_rate=0.90,
        )
        self.assertEqual(result["min_y_rate"], 0.90)
        self.assertFalse(result["promotion_allowed"])
        self.assertIn("spot_check_y_rate_below_threshold", result["promotion_blockers"])

    def test_paid_sweep_gate_blocks_template_or_broad_statements(self) -> None:
        entry = {
            "invariant_id": "INV-CUS-EX-0001",
            "category": "custody",
            "statement": self.tool.STATEMENT_TEMPLATES["custody"][0],
            "target_lang": "solidity",
            "abstraction_level": "protocol-invariant",
            "source_finding_ids": ["a:1", "b:2"],
            "defense_layer": "owner-bound transfer authorization",
            "commit_point_pattern": "owner == msg.sender",
        }
        result = self.tool.evaluate_spot_check_gate(
            [entry],
            sample_size=1,
            min_y_rate=0.90,
            disallow_template_or_broad=True,
        )
        self.assertFalse(result["promotion_allowed"])
        self.assertIn("template_or_broad_statements_present", result["promotion_blockers"])
        self.assertEqual(result["template_or_broad_invariant_ids"], ["INV-CUS-EX-0001"])


class LLMSweepMVPGateTests(unittest.TestCase):
    """Direct tests for paid-sweep policy without making API calls."""

    def setUp(self) -> None:
        self.sweep = _load_sweep_tool()

    def test_sweep_spot_check_delegates_to_extractor_schema_policy(self) -> None:
        entry = {
            "category": "custody",
            "statement": "A token balance MUST be owner-bound.",
            "target_lang": "nonsense",
            "abstraction_level": "protocol-invariant",
            "source_finding_ids": ["a:1", "b:2"],
            "defense_layer": "owner check",
        }
        ok, fails = self.sweep.spot_check_entry(entry)
        self.assertFalse(ok)
        self.assertIn("invalid_target_lang", fails)

    def test_sweep_promotion_gate_blocks_broad_output(self) -> None:
        entry = {
            "invariant_id": "INV-AUT-EX-0001",
            "category": "authorization",
            "statement": "A caller MUST be validated properly before state changes.",
            "target_lang": "solidity",
            "abstraction_level": "protocol-invariant",
            "source_finding_ids": ["a:1", "b:2"],
            "defense_layer": "role check",
            "commit_point_pattern": "",
        }
        result = self.sweep.evaluate_paid_sweep_gate([entry], sample_size=1)
        self.assertFalse(result["promotion_allowed"])
        self.assertIn("template_or_broad_statements_present", result["promotion_blockers"])
        self.assertEqual(result["min_y_rate"], self.sweep.MIN_PROMOTION_Y_RATE)

    def test_full_cohort_selects_every_input_row(self) -> None:
        entries = (
            [{"invariant_id": f"custody-{i}", "category": "custody"} for i in range(7)]
            + [{"invariant_id": f"auth-{i}", "category": "authorization"} for i in range(2)]
            + [{"invariant_id": "oracle-0", "category": "oracle"}]
        )

        cohort, by_cat, mode = self.sweep.select_sweep_cohort(
            entries,
            len(entries),
            seed=7,
        )

        self.assertEqual(mode, "full input")
        self.assertEqual(len(by_cat), 3)
        self.assertEqual([entry["invariant_id"] for entry in cohort], [entry["invariant_id"] for entry in entries])


class BuildIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_build_index_aggregates_correctly(self) -> None:
        pilot = [
            {
                "invariant_id": "INV-P-001",
                "category": "uniqueness",
                "target_lang": "solidity",
                "abstraction_level": "protocol-invariant",
                "verification_tier": "tier-2-verified-public-archive",
                "source_finding_ids": ["src:p:1"],
            },
        ]
        extracted = [
            {
                "invariant_id": "INV-CUST-EX-0001",
                "category": "custody",
                "target_lang": "rust",
                "abstraction_level": "cross-domain",
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                "source_finding_ids": ["src:e:1", "src:e:2"],
            },
        ]
        idx = self.tool.build_index(pilot, extracted)
        self.assertEqual(idx["total_invariants"], 2)
        self.assertEqual(idx["per_category"]["uniqueness"], 1)
        self.assertEqual(idx["per_category"]["custody"], 1)
        self.assertEqual(idx["per_language"]["solidity"], 1)
        self.assertEqual(idx["per_language"]["rust"], 1)
        # Reverse lookup correctness.
        self.assertEqual(
            idx["reverse_lookup_finding_to_invariant"]["src:e:1"],
            ["INV-CUST-EX-0001"],
        )


class MCPCallableFilterTests(unittest.TestCase):
    """Exercises ``vault_invariant_library`` MCP callable."""

    def setUp(self) -> None:
        self.mcp_mod = _load_mcp()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.pilot_audited = self.tmp_path / "pilot_audited.jsonl"
        self.pilot = self.tmp_path / "pilot.jsonl"
        self.extracted = self.tmp_path / "extracted.jsonl"
        self.workspace_extracted = self.tmp_path / "workspace_extracted.jsonl"
        pilot_rows = [
            {
                "schema_version": "auditooor.invariant_pilot.v1",
                "invariant_id": "INV-UNI-001",
                "category": "uniqueness",
                "statement": "A signature MUST be unique.",
                "target_lang": "solidity",
                "source_finding_ids": ["a:1", "b:2"],
                "abstraction_level": "protocol-invariant",
                "commit_point_pattern": "nonce_advance",
                "defense_layer": "nonce-mapping",
                "verification_tier": "tier-2-verified-public-archive",
            },
            {
                "schema_version": "auditooor.invariant_pilot.v1",
                "invariant_id": "INV-CUS-001",
                "category": "custody",
                "statement": "Owner MUST authorize transfers.",
                "target_lang": "rust",
                "source_finding_ids": ["c:1", "d:2"],
                "abstraction_level": "cross-domain",
                "commit_point_pattern": "owner-check",
                "defense_layer": "modifier",
                "verification_tier": "tier-1-officially-disclosed",
            },
        ]
        extracted_rows = [
            {
                "schema_version": "auditooor.invariant_extraction.v1",
                "invariant_id": "INV-AUT-EX-0001",
                "category": "authorization",
                "statement": "Admin paths MUST check role.",
                "target_lang": "solidity",
                "source_finding_ids": ["e:1", "f:2"],
                "abstraction_level": "cross-domain",
                "commit_point_pattern": "onlyOwner",
                "defense_layer": "modifier",
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                "extractor": "hand-extract",
            },
        ]
        self.pilot.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in pilot_rows) + "\n",
            encoding="utf-8",
        )
        self.extracted.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in extracted_rows) + "\n",
            encoding="utf-8",
        )
        # Default test mode: audited subset empty -> callable must fall back
        # to breadth (pilot + extracted) so legacy expectations hold.
        self.pilot_audited.write_text("", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _query(self, vault: Any, **kwargs: Any) -> dict[str, Any]:
        args = {
            "pilot_audited_path": str(self.pilot_audited),
            "pilot_path": str(self.pilot),
            "extracted_path": str(self.extracted),
            "workspace_extracted_path": str(self.workspace_extracted),
            **kwargs,
        }
        return vault.call("vault_invariant_library", args)

    def _vault(self) -> Any:
        return self.mcp_mod.VaultQuery(
            self.mcp_mod.DEFAULT_VAULT, self.mcp_mod.REPO_ROOT
        )

    def test_envelope_shape(self) -> None:
        vault = self._vault()
        out = self._query(vault)
        self.assertEqual(out["schema"], "auditooor.vault_invariant_library.v1")
        self.assertIn("context_pack_id", out)
        self.assertIn("context_pack_hash", out)
        self.assertFalse(out.get("degraded"))
        self.assertEqual(out["total_invariants_matched"], 3)

    def test_category_filter(self) -> None:
        vault = self._vault()
        out = self._query(vault, category="custody")
        self.assertEqual(out["total_invariants_matched"], 1)
        self.assertEqual(out["invariants"][0]["category"], "custody")

    def test_target_lang_filter(self) -> None:
        vault = self._vault()
        out = self._query(vault, target_lang="rust")
        self.assertEqual(out["total_invariants_matched"], 1)
        self.assertEqual(out["invariants"][0]["target_lang"], "rust")

    def test_abstraction_level_filter(self) -> None:
        vault = self._vault()
        out = self._query(vault, abstraction_level="cross-domain")
        cats = {r["category"] for r in out["invariants"]}
        self.assertIn("custody", cats)
        self.assertIn("authorization", cats)

    def test_min_verification_tier_drops_lower(self) -> None:
        vault = self._vault()
        # min_tier=2 keeps tier-1 + tier-2, drops the tier-3-extracted row.
        out = self._query(vault, min_verification_tier=2)
        ids = {r["invariant_id"] for r in out["invariants"]}
        self.assertIn("INV-UNI-001", ids)
        self.assertIn("INV-CUS-001", ids)
        self.assertNotIn("INV-AUT-EX-0001", ids)

    def test_include_pilot_false(self) -> None:
        vault = self._vault()
        out = self._query(vault, include_pilot=False)
        ids = {r["invariant_id"] for r in out["invariants"]}
        self.assertEqual(ids, {"INV-AUT-EX-0001"})

    def test_workspace_invariant_candidates_ingested(self) -> None:
        candidate = {
            "schema_version": "auditooor.invariant_candidate.v1",
            "invariant_id": "INV-HYPERBRIDGE-001",
            "target": "HYPERBRIDGE",
            "statement": "Receipt existence MUST imply timestamp < timeout.",
            "enforcing_code_path": ["modules/ismp/core/src/handlers/request.rs:62-65"],
            "verification_tier": "tier-2-verified-public-archive",
            "source_lane": "HYPERBRIDGE-DRILL-7",
            "audit_pin": "auditooor.vault_active_roadmap.v1:abc123",
        }
        self.workspace_extracted.write_text(
            json.dumps(candidate, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        vault = self._vault()
        out = self._query(vault, include_pilot=False, min_verification_tier=2)
        ids = {r["invariant_id"] for r in out["invariants"]}
        self.assertIn("INV-HYPERBRIDGE-001", ids)
        self.assertIn(self.workspace_extracted.name, out["source_refs"])

    def test_limit_clamp(self) -> None:
        vault = self._vault()
        out = self._query(vault, limit=1)
        self.assertEqual(len(out["invariants"]), 1)
        self.assertEqual(out["filters"]["limit"], 1)
        # Total still reports the full match count.
        self.assertEqual(out["total_invariants_matched"], 3)

    def test_cli_limit_alias_bounds_invariants(self) -> None:
        args = {
            "pilot_audited_path": str(self.pilot_audited),
            "pilot_path": str(self.pilot),
            "extracted_path": str(self.extracted),
            "workspace_extracted_path": str(self.workspace_extracted),
        }
        proc = subprocess.run(
            [
                sys.executable,
                str(MCP_PATH),
                "--call",
                "vault_invariant_library",
                "--limit",
                "1",
                "--args",
                json.dumps(args, sort_keys=True),
            ],
            check=True,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
        )
        out = json.loads(proc.stdout)
        self.assertEqual(len(out["invariants"]), 1)
        self.assertEqual(out["filters"]["limit"], 1)
        self.assertEqual(out["total_invariants_matched"], 3)

    def test_cli_args_limit_overrides_limit_alias(self) -> None:
        args = {
            "pilot_audited_path": str(self.pilot_audited),
            "pilot_path": str(self.pilot),
            "extracted_path": str(self.extracted),
            "workspace_extracted_path": str(self.workspace_extracted),
            "limit": 2,
        }
        proc = subprocess.run(
            [
                sys.executable,
                str(MCP_PATH),
                "--call",
                "vault_invariant_library",
                "--limit",
                "1",
                "--args",
                json.dumps(args, sort_keys=True),
            ],
            check=True,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
        )
        out = json.loads(proc.stdout)
        self.assertEqual(len(out["invariants"]), 2)
        self.assertEqual(out["filters"]["limit"], 2)

    def test_degraded_when_sources_empty(self) -> None:
        vault = self._vault()
        empty_pilot = self.tmp_path / "empty_pilot.jsonl"
        empty_extracted = self.tmp_path / "empty_extracted.jsonl"
        empty_pilot.write_text("", encoding="utf-8")
        empty_extracted.write_text("", encoding="utf-8")
        out = vault.call(
            "vault_invariant_library",
            {
                "pilot_audited_path": str(self.pilot_audited),
                "pilot_path": str(empty_pilot),
                "extracted_path": str(empty_extracted),
                "workspace_extracted_path": str(self.workspace_extracted),
            },
        )
        self.assertTrue(out.get("degraded"))
        self.assertEqual(out["reason"], "both_sources_empty")

    def test_pilot_first_ordering(self) -> None:
        vault = self._vault()
        out = self._query(vault)
        # First two are pilot rows; the third is extracted.
        sources = [r.get("_source") for r in out["invariants"]]
        self.assertEqual(sources[:2], ["pilot", "pilot"])

    def test_audited_primary_prefers_audited_subset(self) -> None:
        vault = self._vault()
        audited_rows = [
            {
                "schema_version": "auditooor.invariant_pilot.v1",
                "invariant_id": "INV-AUD-001",
                "category": "authorization",
                "statement": "Audited path must be default.",
                "target_lang": "solidity",
                "source_finding_ids": ["aud:1"],
                "abstraction_level": "protocol-invariant",
                "quality_audited": True,
                "audit_verdict": "TRUE-POSITIVE",
            },
            {
                "schema_version": "auditooor.invariant_pilot.v1",
                "invariant_id": "INV-AUD-002",
                "category": "authorization",
                "statement": "Rejected audited row should be filtered.",
                "target_lang": "solidity",
                "source_finding_ids": ["aud:2"],
                "abstraction_level": "protocol-invariant",
                "quality_audited": False,
                "audit_verdict": "FALSE-POSITIVE",
            },
        ]
        self.pilot_audited.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in audited_rows) + "\n",
            encoding="utf-8",
        )
        out = self._query(vault)
        self.assertEqual(out["quality_source"], "audited_primary")
        self.assertFalse(out["fallback_to_breadth"])
        self.assertEqual(out["total_invariants_matched"], 1)
        self.assertEqual(out["invariants"][0]["invariant_id"], "INV-AUD-001")
        self.assertEqual(out["invariants"][0]["_source"], "pilot_audited")

    def test_audited_primary_honors_limit(self) -> None:
        vault = self._vault()
        audited_rows = [
            {
                "schema_version": "auditooor.invariant_pilot.v1",
                "invariant_id": f"INV-AUD-{idx:03d}",
                "category": "authorization",
                "statement": f"Audited invariant {idx}.",
                "target_lang": "solidity",
                "source_finding_ids": [f"aud:{idx}"],
                "abstraction_level": "protocol-invariant",
                "quality_audited": True,
                "audit_verdict": "TRUE-POSITIVE",
            }
            for idx in range(1, 4)
        ]
        self.pilot_audited.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in audited_rows) + "\n",
            encoding="utf-8",
        )

        out = self._query(vault, limit=2)

        self.assertEqual(out["quality_source"], "audited_primary")
        self.assertFalse(out["fallback_to_breadth"])
        self.assertEqual(out["total_invariants_matched"], 3)
        self.assertEqual(out["filters"]["limit"], 2)
        self.assertEqual(len(out["invariants"]), 2)
        self.assertEqual(
            [row["invariant_id"] for row in out["invariants"]],
            ["INV-AUD-001", "INV-AUD-002"],
        )


if __name__ == "__main__":
    unittest.main()
