import importlib.util
import hashlib
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "awareness_ledger", Path(__file__).resolve().parents[1] / "awareness-ledger.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


PIN = "commit:abc123"
KINDS = sorted(MODULE.SOURCE_KINDS)


def row(source_id, kind, state="team_aware", **extra):
    content = "semantic evidence for " + source_id
    value = {
        "source_id": source_id,
        "source_kind": kind,
        "pin_binding": PIN,
        "content": content,
        "source_ref": f"https://github.example/{kind}/{source_id}",
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "awareness_state": state,
    }
    value.update(extra)
    return value


def candidate(source_ids, state="team_aware", **extra):
    value = {
        "candidate_id": "cand-1",
        "source_ids": source_ids,
        "pin_binding": PIN,
        "root_cause": "missing binding",
        "affected_path": "Router.execute -> Vault.transfer",
        "required_fix": "bind the recipient to the signed intent",
        "reviewer_rationale": "Reviewed the cited evidence and exact finding identity.",
        "semantic_review": {
            "reviewer_id": "reviewer-1",
            "reviewed_at": "2026-07-18T10:00:00Z",
            "method": "contextual semantic review",
            "rationale": "The source records the team's disposition.",
            "source_ids": source_ids,
        },
    }
    value.update(extra)
    return value


def manifest(rows, candidates):
    return {
        "audit_pin": PIN,
        "expected_sources": [
            {
                "source_id": item["source_id"],
                "source_kind": item["source_kind"],
                "source_ref": item["source_ref"],
                "pin_binding": item["pin_binding"],
            }
            for item in rows
        ],
        "evidence_rows": rows,
        "candidates": candidates,
    }


class AwarenessLedgerTest(unittest.TestCase):
    def setUp(self):
        self.rows = [row("src-" + str(i), kind) for i, kind in enumerate(KINDS)]
        self.ids = [item["source_id"] for item in self.rows]

    def test_complete_manifest_emits_terminal_team_aware(self):
        result = MODULE.build_ledger(manifest(self.rows, [candidate(self.ids)]))
        finding = result["candidates"][0]
        self.assertTrue(finding["terminal"])
        self.assertEqual(finding["state"], "team_aware")
        self.assertTrue(result["fail_closed"] is False)
        self.assertEqual(MODULE.validate_ledger(result), [])

    def test_persisted_ledger_validator_rejects_partial_or_nonterminal_state(self):
        partial = MODULE.build_ledger(manifest(self.rows[:2], [candidate(self.ids[:2])]))
        errors = MODULE.validate_ledger(partial)
        self.assertIn("ledger_not_complete", errors)
        self.assertIn("source_coverage_incomplete", errors)
        self.assertIn("candidate_0:not_terminal", errors)

    def test_partial_source_coverage_is_unknown_and_blocks_novelty(self):
        result = MODULE.build_ledger(manifest(
            self.rows[:2], [candidate([item["source_id"] for item in self.rows[:2]])]
        ))
        finding = result["candidates"][0]
        self.assertEqual(finding["state"], "unknown")
        self.assertIn("partial_source_coverage", finding["reasons"])
        self.assertTrue(finding["novelty_blocked"])

    def test_regex_suggestions_are_not_terminal(self):
        suggestions = MODULE.suggest_candidates("known issue, planned fix")
        self.assertEqual({item["suggestion"] for item in suggestions}, {"team_aware", "deferred"})
        self.assertNotIn("state", suggestions[0])

    def test_marked_fixed_but_live_requires_explicit_fix_verification(self):
        marked = [row(item["source_id"], item["source_kind"], "marked_fixed") for item in self.rows]
        value = manifest(marked, [candidate(self.ids)])
        result = MODULE.build_ledger(value)
        self.assertEqual(result["candidates"][0]["state"], "known_fix")
        marked[0]["fix_verification"] = "bypassable"
        result = MODULE.build_ledger(value)
        self.assertEqual(result["candidates"][0]["state"], "marked_fixed_live")
        self.assertFalse(result["candidates"][0]["novelty_blocked"])

    def test_terminal_classification_fails_closed_without_review_metadata(self):
        bad = candidate(self.ids)
        del bad["semantic_review"]
        result = MODULE.build_ledger(manifest(self.rows, [bad]))
        self.assertFalse(result["candidates"][0]["terminal"])
        self.assertEqual(result["candidates"][0]["state"], "unknown")
        self.assertIn("missing_semantic_review", result["candidates"][0]["reasons"])

    def test_reviewer_may_bind_awareness_to_an_exact_obligation_without_text_matching(self):
        logical = {
            "target_unit": "Vault.withdraw",
            "asset_invariant": "assets conserved",
            "violation_relation": "debit omitted",
            "actor_model": "permissionless attacker",
            "impact_class": "loss of funds",
        }
        reviewed = candidate(self.ids, obligation_logical=logical)
        result = MODULE.build_ledger(manifest(self.rows, [reviewed]))
        self.assertEqual(result["candidates"][0]["obligation_logical"], logical)

    def test_invalid_explicit_obligation_binding_cannot_be_terminal(self):
        reviewed = candidate(self.ids, obligation_logical={"target_unit": "Vault.withdraw"})
        result = MODULE.build_ledger(manifest(self.rows, [reviewed]))
        self.assertFalse(result["candidates"][0]["terminal"])
        self.assertIn("invalid_obligation_logical", result["candidates"][0]["reasons"])

    def test_pin_mismatch_is_rejected(self):
        bad = candidate(self.ids, pin_binding="commit:other")
        result = MODULE.build_ledger(manifest(self.rows, [bad]))
        self.assertIn("candidate_pin_mismatch", result["candidates"][0]["reasons"])
        self.assertFalse(result["candidates"][0]["terminal"])

    def test_invalid_row_manifest_cannot_emit_terminal_state(self):
        invalid = list(self.rows)
        invalid[0] = dict(invalid[0], pin_binding="commit:other")
        result = MODULE.build_ledger(manifest(invalid, [candidate(self.ids)]))
        self.assertTrue(result["fail_closed"])
        self.assertFalse(result["candidates"][0]["terminal"])
        self.assertIn("invalid_evidence_manifest", result["candidates"][0]["reasons"])

    def test_source_reference_and_exact_content_hash_are_mandatory(self):
        missing_ref = [dict(item) for item in self.rows]
        del missing_ref[0]["source_ref"]
        value = manifest(self.rows, [candidate(self.ids)])
        value["evidence_rows"] = missing_ref
        result = MODULE.build_ledger(value)
        self.assertIn("row_0:missing_source_ref:src-0", result["validation_errors"])

        stale_hash = [dict(item) for item in self.rows]
        stale_hash[0]["content_sha256"] = "0" * 64
        result = MODULE.build_ledger(manifest(stale_hash, [candidate(self.ids)]))
        self.assertIn("row_0:content_sha256_mismatch:src-0", result["validation_errors"])

    def test_discovered_source_inventory_must_equal_reviewed_rows(self):
        value = manifest(self.rows, [candidate(self.ids)])
        value["expected_sources"].append({
            "source_id": "unreviewed-commit",
            "source_kind": "commit",
            "source_ref": "https://github.example/commit/unreviewed",
            "pin_binding": PIN,
        })
        result = MODULE.build_ledger(value)
        self.assertTrue(result["fail_closed"])
        self.assertIn("unreviewed-commit", result["source_inventory"]["missing_source_ids"])
        self.assertIn("source_inventory_incomplete", MODULE.validate_ledger(result))

    def test_uninventoried_reviewed_row_is_rejected(self):
        value = manifest(self.rows, [candidate(self.ids)])
        value["expected_sources"].pop()
        result = MODULE.build_ledger(value)
        self.assertTrue(result["fail_closed"])
        self.assertEqual(1, len(result["source_inventory"]["unexpected_source_ids"]))

    def test_manifest_cannot_weaken_the_canonical_source_kind_set(self):
        value = manifest(self.rows, [candidate(self.ids)])
        value["required_source_kinds"] = ["commit"]
        result = MODULE.build_ledger(value)
        self.assertTrue(result["fail_closed"])
        self.assertIn("required_source_kinds_incomplete", result["validation_errors"])


if __name__ == "__main__":
    unittest.main()
