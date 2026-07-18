#!/usr/bin/env python3
"""Tests for tools/ranker.py — S1 + S4 scorers, Phase-A MVP.

Covers:
  - T1: yaml_load parses block + list + nested dict
  - T2: load_rules returns >= 10 rules from audit/ranker_rules.yaml
  - T3: outcome_weight handles ACCEPTED + DROP variants + defaults
  - T4: shape_similarity returns 1.0 / 0.7 / 0.4 / 0.0 per design
  - T5: score_s4 fires RULE_GO_FILE_HANDLER on an exported Go method
  - T6: rank() returns admin-bypass / blocked-addr-bypass in top-5 for the
        cantina-192 RegisterAffiliate sanity-check function.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "ranker.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("ranker_for_test", MOD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {MOD_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ranker_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


RA = _load()


class TestYamlLoad(unittest.TestCase):

    def test_simple_mapping(self):
        d = RA.yaml_load("key: value\nfoo: 42\nflag: true\n")
        self.assertEqual(d, {"key": "value", "foo": 42, "flag": True})

    def test_nested_mapping(self):
        text = "outer:\n  inner: 1\n  also: text\n"
        d = RA.yaml_load(text)
        self.assertEqual(d, {"outer": {"inner": 1, "also": "text"}})

    def test_flow_list(self):
        d = RA.yaml_load("xs: [a, b, c]\n")
        self.assertEqual(d, {"xs": ["a", "b", "c"]})

    def test_block_list_of_dicts(self):
        text = "items:\n  - file_path: a.go\n    line: 1\n  - file_path: b.go\n    line: 2\n"
        d = RA.yaml_load(text)
        self.assertEqual(d["items"][0]["file_path"], "a.go")
        self.assertEqual(d["items"][1]["line"], 2)
        self.assertEqual(len(d["items"]), 2)


class TestRulesLoading(unittest.TestCase):

    def test_rules_present(self):
        rules = RA.load_rules()
        self.assertGreaterEqual(len(rules), 10, f"expected >=10 rules, got {len(rules)}")
        rule_ids = {r.rule_id for r in rules}
        self.assertIn("RULE_D8", rule_ids)
        self.assertIn("RULE_GO_FILE_HANDLER", rule_ids)


class TestScorers(unittest.TestCase):

    def test_outcome_weight_accepted(self):
        t = RA.TagRecord(
            verdict_id="x", target_repo="r", audit_pin_sha="0", language="go",
            verdict_class="FILED", bug_class=None, attack_classes_to_try=[],
            triager_outcome="ACCEPTED", drop_reason=None, sites=[], raw={},
        )
        self.assertEqual(RA.outcome_weight(t), 1.0)

    def test_outcome_weight_drop_reverted(self):
        t = RA.TagRecord(
            verdict_id="x", target_repo="r", audit_pin_sha="0", language="go",
            verdict_class="DROP", bug_class=None, attack_classes_to_try=[],
            triager_outcome=None, drop_reason="b-reverted", sites=[], raw={},
        )
        # DROP-(b) reverted is positive signal: 0.8
        self.assertEqual(RA.outcome_weight(t), 0.8)

    def test_shape_similarity_exact(self):
        sim = RA.shape_similarity(
            "abcd", "fine_a", "abcd", "fine_b",
            "msg-server-family", "msg-server-family",
        )
        self.assertEqual(sim, 1.0)

    def test_shape_similarity_fine_only(self):
        sim = RA.shape_similarity(
            "aaaa", "fineX", "bbbb", "fineX",
            "msg-server-family", "msg-server-family",
        )
        self.assertEqual(sim, 0.7)

    def test_shape_similarity_family_only(self):
        sim = RA.shape_similarity(
            "aaaa", "fineX", "bbbb", "fineY",
            "msg-server-family", "msg-server-family",
        )
        self.assertEqual(sim, 0.4)

    def test_shape_similarity_no_match(self):
        sim = RA.shape_similarity(
            "aaaa", "fineX", "bbbb", "fineY",
            "msg-server-family", "ibc-module",
        )
        self.assertEqual(sim, 0.0)

    def test_s4_fires_on_handler_name(self):
        rec = {
            "language": "go",
            "function_name": "HandleRecvPacket",
            "visibility": "exported",
            "receiver_type": None,
            "guards_detected": [],
            "calls_made": [],
            "params": [],
            "return_types": ["error"],
        }
        rules = RA.load_rules()
        s4 = RA.score_s4(rec, rules)
        self.assertIn("handler-input-validation", s4)


class TestRankSmoke(unittest.TestCase):

    def test_synthesized_go_method_signature_keeps_receiver_and_name(self):
        result = RA.rank(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/clob/keeper/matches.go",
            function_signature="func (k Keeper) ProcessSingleMatch(ctx sdk.Context) error",
            top_n=1,
            min_confidence=0.0,
        )
        self.assertEqual(result.target["function_name"], "ProcessSingleMatch")
        self.assertEqual(result.target["receiver_type"], "Keeper")
        self.assertEqual(result.target["receiver_family"], "msg-server-family")
        self.assertEqual(result.target["return_types"], ["error"])

    def test_cantina_192_register_affiliate_sanity(self):
        result = RA.rank(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/msg_server.go",
            function_signature="func (k msgServer) RegisterAffiliate(ctx context.Context, msg *types.MsgRegisterAffiliate) (*types.MsgRegisterAffiliateResponse, error)",
            top_n=5,
            min_confidence=0.4,
        )
        top_acs = [r["attack_class"] for r in result.ranked_attack_classes]
        # The sanity check: cantina-192 attack-class set should overlap top-5.
        expected = {"admin-bypass", "blocked-addr-bypass", "fee-redirect", "module-account-permafreeze"}
        self.assertTrue(
            expected & set(top_acs),
            f"expected at least one of {expected} in top-5 but got {top_acs}",
        )
        # Evidence trail must be walkable: at least one entry has either a
        # verdict_id (S1) or rule_id (S4) pointer.
        any_walkable = False
        for r in result.ranked_attack_classes:
            for e in r["evidence"]:
                if e.get("verdict_id") or e.get("rule_id"):
                    any_walkable = True
                    break
            if any_walkable:
                break
        self.assertTrue(any_walkable, "expected at least one walkable evidence entry")


if __name__ == "__main__":
    unittest.main()
