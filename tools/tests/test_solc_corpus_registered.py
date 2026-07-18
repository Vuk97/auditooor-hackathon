#!/usr/bin/env python3
"""Regression: the solc_compiler_bugs corpus must be registered in the
incident-corpora ETL CORPORA list, and a solc-shaped source record must yield a
hacker-question whose attack_class_anchor CONTAINS the substring 'compiler' (the
vault_hacker_questions consumer does a plain substring match on that field). The
corpus is git-mined from ethereum/solidity, so its public URL lives in
attacker_action_sequence / fix_pattern, which the generic tier-2 http-scan does
not read; the ETL therefore tier-2-exempts the corpus by name. Non-vacuous:
removing the registration, dropping the tier-2 exemption, or normalizing away
'compiler' in the anchor each breaks a distinct case. B2b (2026-07-09).
"""
import importlib.util
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
_ETL = _REPO / "tools" / "hackerman-etl-from-incident-corpora.py"


def _load_etl():
    spec = importlib.util.spec_from_file_location("_solc_etl_under_test", _ETL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _solc_fixture_record():
    # Mirrors the on-disk auditooor.hackerman_record.v1.1 shape: attack_class is
    # 'solc-compiler-bug-class:<X>' and the public URL is only in
    # attacker_action_sequence / fix_pattern (NOT in the tier-2-scanned fields).
    return {
        "schema_version": "auditooor.hackerman_record.v1.1",
        "record_id": "git-mining:ethereum-solidity:deadbeef:cafe",
        "source_audit_ref": "git-mining:ethereum/solidity@deadbeefcafe",
        "attack_class": "solc-compiler-bug-class:codegen",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": (
            "Upstream solc compiler fix commit at "
            "https://github.com/ethereum/solidity/commit/deadbeefcafe. Emit "
            "Solidity source that triggers the pre-fix codegen behavior and "
            "deploy the resulting bytecode against a mainnet target compiled "
            "with a solc release earlier than the commit's release tag."
        ),
        "required_preconditions": ["Production deployment compiled with an older solc"],
        "fix_pattern": "Diff at https://github.com/ethereum/solidity/commit/deadbeefcafe",
        "severity_at_finding": "low",
        "target_language": "solidity",
        "record_quality_score": 4.0,
        "verification_tier": "tier-1-verified-realtime-api",
    }


class SolcCorpusRegistered(unittest.TestCase):
    def setUp(self):
        self.etl = _load_etl()

    def test_corpus_is_registered(self):
        names = {c["name"] for c in self.etl.CORPORA}
        self.assertIn(
            "solc_compiler_bugs", names,
            "solc_compiler_bugs missing from ETL CORPORA list",
        )
        entry = next(c for c in self.etl.CORPORA if c["name"] == "solc_compiler_bugs")
        # record.json exists on disk for every uid -> loader must read json.
        self.assertEqual(entry["record_format"], "json")
        self.assertEqual(entry.get("record_filename"), "record.json")

    def test_tier2_exemption_is_load_bearing(self):
        # The corpus is exempt (publicly verifiable by commit SHA); an unknown
        # corpus with the SAME no-http record must still be rejected, proving
        # the exemption (not some incidental field) is what admits solc.
        rec = _solc_fixture_record()
        rp = Path("/tmp/solc_fixture/record.json")
        self.assertTrue(
            self.etl.check_tier2_criterion_met(rec, "solc_compiler_bugs", rp),
            "solc corpus should be tier-2-exempt",
        )
        self.assertFalse(
            self.etl.check_tier2_criterion_met(rec, "some_other_corpus", rp),
            "no-http record in a non-exempt corpus must fail tier-2",
        )

    def test_solc_record_yields_compiler_anchor(self):
        rec = _solc_fixture_record()
        rp = Path("/tmp/solc_fixture/record.json")
        hq = self.etl.emit_hacker_question(rec, rp, "solc_compiler_bugs")
        self.assertIsNotNone(hq, "solc record must emit a hacker-question")
        anchor = str(hq.get("attack_class_anchor", "")).lower()
        self.assertIn(
            "compiler", anchor,
            f"anchor must contain 'compiler' for consumer substring match; got {anchor!r}",
        )


if __name__ == "__main__":
    unittest.main()
