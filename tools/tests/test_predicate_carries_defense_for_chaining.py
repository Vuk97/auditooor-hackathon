#!/usr/bin/env python3
"""Regression: the exploit-predicate row must carry the record's OWN fix_pattern as
`defense` + copy `verification_tier`, so causal-chain-extract's quality gate accepts
a well-authored record instead of rejecting it (defense_fallback_or_placeholder /
verification_tier_unknown). Before this fix every richly-authored mined record
produced 0 causal chains. 2026-07-08 (corpus->capability drain loop, box J).
"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(name, mod):
    s = importlib.util.spec_from_file_location(mod, _TOOLS / name)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


_HEP = _load("hackerman-exploit-predicates.py", "hep")
_CCE = _load("causal-chain-extract.py", "cce")

_RECORD = """schema_version: auditooor.hackerman_record.v1.1
record_id: test:defense-carry:deadbeef00
source_audit_ref: https://example.test/writeup
record_tier: public-corpus
record_quality_score: 4.0
source_extraction_method: human-curated
source_extraction_confidence: 0.9
target_domain: vault
target_language: go
target_repo: example/repo
target_component: A keeper that does the thing
function_shape:
  raw_signature: "func Do(ctx sdk.Context)"
  shape_tags: [record]
bug_class: storage-key-collision
attack_class: storage-key-serialization-collision
attacker_role: unprivileged
attacker_action_sequence: Step one. Step two.
required_preconditions:
- A concrete non-placeholder precondition that is specific to the bug.
impact_class: theft
impact_actor: depositor-class
impact_dollar_class: $100K-$1M
fix_pattern: Add a length-prefixed key encoding and reject prefix-colliding keys.
fix_anti_pattern_avoided: naive concatenation of key fields
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
verification_tier: tier-2-verified-public-archive
"""


def _rows(res):
    if isinstance(res, dict):
        if isinstance(res.get("rows"), list):
            return res["rows"]
        for v in res.values():
            if isinstance(v, list) and v and isinstance(v[0], dict) and "record_id" in v[0]:
                return v
    return res if isinstance(res, list) else []


class T(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "rec.yaml").write_text(_RECORD)
        self.row = _rows(_HEP.extract_rows(self.d))[0]

    def test_predicate_carries_defense_from_fix_pattern(self):
        self.assertTrue(self.row.get("defense"), "predicate row missing `defense`")
        self.assertIn("length-prefixed", self.row["defense"])

    def test_predicate_carries_verification_tier(self):
        self.assertEqual(self.row.get("verification_tier"),
                         "tier-2-verified-public-archive")

    def test_causal_gate_accepts_the_row(self):
        # infer_defense must return the real fix, NOT the placeholder fallback.
        d = _CCE.infer_defense(self.row, self.row.get("actions", []))
        self.assertNotEqual(d, _CCE.FALLBACK_DEFENSE)
        self.assertIn("length-prefixed", d)
        vt = _CCE.infer_verification_tier(self.row, [])
        self.assertNotEqual(vt, "unknown")

    def test_quality_guard_rejects_noise(self):
        # Pointer fixes, canned auto-mined one-liners, and too-short fixes must NOT
        # be carried as defense (else the chain corpus floods with noise: measured
        # 2610 -> 61496, ~46% placeholder-pointer, when unguarded).
        self.assertFalse(_HEP._is_substantive_fix({
            "fix_pattern": "See source audit report for recommended fix.",
            "source_extraction_method": "human-curated"}))
        self.assertFalse(_HEP._is_substantive_fix({
            "fix_pattern": "add explicit invariant checks around the affected state transition",
            "source_extraction_method": "corpus-etl"}))  # substantive text but NOT vetted
        self.assertFalse(_HEP._is_substantive_fix({
            "fix_pattern": "add a check", "source_extraction_method": "human-curated"}))
        # a vetted, specific, non-pointer fix IS carried
        self.assertTrue(_HEP._is_substantive_fix({
            "fix_pattern": "Add a length-prefixed key encoding and reject prefix-colliding keys.",
            "source_extraction_method": "human-curated"}))


if __name__ == "__main__":
    unittest.main()
