"""Guard test for tools/hackerman-backfill-solodit-class.py.

Verifies the honesty gate and the in-place / rollback semantics:
  - a body that clearly implies one class flips to the mapped canonical pair;
  - an ambiguous body (no confident classifier rule) stays unknown;
  - a generic-bucket body (classifier confident but no SPECIFIC canonical home)
    stays unknown -- a wrong-but-confident class is worse than honest unknown;
  - every emitted value is a canonical-enum member;
  - the rollback ledger round-trips old <-> new;
  - --dry-run writes nothing in place.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "hackerman-backfill-solodit-class.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_backfill_solodit_class", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RECORD_TEMPLATE = """schema_version: auditooor.hackerman_record.v1.1
record_id: "{rid}"
source_audit_ref: "solodit:{rid}"
verification_tier: tier-2-verified-public-archive
target_domain: dex
target_language: solidity
target_repo: unknown/solodit
target_component: "{title}"
function_shape:
  raw_signature: function unknown()
  shape_tags:
    - solodit-rest-direct
bug_class: unknown-class
attack_class: unknown-attack
attacker_role: unprivileged
attacker_action_sequence: |
  ## Description

  {body}
required_preconditions:
  - Attacker can interact with the affected contract per the source finding.
impact_class: theft
severity_at_finding: high
year: 2024
"""


# Body that clearly implies reentrancy (classifier rule "reentrancy" -> canonical).
REENTRANCY_BODY = (
    "The withdraw function makes an external call before updating the user "
    "balance, allowing the attacker to reenter the contract via re-entrancy and "
    "drain the entire pool through a reentrant callback into the same function."
)

# Ambiguous body: prose with no classifier keyword group -> confidence none.
AMBIGUOUS_BODY = (
    "The protocol documentation states that the configuration parameter should "
    "be reviewed by the team before the next release window so that everything "
    "stays consistent across the various deployment environments over time."
)

# Generic-bucket body: classifier is CONFIDENT (denial-of-service rule) but that
# rule has no SPECIFIC canonical home in CLASSIFIER_TO_CANONICAL, so the honesty
# gate must leave it unknown rather than stamp an over-broad class.
GENERIC_DOS_BODY = (
    "A malicious actor can trigger a permanent revert in the queue processing "
    "loop, causing a denial of service that blocks all withdrawals for every "
    "user indefinitely and a denial-of-service condition across the protocol."
)


def _write_record(d: Path, rid: str, title: str, body: str) -> Path:
    p = d / f"solodit-finding-{rid}-solidity.yaml"
    p.write_text(RECORD_TEMPLATE.format(rid=rid, title=title, body=body), encoding="utf-8")
    return p


class BackfillSoloditClassTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tag_dir = Path(self.tmp.name) / "tags"
        self.sol_dir = self.tag_dir / "solodit_test_backfill"
        self.sol_dir.mkdir(parents=True)
        self.derived = Path(self.tmp.name) / "derived"
        self.cand = self.derived / "candidates.jsonl"
        self.rollback = self.derived / "rollback.jsonl"
        # Load canonical enums into the tool's module-level sets.
        self.mod.CANONICAL_ATTACK = self.mod._load_canonical_ids(self.mod.ATTACK_VOCAB_PATH)
        self.mod.CANONICAL_BUG = self.mod._load_canonical_ids(self.mod.BUG_VOCAB_PATH)
        self.assertTrue(self.mod.CANONICAL_ATTACK and self.mod.CANONICAL_BUG)
        self.classifier = self.mod._load_classifier_module()

        self.reentr = _write_record(self.sol_dir, "1001", "Reentrancy in withdraw", REENTRANCY_BODY)
        self.amb = _write_record(self.sol_dir, "1002", "Config review note", AMBIGUOUS_BODY)
        self.dos = _write_record(self.sol_dir, "1003", "Withdrawals can be blocked", GENERIC_DOS_BODY)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_map_targets_are_canonical(self):
        for rule, (a, b) in self.mod.CLASSIFIER_TO_CANONICAL.items():
            self.assertIn(a, self.mod.CANONICAL_ATTACK, f"{rule} attack {a} not canonical")
            self.assertIn(b, self.mod.CANONICAL_BUG, f"{rule} bug {b} not canonical")

    def test_clear_body_flips_to_canonical_pair(self):
        cands, rb, summary = self.mod.scan(self.tag_dir, self.classifier, apply=False)
        self.assertEqual(summary["would_flip"], 1, summary)
        flipped = cands[0]
        self.assertEqual(flipped["new_attack"], "reentrancy-cross-contract")
        self.assertEqual(flipped["new_bug"], "reentrancy-cross-contract")
        # every emitted value canonical
        for c in cands:
            self.assertIn(c["new_attack"], self.mod.CANONICAL_ATTACK)
            self.assertIn(c["new_bug"], self.mod.CANONICAL_BUG)

    def test_ambiguous_body_stays_unknown(self):
        cands, rb, summary = self.mod.scan(self.tag_dir, self.classifier, apply=False)
        flipped_ids = {c["record_id"] for c in cands}
        self.assertNotIn("solodit:1002", flipped_ids)
        self.assertGreaterEqual(summary["left_unknown_honest"], 1)

    def test_generic_bucket_stays_unknown(self):
        # The DoS body is classifier-confident but maps to no specific canonical
        # home; it must be left unknown, not stamped.
        cands, rb, summary = self.mod.scan(self.tag_dir, self.classifier, apply=False)
        flipped_ids = {c["record_id"] for c in cands}
        self.assertNotIn("solodit:1003", flipped_ids)

    def test_dry_run_writes_nothing_in_place(self):
        before = {p: p.read_text() for p in self.sol_dir.glob("*.yaml")}
        self.mod.scan(self.tag_dir, self.classifier, apply=False)
        for p, txt in before.items():
            self.assertEqual(p.read_text(), txt, f"{p.name} mutated during dry-run")

    def test_apply_flips_in_place_and_rollback_round_trips(self):
        cands, rb, summary = self.mod.scan(self.tag_dir, self.classifier, apply=True)
        self.assertEqual(summary["applied_flips"], 1)
        # in-place flip happened on the reentrancy record. The original lines
        # were unquoted (bug_class: unknown-class) so the rewrite preserves the
        # empty quote group and emits unquoted values.
        reentr_text = self.reentr.read_text()
        self.assertIn("attack_class: reentrancy-cross-contract", reentr_text)
        self.assertIn("bug_class: reentrancy-cross-contract", reentr_text)
        self.assertNotIn("unknown-attack", reentr_text)
        # ambiguous + dos untouched
        self.assertIn("unknown-attack", self.amb.read_text())
        self.assertIn("unknown-attack", self.dos.read_text())
        # rollback ledger round-trips: apply the OLD values back and re-scan flips again
        self.assertEqual(len(rb), 1)
        entry = rb[0]
        self.assertEqual(entry["old_attack"], "unknown-attack")
        self.assertEqual(entry["old_bug"], "unknown-class")
        self.assertEqual(entry["new_attack"], "reentrancy-cross-contract")
        # roll back manually using the ledger, confirm original restored
        restored = reentr_text
        restored = self.mod._rewrite_class_line(restored, self.mod.ATTACK_CLASS_RE, entry["old_attack"])
        restored = self.mod._rewrite_class_line(restored, self.mod.BUG_CLASS_RE, entry["old_bug"])
        self.reentr.write_text(restored)
        cands2, _, summary2 = self.mod.scan(self.tag_dir, self.classifier, apply=False)
        self.assertEqual(summary2["would_flip"], 1, "rollback should reopen the record for re-flip")

    def test_idempotent_rescan_after_apply(self):
        self.mod.scan(self.tag_dir, self.classifier, apply=True)
        # second apply is a no-op: the reentrancy record is now real on both axes
        _, rb2, summary2 = self.mod.scan(self.tag_dir, self.classifier, apply=True)
        self.assertEqual(summary2["would_flip"], 0)
        self.assertEqual(summary2["applied_flips"], 0)

    def test_rollback_ledger_merge_survives_noop_rerun(self):
        # First apply records one flip into the ledger.
        _, rb1, _ = self.mod.scan(self.tag_dir, self.classifier, apply=True)
        self.assertEqual(len(rb1), 1)
        total1 = self.mod.merge_rollback_ledger(rb1, self.rollback)
        self.assertEqual(total1, 1)
        # No-op re-run yields zero new rows; merging must PRESERVE the prior row.
        _, rb2, _ = self.mod.scan(self.tag_dir, self.classifier, apply=True)
        self.assertEqual(len(rb2), 0)
        total2 = self.mod.merge_rollback_ledger(rb2, self.rollback)
        self.assertEqual(total2, 1, "no-op re-run must not erase ledger history")
        lines = [l for l in self.rollback.read_text().splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["new_attack"], "reentrancy-cross-contract")


if __name__ == "__main__":
    unittest.main()
