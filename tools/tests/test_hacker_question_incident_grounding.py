#!/usr/bin/env python3
"""test_hacker_question_incident_grounding.py

Guard tests for the hacker-question-incident-grounding uplift.

Two bugs covered:

  (A) tools/per-function-hacker-questions.py gen_questions() previously iterated
      ONLY fn_record['invariant_candidates'] and silently DROPPED the
      fn_record['incident_invariants'] field that invariant-auto-synth.py attaches
      from the real-incident library. Result: 0% of emitted questions were grounded
      in an actual finding (pure regex-shape templates). The fix adds an
      incident_invariants loop emitting questions stamped
      question_source='incident-invariant' that interpolate the real statement,
      invariant_id and source_finding_ids citation.

  (B) invariant-auto-synth.py synth_invariants_sol() previously gated
      access-control-missing on a FILE-LEVEL "any modifier declared anywhere"
      list (modifiers_in_scope), so it over-fired on every public/external fn in
      any file that inherited (rather than locally declared) its modifiers. The
      fix gates on a PER-FUNCTION modifier-application check
      (_sol_fn_has_modifier over the signature tail).

R76: file:line cites verified by grep against real source.
Lane: hacker-question-incident-grounding.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent


def _load(modname: str, filename: str):
    if modname in sys.modules:
        return sys.modules[modname]
    spec = importlib.util.spec_from_file_location(modname, TOOLS / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_pfhq():
    return _load("pfhq_incident_grounding_under_test",
                 "per-function-hacker-questions.py")


def _load_synth():
    return _load("invariant_auto_synth_incident_under_test",
                 "invariant-auto-synth.py")


class IncidentGroundedQuestionTest(unittest.TestCase):
    """(A) a fn_record with incident_invariants yields >=1 grounded question."""

    def setUp(self) -> None:
        self.mod = _load_pfhq()

    def test_incident_invariants_emit_grounded_question(self) -> None:
        record = {
            "function": "withdraw",
            "file": "src/Vault.sol",
            "language": "solidity",
            "invariant_candidates": [
                "INV-withdraw-amount-nonzero: amount > 0",
            ],
            "incident_invariants": [
                {
                    "invariant_id": "INV-LIB-0042",
                    "category": "conservation",
                    "statement": "sum of user balances must equal total supply",
                    "source_finding_ids": ["FND-1001", "FND-1002"],
                    "verification_tier": "tier-1",
                },
            ],
        }
        qs = self.mod.gen_questions(record)
        grounded = [q for q in qs
                    if q.get("question_source") == "incident-invariant"]
        self.assertGreaterEqual(
            len(grounded), 1,
            "incident_invariants must yield >=1 question_source=incident-invariant")
        g = grounded[0]
        # The real statement is interpolated.
        self.assertIn("sum of user balances must equal total supply", g["question"])
        # The real invariant id is the anchor + stamped on the record.
        self.assertEqual(g["incident_anchor"], "INV-LIB-0042")
        self.assertEqual(g["anchor_invariant"], "INV-LIB-0042")
        # The real source findings are cited in the question text AND on record.
        self.assertIn("FND-1001", g["question"])
        self.assertIn("FND-1002", g["question"])
        self.assertEqual(g["source_finding_ids"], ["FND-1001", "FND-1002"])
        self.assertEqual(g["verification_tier"], "tier-1")

    def test_template_questions_still_fire(self) -> None:
        """Precision, not silencing: synth-template questions remain emitted."""
        record = {
            "function": "withdraw",
            "file": "src/Vault.sol",
            "language": "solidity",
            "invariant_candidates": [
                "INV-withdraw-amount-nonzero: amount > 0",
            ],
            "incident_invariants": [],
        }
        qs = self.mod.gen_questions(record)
        templated = [q for q in qs
                     if q.get("question_source") == "synth-template"]
        self.assertGreaterEqual(len(templated), 1,
                                "synth-template questions must still fire")

    def test_no_incident_invariants_emits_no_grounded(self) -> None:
        record = {
            "function": "f",
            "file": "src/F.sol",
            "language": "solidity",
            "invariant_candidates": ["INV-f-amount-nonzero: amount > 0"],
        }
        qs = self.mod.gen_questions(record)
        grounded = [q for q in qs
                    if q.get("question_source") == "incident-invariant"]
        self.assertEqual(len(grounded), 0)

    def test_cap_does_not_starve_grounded(self) -> None:
        """The per-fn cap must reserve room for incident-grounded questions even
        when synth-template questions alone would fill the entire budget."""
        templated = [
            {"question_source": "synth-template", "question": f"t{i}"}
            for i in range(8)
        ]
        grounded = [
            {"question_source": "incident-invariant", "question": f"g{i}"}
            for i in range(3)
        ]
        capped = self.mod._cap_questions(templated + grounded, 5)
        self.assertEqual(len(capped), 5)
        kept_grounded = [q for q in capped
                         if q["question_source"] == "incident-invariant"]
        self.assertGreaterEqual(
            len(kept_grounded), 1,
            "cap must keep >=1 incident-grounded question, not slice them all away")

    def test_blank_statement_incident_skipped(self) -> None:
        record = {
            "function": "f",
            "file": "src/F.sol",
            "language": "solidity",
            "invariant_candidates": ["INV-f-amount-nonzero: amount > 0"],
            "incident_invariants": [
                {"invariant_id": "INV-LIB-0", "statement": "   "},
            ],
        }
        qs = self.mod.gen_questions(record)
        grounded = [q for q in qs
                    if q.get("question_source") == "incident-invariant"]
        self.assertEqual(len(grounded), 0)


class AccessControlPerFunctionGateTest(unittest.TestCase):
    """(B) a modifier-bearing fn is NOT tagged access-control-missing."""

    def setUp(self) -> None:
        self.mod = _load_synth()

    def test_modifier_bearing_fn_not_flagged(self) -> None:
        cands = self.mod.synth_invariants_sol(
            "setOwner", "address o", "public",
            fn_has_modifier=True, body="owner = o;")
        self.assertFalse(
            any("access-control-missing" in c for c in cands),
            "fn whose signature carries a modifier must NOT be flagged")

    def test_modifierless_public_fn_flagged(self) -> None:
        cands = self.mod.synth_invariants_sol(
            "freebie", "uint x", "external",
            fn_has_modifier=False, body="bal[msg.sender] = x;")
        self.assertTrue(
            any("access-control-missing" in c for c in cands),
            "modifierless public/external fn must still be flagged (true positive)")

    def test_sig_tail_modifier_detection(self) -> None:
        # _sol_fn_has_modifier sees a custom modifier in the signature tail.
        self.assertTrue(self.mod._sol_fn_has_modifier(" onlyOwner "))
        self.assertTrue(self.mod._sol_fn_has_modifier(" nonReentrant "))
        self.assertTrue(self.mod._sol_fn_has_modifier(" onlyRole(ADMIN) "))
        # Reserved keywords alone are NOT modifiers.
        self.assertFalse(self.mod._sol_fn_has_modifier(" view returns (uint) "))
        self.assertFalse(self.mod._sol_fn_has_modifier(" payable virtual override "))
        self.assertFalse(self.mod._sol_fn_has_modifier(""))

    def test_file_level_inherited_modifier_no_longer_suppresses(self) -> None:
        """End-to-end: a contract that declares ONE local modifier but applies it
        to only ONE fn must still flag the OTHER (modifierless) public fn. The old
        file-level heuristic suppressed all fns whenever any modifier existed."""
        import tempfile
        sol = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "contract C {\n"
            "    modifier onlyOwner() { _; }\n"
            "    function guarded(uint x) external onlyOwner { v = x; }\n"
            "    function open(uint x) external { v = x; }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "C.sol"
            p.write_text(sol)
            recs = self.mod.process_sol_file(p)
        by_fn = {r["function"]: r for r in recs}
        guarded_cands = by_fn.get("guarded", {}).get("invariant_candidates", [])
        open_cands = by_fn.get("open", {}).get("invariant_candidates", [])
        self.assertFalse(
            any("access-control-missing" in c for c in guarded_cands),
            "guarded fn (has onlyOwner) must NOT be flagged")
        self.assertTrue(
            any("access-control-missing" in c for c in open_cands),
            "open fn (no modifier) must STILL be flagged despite file having a modifier")


if __name__ == "__main__":
    unittest.main()
