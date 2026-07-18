#!/usr/bin/env python3
"""test_per_fn_hacker_questions_inscope_supplemental.py

Guard test for the L3 fix: per-function-hacker-questions was STRICTLY
invariant-driven - an in-scope (file, function) with no invariant row got ZERO
hacker questions. invariant-auto-synth only covers a subset of in-scope files,
so genuine value-movers (AccountingLib NAV-split math, RoundingGuard precision)
were silently skipped.

After the fix, main() ALSO reads <ws>/.auditooor/inscope_units.jsonl and, for
every in-scope unit the invariant path did NOT cover, emits the generic
impact-methodology question set. This test asserts:

  1. a non-invariant in-scope value-mover gets an impact-methodology question;
  2. a mutation-artifact / non-in-scope unit gets NONE (scoped to in-scope);
  3. invariant-driven rows still emit exactly as before (backward-compatible);
  4. an in-scope unit ALREADY covered by an invariant row is not double-emitted
     by the supplemental pass.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent


def _load_tool():
    modname = "per_function_hacker_questions_inscope_under_test"
    if modname in sys.modules:
        return sys.modules[modname]
    spec = importlib.util.spec_from_file_location(
        modname, TOOLS / "per-function-hacker-questions.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


# A vault-classifying scope so the impact renderer treats value-moving functions
# as value-movers (mirrors the strata ERC-4626 tranche workspace).
_SCOPE_MD = "# Scope\nERC-4626 vault tranche accounting. NAV split, deposit, redeem.\n"

# A value-moving function with a signature so the renderer classifies it.
_INVAR_SIG = ("function deposit(uint256 assets, address receiver) "
              "external returns (uint256 shares)")
_SUPPL_SIG = ("function splitValuatedNavOut(uint256 nav) external "
              "returns (uint256 seniorOut, uint256 juniorOut)")


class InscopeSupplementalTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_tool()
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        # SCOPE.md so the renderer infers a value-moving contract kind.
        (self.ws / "SCOPE.md").write_text(_SCOPE_MD, encoding="utf-8")

        # ONE invariant record (covers Vault.deposit only).
        self.inv_path = self.ws / "invariants.jsonl"
        inv_rec = {
            "function": "deposit",
            "file": "src/Vault.sol",
            "language": "solidity",
            "signature": _INVAR_SIG,
            "invariant_candidates": ["amount-nonzero", "reentrancy-check"],
        }
        self.inv_path.write_text(json.dumps(inv_rec) + "\n", encoding="utf-8")

        # inscope_units.jsonl: deposit (already invariant-covered), a NEW
        # value-mover with no invariant row (splitValuatedNavOut), and a
        # mutation-artifact unit that must be EXCLUDED.
        units = [
            {"file": "src/Vault.sol", "function": "deposit",
             "lang": "solidity", "signature": _INVAR_SIG},
            {"file": "src/AccountingLib.sol", "function": "splitValuatedNavOut",
             "lang": "solidity", "signature": _SUPPL_SIG},
            {"file": "src/AccountingLibMutantA.sol",
             "function": "splitValuatedNavOut",
             "lang": "solidity", "signature": _SUPPL_SIG},
        ]
        (self.ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "\n".join(json.dumps(u) for u in units) + "\n", encoding="utf-8")

        self.out_path = self.ws / "questions.jsonl"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self) -> list[dict]:
        rc = self.mod.main([
            "--invariants", str(self.inv_path),
            "--output", str(self.out_path),
            "--workspace", str(self.ws),
        ])
        self.assertEqual(rc, 0, "main() should succeed")
        recs = []
        with self.out_path.open() as fh:
            for line in fh:
                line = line.strip()
                if line:
                    recs.append(json.loads(line))
        return recs

    # -------------------------------------------------------------- assertions
    def test_supplemental_unit_gets_impact_question(self) -> None:
        recs = self._run()
        suppl = [r for r in recs
                 if r.get("function") == "splitValuatedNavOut"
                 and r.get("file") == "src/AccountingLib.sol"
                 and r.get("question_source") == "impact-methodology"]
        self.assertGreater(
            len(suppl), 0,
            "non-invariant in-scope value-mover must get >=1 impact-methodology "
            "question")
        # The impact rows carry the same provenance markers as the invariant path.
        self.assertTrue(all(r.get("impact_id") is not None for r in suppl))
        self.assertTrue(all(r.get("question_class") == "impact-methodology"
                            for r in suppl))

    def test_oos_mutation_artifact_gets_none(self) -> None:
        recs = self._run()
        oos = [r for r in recs
               if r.get("file") == "src/AccountingLibMutantA.sol"]
        self.assertEqual(
            oos, [],
            "a mutation-artifact / OOS unit must NOT get any question")

    def test_invariant_driven_rows_still_emit(self) -> None:
        recs = self._run()
        # The invariant-driven gen_questions classes for deposit must still emit.
        deposit_inv = [r for r in recs
                       if r.get("function") == "deposit"
                       and r.get("file") == "src/Vault.sol"
                       and r.get("question_source") != "impact-methodology"]
        self.assertGreater(
            len(deposit_inv), 0,
            "invariant-driven rows must still emit (backward-compatible)")
        classes = {r.get("question_class") for r in deposit_inv}
        self.assertIn("amount-nonzero", classes)

    def test_covered_unit_not_double_emitted_by_supplemental(self) -> None:
        # deposit is BOTH in the invariants and in inscope_units. The
        # supplemental pass must skip it (invariant_covered membership), so the
        # impact-methodology rows for deposit come only from the invariant loop,
        # not duplicated by the supplemental pass.
        recs = self._run()
        deposit_impact = [r for r in recs
                          if r.get("function") == "deposit"
                          and r.get("question_source") == "impact-methodology"]
        # Same fn would otherwise produce identical rows twice; assert no exact
        # duplicate question strings for deposit's impact rows.
        questions = [r.get("question") for r in deposit_impact]
        self.assertEqual(
            len(questions), len(set(questions)),
            "deposit impact-methodology rows must not be double-emitted by the "
            "supplemental pass")

    def test_no_sidecar_is_noop(self) -> None:
        # Remove the sidecar: the supplemental pass must be a no-op and the
        # output must contain only invariant-derived rows (byte-identical class).
        (self.ws / ".auditooor" / "inscope_units.jsonl").unlink()
        recs = self._run()
        suppl = [r for r in recs
                 if r.get("function") == "splitValuatedNavOut"]
        self.assertEqual(
            suppl, [],
            "absent the sidecar, no supplemental questions are emitted")
        # invariant rows still present.
        self.assertTrue(any(r.get("function") == "deposit" for r in recs))


if __name__ == "__main__":
    unittest.main()
