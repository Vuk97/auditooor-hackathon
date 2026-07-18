#!/usr/bin/env python3
"""test_go_rust_impact_methodology_fold.py - regression lock for the Go/Rust
impact-methodology corpus-provenance gap.

Bug: for Go/Rust workspaces, <ws>/.auditooor/per_fn_hacker_questions.jsonl was
written EXCLUSIVELY by auto-coverage-closer.py's `_fold_per_fn_hacker_questions`
(the writer that actually runs during `make audit` -> `auto-coverage-close` for
every language). That writer folded per-unit verdict sidecars into plain rows
with no `question_source` field at all - it never called
tools/hacker_question_renderer.render_impact_questions, unlike
tools/per-function-hacker-questions.py (whose producer chain is only wired into
the on-demand `scoped-hunt-plan` / `mimo-harness-hunt` make targets, not
`make audit` itself). Result: impact-methodology-corpus-provenance-check.py
FAILed with 0 impact-methodology rows on every Go/Rust workspace until someone
manually regenerated the corpus.

Fix: `_fold_per_fn_hacker_questions` now also calls
`_impact_methodology_rows_for_unit()` (a generic, language-detected-by-extension
wrapper around the SAME `render_impact_questions` renderer
per-function-hacker-questions.py uses) for every in-scope, function-bound unit
it folds, so the corpus carries genuine `question_source: impact-methodology`
provenance regardless of workspace language.

This test drives a synthetic Go-L1-like workspace (Cosmos-style keeper file
with a value-moving `Withdraw` function) through the real fold function and
asserts the resulting corpus contains a function-bound impact-methodology row.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent


def _load_acc():
    spec = importlib.util.spec_from_file_location(
        "acc_go_rust_impact_under_test", TOOLS / "auto-coverage-closer.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class GoRustImpactMethodologyFoldTest(unittest.TestCase):
    def setUp(self) -> None:
        self.acc = _load_acc()
        self.tmp = Path(tempfile.mkdtemp())
        self.ws = self.tmp / "cosmos-go-l1-fixture"
        self.vdir = self.ws / ".auditooor" / "coverage_unit_verdicts"
        self.vdir.mkdir(parents=True, exist_ok=True)
        # synthetic Go-L1-like in-scope source tree, so the scope filter
        # (_load_inscope_source_paths / _fold_question_in_scope) admits it.
        src_dir = self.ws / "x" / "bank" / "keeper"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "vault.go").write_text(
            "package keeper\n\n"
            "func (k Keeper) Withdraw(ctx sdk.Context, addr sdk.AccAddress, "
            "amount sdk.Coins) error {\n"
            "\treturn k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "
            "ModuleName, addr, amount)\n"
            "}\n",
            encoding="utf-8",
        )
        # synthetic Rust-like in-scope source tree too, so the fold is proven
        # generic across BOTH non-Solidity languages named in the bug report.
        rust_dir = self.ws / "programs" / "vault" / "src"
        rust_dir.mkdir(parents=True, exist_ok=True)
        (rust_dir / "lib.rs").write_text(
            "pub fn redeem(ctx: Context<Redeem>, amount: u64) -> Result<()> {\n"
            "    Ok(())\n"
            "}\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _sidecar(self, slug: str, unit: str, source: str, questions: list[str]) -> None:
        rec = {
            "schema": self.acc.PER_UNIT_VERDICT_SCHEMA,
            "unit_id": unit,
            "source_path": source,
            "verdict": (self.acc.VERDICT_NEEDS_LLM if questions
                        else self.acc.VERDICT_NO_FINDING),
            "adversarial_questions": questions,
            "question_count": len(questions),
        }
        (self.vdir / f"{slug}.json").write_text(json.dumps(rec), encoding="utf-8")

    def test_go_workspace_fold_stamps_impact_methodology_row(self) -> None:
        self._sidecar(
            "a", "vault.go::Withdraw", "x/bank/keeper/vault.go",
            ["Is Withdraw's authorization check bypassable?"],
        )
        res = self.acc._fold_per_fn_hacker_questions(self.ws, "rid-go")
        self.assertGreater(res["records"], 0)

        out = self.ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        self.assertTrue(out.is_file())
        recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]

        impact_rows = [r for r in recs if r.get("question_source") == "impact-methodology"]
        self.assertGreaterEqual(
            len(impact_rows), 1,
            "expected >=1 question_source=impact-methodology row for the "
            "value-moving Go function Withdraw; got recs=%r" % (recs,),
        )
        fn_bound = [
            r for r in impact_rows
            if (r.get("function") or "").strip() == "Withdraw"
            or "Withdraw" in (r.get("unit_id") or "")
        ]
        self.assertGreaterEqual(
            len(fn_bound), 1,
            "impact-methodology row must be function-bound (carry a "
            "function/unit_id identifying Withdraw); got %r" % (impact_rows,),
        )
        self.assertEqual(fn_bound[0].get("language"), "go")

    def test_rust_workspace_fold_stamps_impact_methodology_row(self) -> None:
        self._sidecar(
            "b", "lib.rs::redeem", "programs/vault/src/lib.rs",
            ["Can redeem be called with a stale price?"],
        )
        res = self.acc._fold_per_fn_hacker_questions(self.ws, "rid-rust")
        self.assertGreater(res["records"], 0)

        out = self.ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        impact_rows = [r for r in recs if r.get("question_source") == "impact-methodology"]
        self.assertGreaterEqual(len(impact_rows), 1)
        fn_bound = [
            r for r in impact_rows
            if (r.get("function") or "").strip() == "redeem"
            or "redeem" in (r.get("unit_id") or "")
        ]
        self.assertGreaterEqual(len(fn_bound), 1)
        self.assertEqual(fn_bound[0].get("language"), "rust")

    def test_provenance_gate_passes_on_go_fold_output(self) -> None:
        """End-to-end: faithfully exercise the real
        impact-methodology-corpus-provenance-check.py gate against the
        corpus this fold produces, so the fix is proven against the ACTUAL
        consumer, not just the row shape."""
        self._sidecar(
            "a", "vault.go::Withdraw", "x/bank/keeper/vault.go",
            ["Is Withdraw's authorization check bypassable?"],
        )
        self.acc._fold_per_fn_hacker_questions(self.ws, "rid-go")

        import sys
        modname = "impact_methodology_corpus_provenance_check_under_test"
        if modname in sys.modules:
            gate = sys.modules[modname]
        else:
            spec = importlib.util.spec_from_file_location(
                modname, TOOLS / "impact-methodology-corpus-provenance-check.py")
            gate = importlib.util.module_from_spec(spec)
            sys.modules[modname] = gate
            spec.loader.exec_module(gate)

        result = gate.check(self.ws)
        self.assertEqual(
            result.get("verdict"), gate.VERDICT_PASS,
            "expected pass-impact-methodology-corpus; got %r" % (result,),
        )


if __name__ == "__main__":
    unittest.main()
