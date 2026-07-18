#!/usr/bin/env python3
"""Regression: the auto-coverage-closer per_fn / lane folds must stamp a REAL
Go function anchor onto every folded obligation.

axelar-dlt (Go, 2026-07-12): the per-fn hunt batch builder emitted BROKEN
anchor metadata for every Go obligation - FN "?", LINE RANGE 0..0,
"excerpt unavailable" - and obligations carried language="unknown"
("125 of 138 open ... by language: unknown=125"). Root cause was the SOURCE
fold: `_fold_per_fn_hacker_questions` / `_fold_lane_hypotheses_into_corpus`
wrote rows with only unit_id + source_path and NO function_name / language /
line range / excerpt, and `_seed_advisory_obligations` seeded the obligation
with function_name=unit_id and no language. The enricher had nothing to resolve.

These tests pin `_enrich_fn_anchor` populating a non-"?" function_name, a
non-zero line range, a non-empty excerpt and language="go" for a Go unit, and
`make_obligation` carrying the `language` field. They must never false-pass.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, str(_ROOT / rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


acc = _load("_acc_go_anchor_test", "tools/auto-coverage-closer.py")
hqo = _load("_hqo_go_anchor_test", "tools/hacker-question-obligations.py")

# A Go method (receiver between `func` and the name) and a bare func - both of
# the shapes that the pre-fix name regex silently failed on.
GO_SRC = """package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ConfirmTransferKey is a Go METHOD - the receiver sits between func and name.
func (s msgServer) ConfirmTransferKey(c sdk.Context, req *Request) (*Resp, error) {
	preserved := s.total(c)
	s.credit(c, req.Amount)
	return &Resp{}, nil
}

func deductFee(ctx sdk.Context, amount sdk.Coin) sdk.Coin {
	fee := amount.Amount.Quo(sdk.NewInt(100))
	return sdk.NewCoin(amount.Denom, fee)
}
"""


class TestGoFnAnchorEnrichment(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        src = self.ws / "src" / "x" / "keeper" / "msg_server.go"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text(GO_SRC, encoding="utf-8")
        self.rel = "src/x/keeper/msg_server.go"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_method_anchor_is_real(self) -> None:
        """A Go METHOD unit_id resolves to a non-"?" fn, non-zero line range,
        non-empty excerpt and language='go' (the axelar-dlt failure shape)."""
        unit_id = f"{self.rel}::ConfirmTransferKey"
        a = acc._enrich_fn_anchor(self.ws, unit_id, self.rel)
        self.assertEqual(a.get("language"), "go")
        self.assertEqual(a.get("function_name"), "ConfirmTransferKey")
        self.assertNotIn(a.get("function_name"), ("?", "", None))
        self.assertGreater(a.get("line_start", 0), 0)
        self.assertGreater(a.get("line_end", 0), a.get("line_start", 0))
        self.assertTrue(a.get("excerpt"))
        self.assertIn("ConfirmTransferKey", a["excerpt"])

    def test_bare_func_relative_path_anchor(self) -> None:
        """A bare-func unit_id with a relative source_path still enriches."""
        a = acc._enrich_fn_anchor(self.ws, "deductFee", self.rel)
        self.assertEqual(a.get("language"), "go")
        self.assertEqual(a.get("function_name"), "deductFee")
        self.assertGreater(a.get("line_start", 0), 0)
        self.assertTrue(a.get("excerpt"))
        self.assertIn("deductFee", a["excerpt"])

    def test_make_obligation_carries_language(self) -> None:
        """make_obligation emits the language field so audit-complete's
        by-language accounting no longer buckets Go rows as 'unknown'."""
        ob = hqo.make_obligation(
            workspace="axelar-dlt",
            file=self.rel,
            function_signature=f"{self.rel}::ConfirmTransferKey",
            function_name="ConfirmTransferKey",
            language="go",
            attack_class="advisory",
            question="does ConfirmTransferKey preserve conservation?",
        )
        self.assertEqual(ob.get("language"), "go")
        self.assertEqual(ob.get("function_name"), "ConfirmTransferKey")


if __name__ == "__main__":
    unittest.main()
