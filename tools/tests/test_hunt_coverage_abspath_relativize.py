#!/usr/bin/env python3
"""Regression: hunt-coverage-gate credits a sidecar whose function_anchor.file is
an ABSOLUTE path under the workspace by emitting the workspace-RELATIVE variant.

Serving-join false-red surfaced on near-intents 2026-06-26: 80 genuine wave-A
per-fn hunt sidecars carried `function_anchor.file` = `/Users/.../<ws>/src/x.rs`.
`_normalize_source_ref` only strips the leading '/', yielding
`Users/.../<ws>/src/x.rs`, which never matched the workspace-RELATIVE denominator
unit `src/x.rs` (and the bare basename was ambiguous across two dirs). The gate
read the sidecar and produced tokens, but none mapped to a denominator unit, so
the units scored queued-not-scanned despite being genuinely hunted. The fix adds
the workspace-relative token for any scanned token under the workspace root.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "hunt-coverage-gate.py"
_spec = importlib.util.spec_from_file_location("hcg_abs", _TOOL)
hcg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hcg)


class AbsPathRelativizeTest(unittest.TestCase):
    def test_absolute_token_gets_relative_variant(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "near-intents"
            ws.mkdir()
            ws_abs = str(ws).strip("/")
            tokens = {
                f"{ws_abs}/src/btc-bridge/contracts/satoshi-bridge/src/rbf/withdraw.rs",
                f"{ws_abs}/src/btc-bridge/contracts/satoshi-bridge/src/rbf/withdraw.rs::check_withdraw_rbf_psbt_valid",
            }
            hcg._augment_workspace_relative_tokens(tokens, ws)
            self.assertIn(
                "src/btc-bridge/contracts/satoshi-bridge/src/rbf/withdraw.rs", tokens,
                "workspace-relative file token must be added",
            )
            self.assertIn(
                "src/btc-bridge/contracts/satoshi-bridge/src/rbf/withdraw.rs::check_withdraw_rbf_psbt_valid",
                tokens, "workspace-relative file::fn token must be added",
            )
            # basename variants too (harmless; helps the unique-basename path)
            self.assertIn("withdraw.rs", tokens)
            self.assertIn("withdraw.rs::check_withdraw_rbf_psbt_valid", tokens)

    def test_token_outside_workspace_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "near-intents"
            ws.mkdir()
            tokens = {"Users/someone/elsewhere/other.rs::foo"}
            before = set(tokens)
            hcg._augment_workspace_relative_tokens(tokens, ws)
            # nothing under the ws prefix -> no spurious relative token injected
            self.assertEqual(tokens, before)

    def test_already_relative_token_no_crash_no_dup_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            tokens = {"src/x.rs::foo", "src/x.rs"}
            hcg._augment_workspace_relative_tokens(tokens, ws)
            self.assertIn("src/x.rs::foo", tokens)
            self.assertIn("src/x.rs", tokens)

    def test_additive_only_never_removes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            ws_abs = str(ws).strip("/")
            tokens = {f"{ws_abs}/a/b.rs::g"}
            hcg._augment_workspace_relative_tokens(tokens, ws)
            # original token preserved
            self.assertIn(f"{ws_abs}/a/b.rs::g", tokens)
            self.assertIn("a/b.rs::g", tokens)

    def test_end_to_end_review_record_then_augment(self):
        # the full path a real sidecar takes: _review_token_source_record produces
        # an absolute-path token, then augmentation adds the relative form.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "near-intents"
            (ws / ".auditooor" / "hunt_findings_sidecars").mkdir(parents=True)
            sc = ws / ".auditooor" / "hunt_findings_sidecars" / "t0.json"
            sc.write_text(json.dumps({
                "task_id": "t0",
                "function_anchor": {
                    "file": f"{ws}/src/mpc/foo.rs",
                    "fn": "bar",
                },
                "result": json.dumps({"applies_to_target": "no"}),
            }), encoding="utf-8")
            rec = hcg._review_token_source_record(sc, "")
            self.assertIsNotNone(rec)
            toks = set(rec["tokens"])
            hcg._augment_workspace_relative_tokens(toks, ws)
            self.assertIn("src/mpc/foo.rs::bar", toks)
            self.assertIn("src/mpc/foo.rs", toks)


if __name__ == "__main__":
    unittest.main()
