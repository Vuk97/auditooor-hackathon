#!/usr/bin/env python3
"""Regression: hunt-coverage-gate's primary scanned-token reader must credit a
REAL, function-anchored NEGATIVE hunt sidecar that a hunt agent emitted into the
WORKSPACE-LOCAL mimo_harness_<ws>_workflow/ dir (via workflow-drill-sidecar-emit.py
--out-base <ws>).

Axelar-DLT field run 2026-07-12: 24 axelar-core entry-point units were genuinely
hunted (all clean NEGATIVE, applies_to_target="no", correct function_anchor) but
the emit landed in <ws>/mimo_harness_<ws>_workflow/. The gate's primary reader only
scanned .auditooor/hunt_findings_sidecars, and the heatmap mega/mimo harvester
treats applies_to_target="no" as a hallucination signal and skips it - so the
genuine NEGATIVE hunts scored queued-not-scanned (residual stuck at 99). The gate's
_collect_scanned_tokens now also scans the ws-local mimo_harness_*/mega_* dirs,
where _review_token_source_record correctly credits a "no" verdict via its
function_anchor.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_MOD = Path(__file__).resolve().parent.parent / "hunt-coverage-gate.py"
_spec = importlib.util.spec_from_file_location("hcg", _MOD)
g = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g)


class TestWsLocalMimoCredit(unittest.TestCase):
    def _ws_with_mimo_negative(self) -> Path:
        ws = Path(tempfile.mkdtemp())
        mimo = ws / "mimo_harness_axdlt_workflow"
        mimo.mkdir(parents=True)
        # a REAL NEGATIVE hunt: applies_to_target="no", correct function_anchor
        (mimo / "perfn_00001.json").write_text(json.dumps({
            "status": "ok",
            "task_id": "perfn_00001",
            "workspace": "axdlt",
            "function_anchor": {
                "file": "src/x/multisig/types/msg_keygen_optin.go",
                "fn": "ValidateBasic",
                "function": "ValidateBasic",
                "line": 12,
            },
            "result": json.dumps({
                "verdict": "KILL",
                "applies_to_target": "no",
                "confidence": "high",
                "file_line": "src/x/multisig/types/msg_keygen_optin.go:12-17",
                "reasoning": "stateless bech32 format check, fails closed.",
            }),
        }))
        return ws

    def test_ws_local_mimo_negative_hunt_credits_a_token(self):
        ws = self._ws_with_mimo_negative()

        class _Heat:  # minimal heatmap stub - the ws-local sidecar loop does not need it
            pass

        tokens, _records = g._collect_scanned_tokens(_Heat(), ws, current_run_id="")
        # the NEGATIVE hunt's function is credited at basename::fn granularity
        self.assertIn("msg_keygen_optin.go::ValidateBasic", tokens,
                      f"ws-local mimo NEGATIVE hunt not credited; tokens={sorted(tokens)}")

    def test_absent_mimo_dir_is_noop(self):
        ws = Path(tempfile.mkdtemp())

        class _Heat:
            pass

        tokens, _ = g._collect_scanned_tokens(_Heat(), ws, current_run_id="")
        self.assertEqual(tokens, set())


if __name__ == "__main__":
    unittest.main()
